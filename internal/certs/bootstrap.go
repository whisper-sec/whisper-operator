// Copyright 2026 viaGraph B.V. (Whisper Security)
// SPDX-License-Identifier: MIT

// Package certs self-manages the webhook serving certificate so the operator
// has ZERO hard dependencies: no cert-manager required (it stays an optional
// nicety). On startup the operator ensures a CA + leaf pair in a Secret
// (first replica wins; others reuse - restart-safe and multi-replica-safe),
// writes the leaf to the webhook server's cert dir, and patches the CA bundle
// into the MutatingWebhookConfiguration.
package certs

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	admissionv1 "k8s.io/api/admissionregistration/v1"
)

// Options configure the bootstrap.
type Options struct {
	Namespace         string // operator namespace
	ServiceName       string // webhook Service name
	CertSecretName    string // Secret persisting the CA + leaf
	WebhookConfigName string // MutatingWebhookConfiguration to patch
	CertDir           string // where tls.crt / tls.key are written
}

const (
	caValidity   = 10 * 365 * 24 * time.Hour
	leafValidity = 2 * 365 * 24 * time.Hour
	// renewBefore renews certs that are within this window of expiry.
	renewBefore = 30 * 24 * time.Hour
)

// Ensure makes the serving cert + CA bundle real: Secret ensured, cert dir
// written, webhook configuration patched. Call before the manager starts.
func Ensure(ctx context.Context, c client.Client, o Options) error {
	sec, err := ensureSecret(ctx, c, o)
	if err != nil {
		return fmt.Errorf("ensure webhook cert secret: %w", err)
	}
	if err := writeCertDir(o.CertDir, sec); err != nil {
		return fmt.Errorf("write cert dir: %w", err)
	}
	if err := patchCABundle(ctx, c, o.WebhookConfigName, sec.Data["ca.crt"]); err != nil {
		return fmt.Errorf("patch caBundle: %w", err)
	}
	return nil
}

// ensureSecret returns a Secret holding a valid ca.crt/tls.crt/tls.key,
// creating or rotating it as needed. Create conflicts (another replica won
// the race) re-read the winner.
func ensureSecret(ctx context.Context, c client.Client, o Options) (*corev1.Secret, error) {
	key := types.NamespacedName{Namespace: o.Namespace, Name: o.CertSecretName}
	sec := &corev1.Secret{}
	err := c.Get(ctx, key, sec)
	if err == nil && secretValid(sec, o) {
		return sec, nil
	}
	if err != nil && !apierrors.IsNotFound(err) {
		return nil, err
	}

	data, genErr := generate(o)
	if genErr != nil {
		return nil, genErr
	}
	fresh := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: o.Namespace,
			Name:      o.CertSecretName,
			Labels:    map[string]string{"app.kubernetes.io/managed-by": "whisper-operator"},
		},
		Type: corev1.SecretTypeTLS,
		Data: data,
	}
	if apierrors.IsNotFound(err) {
		if cerr := c.Create(ctx, fresh); cerr != nil {
			if apierrors.IsAlreadyExists(cerr) { // another replica won: use theirs
				if gerr := c.Get(ctx, key, sec); gerr == nil && secretValid(sec, o) {
					return sec, nil
				}
			}
			return nil, cerr
		}
		return fresh, nil
	}
	// Existing but invalid/expiring: rotate in place.
	sec.Type = corev1.SecretTypeTLS
	sec.Data = data
	if uerr := c.Update(ctx, sec); uerr != nil {
		return nil, uerr
	}
	return sec, nil
}

// secretValid checks the stored pair parses, matches our DNS names, and is not
// about to expire.
func secretValid(sec *corev1.Secret, o Options) bool {
	certPEM, keyPEM, caPEM := sec.Data["tls.crt"], sec.Data["tls.key"], sec.Data["ca.crt"]
	if len(certPEM) == 0 || len(keyPEM) == 0 || len(caPEM) == 0 {
		return false
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}
	if time.Now().Add(renewBefore).After(cert.NotAfter) {
		return false
	}
	want := serviceDNS(o)[0]
	return cert.VerifyHostname(want) == nil
}

func serviceDNS(o Options) []string {
	base := fmt.Sprintf("%s.%s.svc", o.ServiceName, o.Namespace)
	return []string{base, base + ".cluster.local", o.ServiceName, fmt.Sprintf("%s.%s", o.ServiceName, o.Namespace)}
}

// generate mints a fresh ECDSA P-256 CA + leaf for the webhook Service.
func generate(o Options) (map[string][]byte, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	caSerial, err := randSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now().Add(-5 * time.Minute) // clock-skew slack
	caTmpl := &x509.Certificate{
		SerialNumber:          caSerial,
		Subject:               pkix.Name{CommonName: "whisper-operator-ca", Organization: []string{"Whisper Security"}},
		NotBefore:             now,
		NotAfter:              now.Add(caValidity),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	leafSerial, err := randSerial()
	if err != nil {
		return nil, err
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: leafSerial,
		Subject:      pkix.Name{CommonName: serviceDNS(o)[0], Organization: []string{"Whisper Security"}},
		NotBefore:    now,
		NotAfter:     now.Add(leafValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     serviceDNS(o),
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	leafKeyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		return nil, err
	}

	return map[string][]byte{
		"ca.crt":  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		"tls.crt": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		"tls.key": pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: leafKeyDER}),
	}, nil
}

func randSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

// writeCertDir lays tls.crt/tls.key (+ ca.crt) down for the webhook server.
func writeCertDir(dir string, sec *corev1.Secret) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	for name, data := range sec.Data {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			return err
		}
	}
	return nil
}

// patchCABundle stamps the CA into every webhook of the configuration,
// retrying on conflict. A missing configuration is an error - the chart
// installs it alongside the Deployment.
func patchCABundle(ctx context.Context, c client.Client, name string, ca []byte) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		mwc := &admissionv1.MutatingWebhookConfiguration{}
		if err := c.Get(ctx, types.NamespacedName{Name: name}, mwc); err != nil {
			return err
		}
		changed := false
		for i := range mwc.Webhooks {
			if string(mwc.Webhooks[i].ClientConfig.CABundle) != string(ca) {
				mwc.Webhooks[i].ClientConfig.CABundle = ca
				changed = true
			}
		}
		if !changed {
			return nil
		}
		return c.Update(ctx, mwc)
	})
}
