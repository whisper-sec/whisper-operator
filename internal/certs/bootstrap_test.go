// Copyright 2026 viaGraph B.V. (Whisper Security)
// SPDX-License-Identifier: MIT

package certs

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func testOptions() Options {
	return Options{
		Namespace:         "whisper-system",
		ServiceName:       "whisper-operator-webhook",
		CertSecretName:    "whisper-operator-webhook-cert",
		WebhookConfigName: "whisper-operator",
		CertDir:           "",
	}
}

func TestGenerateProducesServableTLSPair(t *testing.T) {
	data, err := generate(testOptions())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tls.X509KeyPair(data["tls.crt"], data["tls.key"]); err != nil {
		t.Fatalf("leaf pair unusable: %v", err)
	}

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(data["ca.crt"]) {
		t.Fatal("ca.crt did not parse")
	}
	block, _ := pem.Decode(data["tls.crt"])
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	// The leaf must verify against the CA for the in-cluster service name.
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:   roots,
		DNSName: "whisper-operator-webhook.whisper-system.svc",
	}); err != nil {
		t.Fatalf("leaf does not verify for the service DNS name: %v", err)
	}
}

func TestSecretValid(t *testing.T) {
	o := testOptions()
	data, err := generate(o)
	if err != nil {
		t.Fatal(err)
	}
	sec := &corev1.Secret{Data: data}
	if !secretValid(sec, o) {
		t.Fatal("freshly generated secret must be valid")
	}
	// A different service name must invalidate (forces rotation on rename).
	other := o
	other.ServiceName = "renamed"
	if secretValid(sec, other) {
		t.Fatal("secret for the old service name must be invalid")
	}
	// Truncated data must be invalid, never a panic.
	if secretValid(&corev1.Secret{Data: map[string][]byte{"tls.crt": []byte("junk")}}, o) {
		t.Fatal("junk secret must be invalid")
	}
}
