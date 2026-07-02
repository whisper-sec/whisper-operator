// Copyright 2026 viaGraph B.V. (Whisper Security)
// SPDX-License-Identifier: MIT

// Package inject implements the pod-mutating admission webhook that gives an
// annotated pod a Whisper network identity: it appends a NATIVE sidecar
// (an initContainer with restartPolicy: Always, Kubernetes >= 1.29) running
// `whisper connect`, and points every app container's proxy environment at the
// sidecar's local proxy on 127.0.0.1:<port>. The pod's egress then sources
// from a real, routable Whisper IPv6 /128 — verifiable via reverse DNS + RDAP.
//
// Fail-open by design (Postel): any problem — missing Secret, malformed
// annotation, an unreachable API server — admits the pod UNMUTATED with a
// warning, never an error. A Whisper hiccup must never block a pod from
// scheduling; the MutatingWebhookConfiguration additionally carries
// failurePolicy: Ignore for the webhook-unreachable case.
package inject

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	egressv1alpha1 "github.com/whisper-sec/whisper-operator/api/v1alpha1"
)

const (
	// AnnotationPrefix is the annotation namespace all pod-level knobs live under.
	AnnotationPrefix = "whisper.security/"

	// AnnEgress opts a pod in ("enabled"/"true") or out ("disabled"/"false").
	AnnEgress = AnnotationPrefix + "egress"
	// AnnSecret names the Secret holding the Whisper API key (default "whisper").
	AnnSecret = AnnotationPrefix + "secret"
	// AnnSecretKey names the key inside that Secret (default "api-key").
	AnnSecretKey = AnnotationPrefix + "secret-key"
	// AnnAgent pins the Whisper agent identity (an agent id, name, or /128).
	AnnAgent = AnnotationPrefix + "agent"
	// AnnTier selects the egress tier: socks5 (default) | wireguard.
	AnnTier = AnnotationPrefix + "tier"
	// AnnMode selects app wiring: proxy (default; proxy-env into containers).
	AnnMode = AnnotationPrefix + "mode"
	// AnnPort pins the sidecar's local proxy port (default 18080).
	AnnPort = AnnotationPrefix + "port"
	// AnnImage overrides the sidecar image.
	AnnImage = AnnotationPrefix + "image"
	// AnnStatus is stamped by the webhook after injection (idempotency guard).
	AnnStatus = AnnotationPrefix + "status"

	// StatusInjected is the AnnStatus value stamped on mutated pods.
	StatusInjected = "injected"

	// SidecarName is the injected native sidecar's container name.
	SidecarName = "whisper"

	// DefaultImage is the official multi-arch Whisper CLI image.
	DefaultImage = "ghcr.io/whisper-sec/whisper:latest"
	// DefaultSecretName / DefaultSecretKey follow `whisper init k8s`:
	//   kubectl create secret generic whisper --from-literal=api-key=...
	DefaultSecretName = "whisper"
	DefaultSecretKey  = "api-key"
	// DefaultPort is the sidecar's local proxy port.
	DefaultPort int32 = 18080
)

// Defaults are the operator-level (chart values) fallbacks, the lowest rung of
// the precedence ladder: pod annotation > namespace WhisperEgress > Defaults.
type Defaults struct {
	Image      string
	SecretName string
	SecretKey  string
	Port       int32
}

// WithFallbacks fills any zero field with the built-in constants.
func (d Defaults) WithFallbacks() Defaults {
	if d.Image == "" {
		d.Image = DefaultImage
	}
	if d.SecretName == "" {
		d.SecretName = DefaultSecretName
	}
	if d.SecretKey == "" {
		d.SecretKey = DefaultSecretKey
	}
	if d.Port == 0 {
		d.Port = DefaultPort
	}
	return d
}

// config is the fully-resolved injection config for one pod.
type config struct {
	image      string
	secretName string
	secretKey  string
	agent      string
	namePrefix string
	tier       string
	mode       string
	port       int32
}

// PodInjector is the admission.Handler behind /mutate-pod.
type PodInjector struct {
	// reader is an UNCACHED API reader: WhisperEgress lookups work even when
	// the CRD is not installed (NoKindMatch is simply ignored) and Secret
	// existence checks never depend on informer warm-up.
	reader   client.Reader
	decoder  admission.Decoder
	defaults Defaults
}

// NewPodInjector builds the handler. reader must be an uncached client.Reader.
func NewPodInjector(reader client.Reader, decoder admission.Decoder, defaults Defaults) *PodInjector {
	return &PodInjector{reader: reader, decoder: decoder, defaults: defaults.WithFallbacks()}
}

// Handle mutates pod CREATE requests. It is idempotent (reinvocationPolicy:
// IfNeeded safe) and NEVER returns an error response: every failure path
// admits the pod unmutated with a warning.
func (p *PodInjector) Handle(ctx context.Context, req admission.Request) admission.Response {
	log := logf.FromContext(ctx).WithName("whisper-inject")

	pod := &corev1.Pod{}
	if err := p.decoder.Decode(req, pod); err != nil {
		// Liberal in what we accept: an undecodable object is admitted untouched.
		return warn(admission.Allowed("whisper: undecodable pod, admitted unmutated"),
			fmt.Sprintf("whisper-operator could not decode the pod (%v); no sidecar injected", err))
	}

	ns := req.Namespace
	if ns == "" {
		ns = pod.Namespace
	}
	ann := pod.GetAnnotations()

	// Explicit opt-out and idempotency short-circuits.
	switch strings.ToLower(strings.TrimSpace(ann[AnnEgress])) {
	case "disabled", "false", "off", "no":
		return admission.Allowed("whisper: egress disabled by annotation")
	}
	if ann[AnnStatus] == StatusInjected || hasContainer(pod.Spec.InitContainers, SidecarName) {
		return admission.Allowed("whisper: sidecar already injected")
	}

	cfg, warnings := p.resolveConfig(ctx, ns, ann)

	if cfg.mode != "" && cfg.mode != "proxy" {
		// Conservative in what we emit: an unsupported mode is a clear warning
		// + an unmutated pod, never a silent different behavior.
		return warn(admission.Allowed("whisper: unsupported mode"),
			fmt.Sprintf("whisper.security/mode %q is not supported by this operator version (only \"proxy\"); pod admitted without egress injection", cfg.mode))
	}

	// The API key Secret must exist, otherwise the injected sidecar would hold
	// the pod in CreateContainerConfigError — the opposite of fail-open. A
	// read error (not NotFound) injects optimistically: never let a flaky
	// API-server read take away the product.
	secret := &corev1.Secret{}
	if err := p.reader.Get(ctx, types.NamespacedName{Namespace: ns, Name: cfg.secretName}, secret); err != nil {
		if apierrors.IsNotFound(err) {
			return warn(admission.Allowed("whisper: api-key secret not found"),
				fmt.Sprintf("Secret %q not found in namespace %q — create it (kubectl create secret generic %s --from-literal=%s=<your Whisper API key>) and recreate the pod; admitted without egress injection",
					cfg.secretName, ns, cfg.secretName, cfg.secretKey))
		}
		log.Info("secret lookup failed, injecting optimistically", "secret", cfg.secretName, "namespace", ns, "err", err.Error())
	} else if _, ok := secret.Data[cfg.secretKey]; !ok {
		keys := make([]string, 0, len(secret.Data))
		for k := range secret.Data {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		return warn(admission.Allowed("whisper: api-key secret key missing"),
			fmt.Sprintf("Secret %q in namespace %q has no key %q (found: %s); admitted without egress injection",
				cfg.secretName, ns, cfg.secretKey, strings.Join(keys, ", ")))
	}

	mutated := pod.DeepCopy()
	applyInjection(mutated, cfg)

	raw, err := json.Marshal(mutated)
	if err != nil {
		return warn(admission.Allowed("whisper: marshal failed"),
			fmt.Sprintf("whisper-operator failed to encode the mutated pod (%v); admitted unmutated", err))
	}
	resp := admission.PatchResponseFromRaw(req.Object.Raw, raw)
	resp.Warnings = append(resp.Warnings, warnings...)
	log.Info("injected whisper egress sidecar",
		"namespace", ns, "pod", podDisplayName(pod), "port", cfg.port, "agent", cfg.agent, "tier", orDefault(cfg.tier, "socks5"))
	return resp
}

// resolveConfig walks the precedence ladder: pod annotations > the namespace's
// WhisperEgress default > operator Defaults. It never fails — bad values fall
// back with a warning.
func (p *PodInjector) resolveConfig(ctx context.Context, ns string, ann map[string]string) (config, []string) {
	var warnings []string
	cfg := config{
		image:      p.defaults.Image,
		secretName: p.defaults.SecretName,
		secretKey:  p.defaults.SecretKey,
		port:       p.defaults.Port,
	}

	// Namespace tier: the optional WhisperEgress CRD. Read through the
	// uncached reader so a cluster with zero CRDs installed works untouched.
	if we := p.namespaceEgress(ctx, ns); we != nil {
		s := we.Spec
		if s.SecretRef != nil && s.SecretRef.Name != "" {
			cfg.secretName = s.SecretRef.Name
			if s.SecretRef.Key != "" {
				cfg.secretKey = s.SecretRef.Key
			}
		}
		if s.Image != "" {
			cfg.image = s.Image
		}
		if s.Port > 0 {
			cfg.port = s.Port
		}
		cfg.tier = s.Tier
		cfg.mode = s.Mode
		cfg.namePrefix = s.AgentNamePrefix
	}

	// Pod tier: annotations win.
	if v := ann[AnnSecret]; v != "" {
		cfg.secretName = v
	}
	if v := ann[AnnSecretKey]; v != "" {
		cfg.secretKey = v
	}
	if v := ann[AnnAgent]; v != "" {
		cfg.agent = v
	}
	if v := ann[AnnTier]; v != "" {
		cfg.tier = v
	}
	if v := ann[AnnMode]; v != "" {
		cfg.mode = v
	}
	if v := ann[AnnImage]; v != "" {
		cfg.image = v
	}
	if v := ann[AnnPort]; v != "" {
		if port, err := strconv.ParseInt(v, 10, 32); err == nil && port > 0 && port < 65536 {
			cfg.port = int32(port)
		} else {
			warnings = append(warnings, fmt.Sprintf("whisper.security/port %q is not a valid port; using %d", v, cfg.port))
		}
	}
	return cfg, warnings
}

// namespaceEgress returns the namespace's WhisperEgress defaults: the object
// named "default" if present, else the alphabetically-first one, else nil.
// Every error (including "CRD not installed") resolves to nil — optional
// means optional.
func (p *PodInjector) namespaceEgress(ctx context.Context, ns string) *egressv1alpha1.WhisperEgress {
	list := &egressv1alpha1.WhisperEgressList{}
	if err := p.reader.List(ctx, list, client.InNamespace(ns)); err != nil {
		if !meta.IsNoMatchError(err) && !apierrors.IsNotFound(err) {
			logf.FromContext(ctx).V(1).Info("WhisperEgress lookup failed; using operator defaults", "namespace", ns, "err", err.Error())
		}
		return nil
	}
	if len(list.Items) == 0 {
		return nil
	}
	sort.Slice(list.Items, func(i, j int) bool { return list.Items[i].Name < list.Items[j].Name })
	for i := range list.Items {
		if list.Items[i].Name == "default" {
			return &list.Items[i]
		}
	}
	return &list.Items[0]
}

// applyInjection mutates the pod in place: native sidecar + proxy env + stamp.
func applyInjection(pod *corev1.Pod, cfg config) {
	pod.Spec.InitContainers = append(pod.Spec.InitContainers, buildSidecar(pod, cfg))

	for i := range pod.Spec.Containers {
		c := &pod.Spec.Containers[i]
		if c.Name == SidecarName || hasProxyEnv(c.Env) {
			continue // respect user intent: never clobber an existing proxy setup
		}
		c.Env = append(c.Env, proxyEnv(cfg.port)...)
	}

	if pod.Annotations == nil {
		pod.Annotations = map[string]string{}
	}
	pod.Annotations[AnnStatus] = StatusInjected
}

// buildSidecar assembles the native sidecar container (initContainer with
// restartPolicy: Always — starts before, and outlives, every app container).
func buildSidecar(pod *corev1.Pod, cfg config) corev1.Container {
	always := corev1.ContainerRestartPolicyAlways
	no := false
	yes := true

	args := []string{"connect", "--port", strconv.Itoa(int(cfg.port)), "--quiet"}
	if cfg.agent != "" {
		// Pin a specific identity: an agent id, human name, or its /128.
		args = append(args, "--agent", cfg.agent)
	} else {
		// No pin: the server reuses the account's most-recent agent; on a
		// brand-new account `whisper connect` creates one, named here.
		args = append(args, "--name", agentName(pod, cfg.namePrefix))
	}
	if cfg.tier != "" && cfg.tier != "socks5" {
		args = append(args, "--tier", cfg.tier)
	}

	return corev1.Container{
		Name:            SidecarName,
		Image:           cfg.image,
		ImagePullPolicy: corev1.PullIfNotPresent,
		Args:            args,
		RestartPolicy:   &always,
		Env: []corev1.EnvVar{{
			Name: "WHISPER_API_KEY",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: cfg.secretName},
					Key:                  cfg.secretKey,
				},
			},
		}},
		SecurityContext: &corev1.SecurityContext{
			AllowPrivilegeEscalation: &no,
			RunAsNonRoot:             &yes,
			Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
			SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
		},
		Resources: corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("10m"),
				corev1.ResourceMemory: resource.MustParse("32Mi"),
			},
			Limits: corev1.ResourceList{
				corev1.ResourceMemory: resource.MustParse("256Mi"),
			},
		},
	}
}

// agentName derives the human name used only when a brand-new agent must be
// created: <prefix or "k8s">-<namespace>[-<pod name>], trimmed to something
// a human can read in `whisper list`.
func agentName(pod *corev1.Pod, prefix string) string {
	if prefix == "" {
		prefix = "k8s"
	}
	parts := []string{prefix, pod.Namespace}
	name := pod.Name
	if name == "" {
		name = strings.TrimSuffix(pod.GenerateName, "-")
	}
	if name != "" {
		parts = append(parts, name)
	}
	n := strings.Trim(strings.Join(parts, "-"), "-")
	if len(n) > 63 {
		n = n[:63]
	}
	return n
}

// proxyEnv is the app-side proxy environment, both spellings (curl reads
// lowercase http_proxy; most SDKs read uppercase — cover every scenario).
func proxyEnv(port int32) []corev1.EnvVar {
	httpURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	socksURL := fmt.Sprintf("socks5h://127.0.0.1:%d", port)
	const noProxy = "localhost,127.0.0.1,::1,.svc,.cluster.local"
	return []corev1.EnvVar{
		{Name: "HTTP_PROXY", Value: httpURL},
		{Name: "http_proxy", Value: httpURL},
		{Name: "HTTPS_PROXY", Value: httpURL},
		{Name: "https_proxy", Value: httpURL},
		{Name: "ALL_PROXY", Value: socksURL},
		{Name: "all_proxy", Value: socksURL},
		{Name: "NO_PROXY", Value: noProxy},
		{Name: "no_proxy", Value: noProxy},
	}
}

// hasProxyEnv reports whether the container already sets any proxy variable.
func hasProxyEnv(env []corev1.EnvVar) bool {
	for _, e := range env {
		switch strings.ToUpper(e.Name) {
		case "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY":
			return true
		}
	}
	return false
}

func hasContainer(cs []corev1.Container, name string) bool {
	for _, c := range cs {
		if c.Name == name {
			return true
		}
	}
	return false
}

func podDisplayName(pod *corev1.Pod) string {
	if pod.Name != "" {
		return pod.Name
	}
	return pod.GenerateName + "*"
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// warn attaches a warning (surfaced by kubectl) to an allowed response and
// normalizes its HTTP code.
func warn(resp admission.Response, w string) admission.Response {
	resp.Warnings = append(resp.Warnings, w)
	if resp.Result != nil && resp.Result.Code == 0 {
		resp.Result.Code = http.StatusOK
	}
	return resp
}
