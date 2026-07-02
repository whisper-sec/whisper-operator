// Copyright 2026 viaGraph B.V. (Whisper Security)
// SPDX-License-Identifier: MIT

package inject

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	egressv1alpha1 "github.com/whisper-sec/whisper-operator/api/v1alpha1"
)

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := egressv1alpha1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return s
}

func apiKeySecret(ns, name, key string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Data:       map[string][]byte{key: []byte("test-key-value")},
	}
}

func newInjector(t *testing.T, objs ...client.Object) *PodInjector {
	t.Helper()
	s := testScheme(t)
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(objs...).Build()
	return NewPodInjector(c, admission.NewDecoder(s), Defaults{})
}

func testPod(ns, name string, ann map[string]string) *corev1.Pod {
	return &corev1.Pod{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"},
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Annotations: ann},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app", Image: "curlimages/curl"}},
		},
	}
}

func request(t *testing.T, pod *corev1.Pod) admission.Request {
	t.Helper()
	raw, err := json.Marshal(pod)
	if err != nil {
		t.Fatal(err)
	}
	return admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
		Operation: admissionv1.Create,
		Namespace: pod.Namespace,
		Object:    runtime.RawExtension{Raw: raw},
	}}
}

// mutatedPod applies the response patch semantics by decoding the handler's
// patched object from the JSON patch response (we re-run applyInjection for
// structural asserts where simpler).
func requireAllowed(t *testing.T, resp admission.Response) {
	t.Helper()
	if !resp.Allowed {
		t.Fatalf("response not allowed: %+v", resp.Result)
	}
}

func TestInjectHappyPath(t *testing.T) {
	inj := newInjector(t, apiKeySecret("team-a", "whisper", "api-key"))
	pod := testPod("team-a", "worker-1", map[string]string{AnnEgress: "enabled"})
	resp := inj.Handle(context.Background(), request(t, pod))
	requireAllowed(t, resp)
	if len(resp.Patches) == 0 {
		t.Fatal("expected a mutation patch, got none")
	}
	// Assert via direct application (same code path builds the patch).
	cfg, _ := inj.resolveConfig(context.Background(), "team-a", pod.Annotations)
	mutated := pod.DeepCopy()
	applyInjection(mutated, cfg)

	if len(mutated.Spec.InitContainers) != 1 || mutated.Spec.InitContainers[0].Name != SidecarName {
		t.Fatalf("sidecar not injected: %+v", mutated.Spec.InitContainers)
	}
	sc := mutated.Spec.InitContainers[0]
	if sc.RestartPolicy == nil || *sc.RestartPolicy != corev1.ContainerRestartPolicyAlways {
		t.Fatal("sidecar must be a NATIVE sidecar (restartPolicy: Always)")
	}
	if sc.Image != DefaultImage {
		t.Fatalf("unexpected image %q", sc.Image)
	}
	if sc.Env[0].Name != "WHISPER_API_KEY" || sc.Env[0].ValueFrom.SecretKeyRef.Name != "whisper" {
		t.Fatalf("api key env wrong: %+v", sc.Env)
	}
	args := strings.Join(sc.Args, " ")
	if !strings.HasPrefix(args, "connect --port 18080") {
		t.Fatalf("unexpected args: %s", args)
	}
	if !strings.Contains(args, "--name k8s-team-a-worker-1") {
		t.Fatalf("expected default --name, got: %s", args)
	}
	app := mutated.Spec.Containers[0]
	envMap := map[string]string{}
	for _, e := range app.Env {
		envMap[e.Name] = e.Value
	}
	for _, k := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"} {
		if envMap[k] != "http://127.0.0.1:18080" {
			t.Fatalf("%s = %q", k, envMap[k])
		}
	}
	if envMap["ALL_PROXY"] != "socks5h://127.0.0.1:18080" {
		t.Fatalf("ALL_PROXY = %q", envMap["ALL_PROXY"])
	}
	if !strings.Contains(envMap["NO_PROXY"], ".cluster.local") {
		t.Fatalf("NO_PROXY = %q", envMap["NO_PROXY"])
	}
	if mutated.Annotations[AnnStatus] != StatusInjected {
		t.Fatal("idempotency stamp missing")
	}
}

func TestIdempotentOnStamp(t *testing.T) {
	inj := newInjector(t, apiKeySecret("ns1", "whisper", "api-key"))
	pod := testPod("ns1", "p", map[string]string{AnnStatus: StatusInjected})
	resp := inj.Handle(context.Background(), request(t, pod))
	requireAllowed(t, resp)
	if len(resp.Patches) != 0 {
		t.Fatalf("stamped pod must not be re-mutated: %+v", resp.Patches)
	}
}

func TestOptOutAnnotation(t *testing.T) {
	inj := newInjector(t, apiKeySecret("ns1", "whisper", "api-key"))
	for _, v := range []string{"disabled", "false", "off", "no", "FALSE"} {
		pod := testPod("ns1", "p", map[string]string{AnnEgress: v})
		resp := inj.Handle(context.Background(), request(t, pod))
		requireAllowed(t, resp)
		if len(resp.Patches) != 0 {
			t.Fatalf("opt-out %q must not mutate", v)
		}
	}
}

func TestMissingSecretAdmitsUnmutatedWithWarning(t *testing.T) {
	inj := newInjector(t) // no secret exists
	pod := testPod("ns1", "p", nil)
	resp := inj.Handle(context.Background(), request(t, pod))
	requireAllowed(t, resp)
	if len(resp.Patches) != 0 {
		t.Fatal("must not inject without the api-key Secret")
	}
	if len(resp.Warnings) == 0 || !strings.Contains(resp.Warnings[0], "kubectl create secret") {
		t.Fatalf("expected a helpful warning, got %v", resp.Warnings)
	}
}

func TestSecretKeyMissingAdmitsUnmutated(t *testing.T) {
	inj := newInjector(t, apiKeySecret("ns1", "whisper", "wrong-key"))
	pod := testPod("ns1", "p", nil)
	resp := inj.Handle(context.Background(), request(t, pod))
	requireAllowed(t, resp)
	if len(resp.Patches) != 0 {
		t.Fatal("must not inject when the Secret lacks the key")
	}
	if len(resp.Warnings) == 0 || !strings.Contains(resp.Warnings[0], "wrong-key") {
		t.Fatalf("warning should list found keys: %v", resp.Warnings)
	}
}

func TestUnsupportedModeAdmitsUnmutated(t *testing.T) {
	inj := newInjector(t, apiKeySecret("ns1", "whisper", "api-key"))
	pod := testPod("ns1", "p", map[string]string{AnnMode: "transparent"})
	resp := inj.Handle(context.Background(), request(t, pod))
	requireAllowed(t, resp)
	if len(resp.Patches) != 0 {
		t.Fatal("unsupported mode must not mutate")
	}
	if len(resp.Warnings) == 0 || !strings.Contains(resp.Warnings[0], "transparent") {
		t.Fatalf("expected mode warning, got %v", resp.Warnings)
	}
}

func TestAgentAnnotationPinsIdentity(t *testing.T) {
	inj := newInjector(t, apiKeySecret("ns1", "whisper", "api-key"))
	ann := map[string]string{AnnAgent: "2a04:2a01::dead:beef"}
	cfg, _ := inj.resolveConfig(context.Background(), "ns1", ann)
	pod := testPod("ns1", "p", ann)
	sc := buildSidecar(pod, cfg)
	args := strings.Join(sc.Args, " ")
	if !strings.Contains(args, "--agent 2a04:2a01::dead:beef") {
		t.Fatalf("agent pin missing: %s", args)
	}
	if strings.Contains(args, "--name") {
		t.Fatalf("--name must not accompany a pinned --agent: %s", args)
	}
}

func TestExistingProxyEnvRespected(t *testing.T) {
	inj := newInjector(t, apiKeySecret("ns1", "whisper", "api-key"))
	pod := testPod("ns1", "p", nil)
	pod.Spec.Containers[0].Env = []corev1.EnvVar{{Name: "HTTPS_PROXY", Value: "http://corp-proxy:3128"}}
	cfg, _ := inj.resolveConfig(context.Background(), "ns1", pod.Annotations)
	mutated := pod.DeepCopy()
	applyInjection(mutated, cfg)
	if len(mutated.Spec.Containers[0].Env) != 1 {
		t.Fatalf("user proxy env must be respected: %+v", mutated.Spec.Containers[0].Env)
	}
	if len(mutated.Spec.InitContainers) != 1 {
		t.Fatal("sidecar should still be injected")
	}
}

func TestInvalidPortFallsBackWithWarning(t *testing.T) {
	inj := newInjector(t, apiKeySecret("ns1", "whisper", "api-key"))
	cfg, warns := inj.resolveConfig(context.Background(), "ns1", map[string]string{AnnPort: "not-a-port"})
	if cfg.port != DefaultPort {
		t.Fatalf("expected fallback port %d, got %d", DefaultPort, cfg.port)
	}
	if len(warns) == 0 {
		t.Fatal("expected a warning for the bad port")
	}
}

func TestWhisperEgressNamespaceDefaults(t *testing.T) {
	we := &egressv1alpha1.WhisperEgress{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns1", Name: "default"},
		Spec: egressv1alpha1.WhisperEgressSpec{
			SecretRef: &egressv1alpha1.SecretReference{Name: "team-secret", Key: "token"},
			Port:      12345,
			Tier:      "socks5",
			Image:     "ghcr.io/whisper-sec/whisper:pinned",
		},
	}
	inj := newInjector(t, we, apiKeySecret("ns1", "team-secret", "token"))
	cfg, _ := inj.resolveConfig(context.Background(), "ns1", nil)
	if cfg.secretName != "team-secret" || cfg.secretKey != "token" || cfg.port != 12345 || cfg.image != "ghcr.io/whisper-sec/whisper:pinned" {
		t.Fatalf("WhisperEgress defaults not applied: %+v", cfg)
	}
	// Pod annotation still wins over the CRD.
	cfg2, _ := inj.resolveConfig(context.Background(), "ns1", map[string]string{AnnPort: "2000", AnnSecret: "pod-secret"})
	if cfg2.port != 2000 || cfg2.secretName != "pod-secret" {
		t.Fatalf("annotation precedence broken: %+v", cfg2)
	}
}

func TestSecondInvocationAfterPatchIsNoop(t *testing.T) {
	// Simulates reinvocationPolicy: IfNeeded - a pod already carrying the
	// sidecar (but no stamp) must not get a second one.
	inj := newInjector(t, apiKeySecret("ns1", "whisper", "api-key"))
	pod := testPod("ns1", "p", nil)
	always := corev1.ContainerRestartPolicyAlways
	pod.Spec.InitContainers = []corev1.Container{{Name: SidecarName, RestartPolicy: &always}}
	resp := inj.Handle(context.Background(), request(t, pod))
	requireAllowed(t, resp)
	if len(resp.Patches) != 0 {
		t.Fatal("pod with an existing whisper sidecar must not be re-mutated")
	}
}

func TestGenerateNamePodGetsAgentName(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "jobs", GenerateName: "batch-"},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}},
	}
	n := agentName(pod, "")
	if n != "k8s-jobs-batch" {
		t.Fatalf("agentName = %q", n)
	}
}
