// Copyright 2026 viaGraph B.V. (Whisper Security)
// SPDX-License-Identifier: MIT

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SecretReference points at the Kubernetes Secret holding the Whisper API key
// used by injected sidecars in this namespace.
type SecretReference struct {
	// Name of the Secret (in the same namespace as the pods).
	Name string `json:"name"`
	// Key inside the Secret holding the API key. Defaults to "api-key".
	// +optional
	Key string `json:"key,omitempty"`
}

// WhisperEgressSpec holds per-namespace defaults for Whisper egress injection.
// Every field is optional: pod annotations override these, and these override
// the operator's chart-level defaults (Postel: sensible defaults everywhere).
type WhisperEgressSpec struct {
	// SecretRef names the Secret holding the Whisper API key.
	// Default: {name: whisper, key: api-key}.
	// +optional
	SecretRef *SecretReference `json:"secretRef,omitempty"`

	// AgentNamePrefix seeds the human name used if a brand-new Whisper agent
	// has to be created for a pod (accounts with existing agents reuse them).
	// +optional
	AgentNamePrefix string `json:"agentNamePrefix,omitempty"`

	// Tier selects the egress tier: "socks5" (default, zero-privilege) or
	// "wireguard" (routed /128; requires TUN support in the pod).
	// +optional
	// +kubebuilder:validation:Enum=socks5;wireguard
	Tier string `json:"tier,omitempty"`

	// Mode selects how app traffic reaches the sidecar: "proxy" (default —
	// HTTP(S)_PROXY/ALL_PROXY env pointing at the local sidecar proxy).
	// +optional
	// +kubebuilder:validation:Enum=proxy
	Mode string `json:"mode,omitempty"`

	// Port is the local loopback port the sidecar proxy listens on. Default 18080.
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port,omitempty"`

	// Image overrides the sidecar image. Default ghcr.io/whisper-sec/whisper:latest.
	// +optional
	Image string `json:"image,omitempty"`
}

// WhisperEgressStatus reports the observed state.
type WhisperEgressStatus struct {
	// InjectedPods is the number of pods in this namespace currently carrying
	// an injected Whisper sidecar.
	// +optional
	InjectedPods int32 `json:"injectedPods,omitempty"`

	// LastError surfaces the most recent configuration problem (e.g. the
	// referenced Secret is missing), empty when healthy.
	// +optional
	LastError string `json:"lastError,omitempty"`

	// Conditions follow the standard Kubernetes condition conventions.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=wegress
// +kubebuilder:printcolumn:name="Secret",type=string,JSONPath=`.spec.secretRef.name`
// +kubebuilder:printcolumn:name="Tier",type=string,JSONPath=`.spec.tier`
// +kubebuilder:printcolumn:name="Injected",type=integer,JSONPath=`.status.injectedPods`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`

// WhisperEgress holds per-namespace defaults for Whisper egress sidecar
// injection. It is OPTIONAL: the webhook works with zero WhisperEgress
// objects installed — pod annotations alone are enough.
type WhisperEgress struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   WhisperEgressSpec   `json:"spec,omitempty"`
	Status WhisperEgressStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// WhisperEgressList contains a list of WhisperEgress.
type WhisperEgressList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []WhisperEgress `json:"items"`
}

func init() {
	SchemeBuilder.Register(&WhisperEgress{}, &WhisperEgressList{})
}
