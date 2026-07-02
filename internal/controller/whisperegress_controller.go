// Copyright 2026 viaGraph B.V. (Whisper Security)
// SPDX-License-Identifier: MIT

// Package controller holds the (deliberately thin) WhisperEgress reconciler.
// All injection logic lives in the webhook; the reconciler only validates the
// referenced Secret and surfaces status - visibility, not machinery.
package controller

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	egressv1alpha1 "github.com/whisper-sec/whisper-operator/api/v1alpha1"
	"github.com/whisper-sec/whisper-operator/internal/inject"
)

// WhisperEgressReconciler validates WhisperEgress objects and reports status.
type WhisperEgressReconciler struct {
	client.Client
}

// +kubebuilder:rbac:groups=egress.whisper.security,resources=whisperegresses,verbs=get;list;watch
// +kubebuilder:rbac:groups=egress.whisper.security,resources=whisperegresses/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch

// Reconcile checks the referenced Secret exists and counts injected pods.
func (r *WhisperEgressReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	we := &egressv1alpha1.WhisperEgress{}
	if err := r.Get(ctx, req.NamespacedName, we); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	secretName, secretKey := inject.DefaultSecretName, inject.DefaultSecretKey
	if we.Spec.SecretRef != nil && we.Spec.SecretRef.Name != "" {
		secretName = we.Spec.SecretRef.Name
		if we.Spec.SecretRef.Key != "" {
			secretKey = we.Spec.SecretRef.Key
		}
	}

	ready := metav1.Condition{
		Type:               "Ready",
		Status:             metav1.ConditionTrue,
		Reason:             "SecretFound",
		Message:            fmt.Sprintf("Secret %q with key %q is present", secretName, secretKey),
		ObservedGeneration: we.Generation,
	}
	lastError := ""

	secret := &corev1.Secret{}
	err := r.Get(ctx, types.NamespacedName{Namespace: we.Namespace, Name: secretName}, secret)
	switch {
	case apierrors.IsNotFound(err):
		ready.Status = metav1.ConditionFalse
		ready.Reason = "SecretMissing"
		ready.Message = fmt.Sprintf("Secret %q not found in namespace %q", secretName, we.Namespace)
		lastError = ready.Message
	case err != nil:
		return ctrl.Result{}, err
	default:
		if _, ok := secret.Data[secretKey]; !ok {
			ready.Status = metav1.ConditionFalse
			ready.Reason = "SecretKeyMissing"
			ready.Message = fmt.Sprintf("Secret %q has no key %q", secretName, secretKey)
			lastError = ready.Message
		}
	}

	// Count pods carrying the injection stamp (visibility only).
	pods := &corev1.PodList{}
	injected := int32(0)
	if err := r.List(ctx, pods, client.InNamespace(we.Namespace)); err == nil {
		for i := range pods.Items {
			if pods.Items[i].Annotations[inject.AnnStatus] == inject.StatusInjected {
				injected++
			}
		}
	}

	meta.SetStatusCondition(&we.Status.Conditions, ready)
	we.Status.InjectedPods = injected
	we.Status.LastError = lastError
	if err := r.Status().Update(ctx, we); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	log.V(1).Info("reconciled WhisperEgress", "ready", ready.Status, "injectedPods", injected)
	// Periodic re-check: catches a Secret created after the WhisperEgress.
	return ctrl.Result{RequeueAfter: 2 * time.Minute}, nil
}

// SetupWithManager wires the reconciler.
func (r *WhisperEgressReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&egressv1alpha1.WhisperEgress{}).
		Named("whisperegress").
		Complete(r)
}
