// Copyright 2026 viaGraph B.V. (Whisper Security)
// SPDX-License-Identifier: MIT

// whisper-operator gives Kubernetes pods a real network identity: a mutating
// admission webhook injects a zero-privilege Whisper egress sidecar into
// annotated pods so their traffic sources from a routable Whisper IPv6 /128 —
// verifiable by anyone via reverse DNS + RDAP. One annotation, no NET_ADMIN,
// fail-open.
package main

import (
	"context"
	"flag"
	"os"
	"strconv"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	egressv1alpha1 "github.com/whisper-sec/whisper-operator/api/v1alpha1"
	"github.com/whisper-sec/whisper-operator/internal/certs"
	"github.com/whisper-sec/whisper-operator/internal/controller"
	"github.com/whisper-sec/whisper-operator/internal/inject"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(egressv1alpha1.AddToScheme(scheme))
}

func main() {
	var metricsAddr, probeAddr, certDir string
	var webhookPort int
	var enableLeaderElection bool
	flag.StringVar(&metricsAddr, "metrics-bind-address", env("METRICS_BIND_ADDRESS", ":8082"), "metrics endpoint bind address ('0' disables)")
	flag.StringVar(&probeAddr, "health-probe-bind-address", env("HEALTH_PROBE_BIND_ADDRESS", ":8081"), "health probe bind address")
	flag.StringVar(&certDir, "cert-dir", env("CERT_DIR", "/tmp/whisper-webhook-certs"), "directory for the webhook serving cert")
	flag.IntVar(&webhookPort, "webhook-port", envInt("WEBHOOK_PORT", 9443), "webhook server port")
	flag.BoolVar(&enableLeaderElection, "leader-elect", env("LEADER_ELECT", "") == "true", "enable leader election for the reconciler")
	opts := zap.Options{Development: false}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	namespace := env("POD_NAMESPACE", "whisper-system")
	certOpts := certs.Options{
		Namespace:         namespace,
		ServiceName:       env("SERVICE_NAME", "whisper-operator-webhook"),
		CertSecretName:    env("CERT_SECRET_NAME", "whisper-operator-webhook-cert"),
		WebhookConfigName: env("WEBHOOK_CONFIG_NAME", "whisper-operator"),
		CertDir:           certDir,
	}
	defaults := inject.Defaults{
		Image:      env("WHISPER_SIDECAR_IMAGE", inject.DefaultImage),
		SecretName: env("WHISPER_DEFAULT_SECRET", inject.DefaultSecretName),
		SecretKey:  env("WHISPER_DEFAULT_SECRET_KEY", inject.DefaultSecretKey),
		Port:       int32(envInt("WHISPER_DEFAULT_PORT", int(inject.DefaultPort))),
	}

	cfg := ctrl.GetConfigOrDie()

	// Self-managed webhook TLS: ensure the CA + leaf BEFORE the manager (and
	// its webhook server) starts, using a direct client — no cert-manager.
	bootCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	directClient, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		setupLog.Error(err, "unable to build bootstrap client")
		os.Exit(1)
	}
	if err := certs.Ensure(bootCtx, directClient, certOpts); err != nil {
		setupLog.Error(err, "unable to bootstrap webhook certificates")
		os.Exit(1)
	}
	cancel()

	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:  scheme,
		Metrics: metricsserver.Options{BindAddress: metricsAddr},
		WebhookServer: webhook.NewServer(webhook.Options{
			Port:    webhookPort,
			CertDir: certDir,
		}),
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "whisper-operator.whisper.security",
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	// The pod injector reads through the UNCACHED API reader so it works with
	// zero CRDs installed and needs no informer warm-up on the admission path.
	decoder := admission.NewDecoder(mgr.GetScheme())
	mgr.GetWebhookServer().Register("/mutate-pod", &webhook.Admission{
		Handler: inject.NewPodInjector(mgr.GetAPIReader(), decoder, defaults),
	})

	// The WhisperEgress reconciler is optional visibility: only wire it when
	// the CRD is installed (the webhook alone is a complete product).
	if crdInstalled(mgr) {
		if err := (&controller.WhisperEgressReconciler{Client: mgr.GetClient()}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "unable to create controller", "controller", "WhisperEgress")
			os.Exit(1)
		}
	} else {
		setupLog.Info("WhisperEgress CRD not installed — running webhook-only (annotations still fully work)")
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("webhook", mgr.GetWebhookServer().StartedChecker()); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting whisper-operator", "sidecarImage", defaults.Image, "defaultPort", defaults.Port)
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}

// crdInstalled reports whether the WhisperEgress CRD is served.
func crdInstalled(mgr ctrl.Manager) bool {
	gvk := egressv1alpha1.GroupVersion.WithKind("WhisperEgress")
	mapper := mgr.GetRESTMapper()
	_, err := mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
	return err == nil
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}
