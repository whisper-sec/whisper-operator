# whisper-operator

Give any Kubernetes pod a **real network identity**. One label, and a pod's
egress sources from a routable **Whisper IPv6 /128** — an identity anyone can
verify with plain `dig` and RDAP. Zero privileges, no NET_ADMIN, fail-open.

```bash
helm install whisper-operator oci://ghcr.io/whisper-sec/charts/whisper-operator \
  --namespace whisper-system --create-namespace
```

Then, in the namespace your workload runs in:

```bash
kubectl create secret generic whisper --from-literal=api-key=<your Whisper API key>
kubectl label namespace <ns> whisper.security/egress=enabled
```

That's it. Every new pod in that namespace gets a Whisper egress sidecar and
its outbound traffic carries a verifiable identity:

```bash
kubectl exec <pod> -- curl -s https://v6.ident.me
# 2a04:2a01:xxxx:...          ← the pod's own Whisper /128

dig -x 2a04:2a01:xxxx:...     # → <agent>.<tenant>.agents.whisper.online
curl https://rdap.whisper.online/ip/2a04:2a01:xxxx:...   # full RDAP, no key needed
```

No API key yet? Get one at [whisper.online](https://whisper.online). Identity
*verification* (reverse DNS, RDAP, `whisper verify`) needs no key at all.

## How it works

A mutating admission webhook watches for opted-in pods and injects:

1. **A native sidecar** (Kubernetes ≥ 1.29: an initContainer with
   `restartPolicy: Always`, so it starts before and outlives your app) running
   [`whisper connect`](https://github.com/whisper-sec/whisper-cli) from the
   official `ghcr.io/whisper-sec/whisper` image. It provisions the pod's /128
   and serves a local SOCKS5h + HTTP-CONNECT proxy on `127.0.0.1:18080`.
2. **Proxy environment** (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`,
   upper- and lowercase) into every app container that doesn't already set one
   — your code changes not at all.

The pod needs **no privileges**: no NET_ADMIN, no iptables, no host network.
The /128 source-binding happens at the Whisper edge, so this works on
IPv4-only clusters too.

### Fail-open, by design

A Whisper hiccup must never block your workloads. The webhook registers with
`failurePolicy: Ignore`, and every in-handler problem — a missing Secret, a
malformed annotation — admits the pod **unmutated with a clear warning**,
never an error.

## Opting in

| Scope | How |
|---|---|
| Whole namespace | `kubectl label ns <ns> whisper.security/egress=enabled` |
| Single pod (any namespace) | pod **label** `whisper.security/egress: enabled` |
| Opt a pod out of a labelled namespace | pod annotation `whisper.security/egress: disabled` |

## Per-pod configuration (annotations)

| Annotation | Default | Meaning |
|---|---|---|
| `whisper.security/agent` | account default | Pin a Whisper agent identity: id, name, or its /128 |
| `whisper.security/secret` | `whisper` | Secret holding the API key |
| `whisper.security/secret-key` | `api-key` | Key inside that Secret |
| `whisper.security/port` | `18080` | Local proxy port |
| `whisper.security/tier` | `socks5` | Egress tier (`socks5` zero-privilege; `wireguard` needs TUN) |
| `whisper.security/image` | `ghcr.io/whisper-sec/whisper:latest` | Sidecar image |

Containers that already define `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` are left
untouched — the operator respects your proxy setup.

> **Heads-up (Node.js):** Node's global `fetch` honors proxy environment
> variables only from Node **22.21**. On older Node, use `undici`'s
> `EnvHttpProxyAgent` or an HTTP client that reads the proxy env — otherwise
> traffic silently bypasses the sidecar and egresses from the node IP.

## Per-namespace defaults (optional CRD)

Install once, and pods need only the opt-in label:

```yaml
apiVersion: egress.whisper.security/v1alpha1
kind: WhisperEgress
metadata:
  name: default
  namespace: my-team
spec:
  secretRef: { name: whisper, key: api-key }
  port: 18080
```

`kubectl get wegress -n my-team` shows readiness (is the Secret there?) and
the count of injected pods. The CRD is optional — annotations alone are a
complete interface, and the operator runs webhook-only if the CRD is absent.

Precedence: pod annotations → namespace `WhisperEgress` → chart values.

## Chart values (the useful ones)

| Value | Default | |
|---|---|---|
| `sidecar.image` | `ghcr.io/whisper-sec/whisper:latest` | Injected sidecar image |
| `sidecar.secretName` / `sidecar.secretKey` | `whisper` / `api-key` | Default API-key Secret |
| `sidecar.port` | `18080` | Local proxy port |
| `webhook.failurePolicy` | `Ignore` | Keep `Ignore` unless you want hard-fail admission |
| `certs.mode` | `self-managed` | The operator mints + rotates its own webhook CA; cert-manager not required |
| `replicaCount` | `1` | Set ≥2 + `leaderElection: true` for HA |

## Verify an identity (no key required)

```bash
whisper verify <the /128>                       # DNSSEC + DANE + transparency
dig -x <the /128> +short                        # PTR → <agent>.agents.whisper.online
curl https://rdap.whisper.online/ip/<the /128>  # RDAP: holder, abuse contact, status
```

## Building from source

```bash
make            # generate + vet + test + build
make docker-build IMG=ghcr.io/whisper-sec/whisper-operator:dev
```

## License

MIT © 2026 viaGraph B.V. (Whisper Security)
