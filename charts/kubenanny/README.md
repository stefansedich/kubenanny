# kubenanny

eBPF-based Kubernetes egress hostname filter.

## Installation

```bash
helm install kubenanny ./charts/kubenanny \
  --namespace kubenanny-system \
  --create-namespace \
  --set image.repository=kubenanny \
  --set image.tag=latest
```

## Configuration

See [values.yaml](values.yaml) for the full list of configurable parameters.

| Parameter | Description | Default |
|---|---|---|
| `image.repository` | Container image repository | `kubenanny` |
| `image.tag` | Container image tag | `latest` |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `hostNetwork` | Enable host networking (required for TC attachment) | `true` |
| `tolerations` | Node tolerations | `[{operator: Exists}]` |
| `resources.requests.cpu` | CPU request | `100m` |
| `resources.requests.memory` | Memory request | `128Mi` |
| `resources.limits.cpu` | CPU limit | `500m` |
| `resources.limits.memory` | Memory limit | `256Mi` |
| `metrics.enabled` | Enable Prometheus metrics | `true` |
| `metrics.port` | Metrics port | `9090` |
| `metrics.serviceMonitor.enabled` | Create ServiceMonitor for Prometheus Operator | `false` |
| `serviceAccount.create` | Create a ServiceAccount | `true` |
| `securityContext.privileged` | Run with privileged security context (required for eBPF) | `true` |

## Uninstallation

```bash
helm uninstall kubenanny --namespace kubenanny-system
```

> **Note:** The CRD is installed as part of the chart. Helm will not delete CRDs on uninstall by default. To remove the CRD manually:
> ```bash
> kubectl delete crd egresspolicies.policy.kubenanny.io
> ```
