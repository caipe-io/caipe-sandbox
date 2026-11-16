---
title: Get started
description: Deploy CAIPE Sandbox on Kubernetes with Helm and verify your first sandbox.
---

This guide is for **platform operators deploying CAIPE Sandbox**. One Helm chart
can install the portal, its persistent SQLite database and the Agent Sandbox
controller. You supply storage, HTTPS and your identity provider.

This quickstart uses ordinary containers on an existing Kubernetes cluster.
[Add Kata](#add-micro-vm-isolation) when you are ready to run workloads in micro VMs.

:::info First OSS release
The portal/chart import is still under review. The published-chart command
becomes available after the first OCI release. Until then, use the
[source-checkout option](#install-from-source) with your own built portal image.
:::

## Requirements and optional components

### Core requirements

| Component                                    | Requirement                                            | Who provides it?                                                                                                              |
| -------------------------------------------- | ------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------- |
| Kubernetes **1.30+** and Linux node capacity | Required                                               | Operator-provided cluster.                                                                                                    |
| Helm **3.17+** and `kubectl`                 | Required for installation                              | Operator's workstation or deployment pipeline.                                                                                |
| Portal                                       | Required                                               | Included in the main chart.                                                                                                   |
| Metadata database                            | Required                                               | SQLite is included by default; use one portal replica. External PostgreSQL is an alternative.                                 |
| Persistent storage                           | Required for SQLite and persistent sandbox files       | Operator-provided CSI driver and StorageClass. This quickstart uses the cluster default.                                      |
| Identity provider                            | Required; this quickstart uses OIDC                    | Operator provides the identity provider, client registration and authentication Secret.                                       |
| DNS, HTTPS and ingress                       | Required for this quickstart                           | Operator provides DNS, an ingress controller and TLS certificate. The chart can create the Ingress resource.                  |
| Agent Sandbox controller and CRDs            | Required by both current sandbox backends              | Optional subchart via `agentSandbox.enabled`, or reuse an existing installation. Installation defaults **off**.               |
| CNI and platform network policies            | An enforcing CNI is needed for NetworkPolicy isolation | Operator provides network enforcement and platform policies. The portal's additional baseline is opt-in and defaults **off**. |

The installing identity needs permission to create cluster-scoped CRDs, RBAC and
admission policies. Agent Sandbox is a dependency of the current backends, rather
than an unconditional installation: the quickstart enables its subchart, while
clusters with an existing controller leave that toggle off.

### Optional integrations and services

| Component                         | When to use it                                                        | Installation                                                                                                   |
| --------------------------------- | --------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| Kata                              | Micro VM isolation using a Kata RuntimeClass                          | Optional upstream subchart, `kata.enabled`; defaults **off**. Can also be operator-installed.                  |
| OpenShell                         | Runtime process and network policy                                    | Optional upstream subchart, `openShell.enabled`; defaults **off**. Can also use an existing gateway.           |
| Omnigent                          | Optional agent/tool integration                                       | Optional application subchart, `omnigent.enabled`; defaults **off**. Can also use an existing server.          |
| PostgreSQL                        | Multiple portal replicas or an externally managed database            | **External only:** supply a connection through a Secret. No PostgreSQL server or database operator is bundled. |
| cert-manager                      | Automated certificate management, if your platform uses it            | Operator-provided; not bundled.                                                                                |
| Vault / External Secrets Operator | Delivering credentials through your existing secret-management system | Operator-provided; not bundled. Ordinary Kubernetes Secrets also work.                                         |
| Karpenter / node autoscaler       | Provisioning and scaling cluster capacity                             | Operator-provided; not bundled. Existing static nodes also work.                                               |
| Log/trace collectors and backends | Central logging, auditing and tracing                                 | Operator-provided; not bundled. The portal emits logs and supports optional OTLP tracing.                      |
| Argo CD / GitOps tooling          | Managing installations through GitOps                                 | Operator-provided; not bundled. Plain Helm works independently.                                                |

All optional integration subcharts default off. Leaving a subchart off means the
chart does not install that service; profiles may still use an existing service.
Only SQLite is bundled for metadata storage.

Use `extraObjects` for additional Kubernetes resources, such as an ExternalSecret;
the operator still provides the controllers those resources require. See
[Packaging](packaging.md#operator-objects-and-network-policies) for examples.

## 1. Prepare sign-in and HTTPS

Use [Authentication & SSO](authentication.md) for provider setup, including
[Keycloak](authentication-keycloak.md) and [Okta](authentication-okta.md).

This example uses `https://sandbox.example.com`. Register this exact redirect URI
with your OIDC provider:

```text
https://sandbox.example.com/auth/callback
```

Create the namespace and provide a TLS Secret named `sandbox-tls` there using
your platform's normal certificate management:

```sh
kubectl create namespace sandbox-system
```

Prepare two private files outside source control, without trailing newlines:

- `oidc-client-secret`: the client secret from your identity provider.
- `session-secret`: a random session-signing secret of at least 32 characters.

For example, generate the session secret with:

```sh
umask 077
openssl rand -hex 32 | tr -d '\n' > session-secret
```

Create the authentication Secret:

```sh
kubectl -n sandbox-system create secret generic portal-oidc \
  --from-file=client-secret=./oidc-client-secret \
  --from-file=session-secret=./session-secret
```

## 2. Create your values file

Save this as `values.yaml`. Replace the hostname, ingress class, OIDC settings
and email addresses with your own.

```yaml title="values.yaml"
agentSandbox:
  enabled: true

settings:
  origin: https://sandbox.example.com
  basePath: ""
  namespacePrefix: sandbox
  # Initial evaluation: approve the cluster's default container runtime.
  runtimeClass: ""
  allowedRuntimeClasses: [""]
  maxSandboxesPerUser: 5

auth:
  mode: oidc
  existingSecret: portal-oidc
  adminEmails: [operator@example.com]
  oidc:
    issuer: https://identity.example.com
    client_id: sandbox-portal
    scopes: openid email profile
    allowed_email_domains: [example.com]
    default_role: user

ingress:
  enabled: true
  className: nginx
  host: sandbox.example.com
  tlsSecretName: sandbox-tls
```

The chart supplies one portal replica, SQLite storage and a starting sandbox
profile. This example admits verified users from the allowed email domain and
makes the listed operator an administrator. Use group restrictions for a smaller
cohort; see [Security](security.md).

If Agent Sandbox is already installed, use `agentSandbox.enabled: false` to reuse
it. Install the controller only once per cluster, and choose a unique
`settings.namespacePrefix` for each portal installation.

## 3. Install with Helm

Replace `PUBLISHED_CHART_VERSION` with the published chart version you want to install:

```sh
helm upgrade --install sandbox oci://ghcr.io/caipe-io/charts/caipe-sandbox \
  --version PUBLISHED_CHART_VERSION \
  --namespace sandbox-system \
  -f values.yaml \
  --wait --timeout 10m
```

Published charts include their dependencies and pin the portal and default
workload image digests. Components do not need separate Helm installations.

### Install from source

Build and push the portal image using the [contributor instructions](contributing.md),
then install the local chart with that image's repository and immutable digest:

```sh
helm dependency build charts/caipe-sandbox --skip-refresh

helm upgrade --install sandbox ./charts/caipe-sandbox \
  --namespace sandbox-system \
  -f values.yaml \
  --set-string image.repository=YOUR_REGISTRY/caipe-sandbox-portal \
  --set-string image.digest=sha256:YOUR_IMAGE_DIGEST \
  --wait --timeout 10m
```

The source chart starts with a basic Python/shell image. Published charts select
the released default workload image, which also provides startup/service
management. Add agent binaries through your own image and [profiles](profiles.md).

## 4. Verify your first sandbox

```sh
kubectl -n sandbox-system get deployments,pods,pvc,ingress
kubectl -n sandbox-system rollout status deployment/sandbox
```

Open your HTTPS portal URL and sign in as the configured operator. Create a
disposable sandbox, open its terminal and write a file under its persistent home
directory. Suspend/resume it and confirm the file remains, then delete the test
sandbox.

If the portal does not become ready, inspect its application and schema-init logs:

```sh
kubectl -n sandbox-system logs deployment/sandbox -c portal --tail=100
kubectl -n sandbox-system logs deployment/sandbox -c metadata-schema --tail=100
```

## Add micro VM isolation

Once Kata is installed on compatible nodes, select its installed RuntimeClass:

```yaml
settings:
  runtimeClass: kata-qemu
  allowedRuntimeClasses: [kata-qemu]
```

Replace `kata-qemu` with your platform's actual RuntimeClass name. Kata can be
operator-managed or installed through `kata.enabled`, with node/shim settings
suited to your infrastructure. Create a new sandbox to verify VM isolation;
existing sandboxes retain their recorded runtime.

Continue with [Packaging](packaging.md) for Kata/OpenShell installation,
[Profiles](profiles.md) for agent tools and startup configuration, and
[Database and persistence](metadata.md) for PostgreSQL, backups and upgrades.
