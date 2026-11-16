---
title: Deployment checks
description: Prepare an installation, verify access and isolation, and diagnose operational failures.
---

Use the [operator quickstart](getting-started.md) for a first installation and
[Install and upgrade](packaging.md) for packaging and release changes. This page
covers the decisions and checks needed before engineers use the service.

Configure identity using [Authentication & SSO](authentication.md); its provider guides cover
Keycloak and Okta, with separate setup for external MCP agents.

## Platform prerequisites

Both current backends need an Agent Sandbox controller and CRDs. OpenShell
profiles also need the compatible gateway, its client credentials and native
runtime/network prerequisites. Enable the relevant optional subcharts or reuse
existing installations; the portal does not discover and install missing services.

The [requirements table](getting-started.md#requirements-and-optional-components)
separates chart components from operator-provided storage, nodes, identity and
network enforcement. Ordinary containers are useful for development; select and
verify Kata when the deployment requires a separate guest kernel.

## Keep deployment configuration separate

| Scope    | Configuration                                                                         |
| -------- | ------------------------------------------------------------------------------------- |
| Portal   | Origin/base path, OIDC, roles, metadata database and replica settings.                |
| Profile  | Workload image, native runtime configuration, startup, helpers and resource choices.  |
| Platform | Nodes, RuntimeClasses, storage, CNI, namespace policy, admission and secret delivery. |
| Tool     | Its server URL, native login flow and persistent credential path.                     |

For a dedicated hostname, set `settings.basePath: ""`, the correct HTTPS
`settings.origin`, and the exact `/auth/callback` redirect at the identity
provider. A subpath deployment includes that base path in its callback. Configure
the ingress for WebSocket upgrades and connection timeouts suitable for terminals.

Use deployment-owned Secrets for authentication and database/gateway credentials.
Keep a unique namespace prefix and independent database for each installation.
Replicas of one installation share the database and session-signing Secret.

## Acceptance before opening access

| Check                 | Expected result                                                                                                                                                  |
| --------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Sign-in               | An allowed engineer can enter; an identity outside the configured admission policy cannot. Admin access is limited to the intended emails.                       |
| Creation              | A disposable sandbox reaches native readiness using the intended image, runtime, namespace and resource limits.                                                  |
| Terminal and tools    | A shell works through the real ingress. Tool sign-in and helper status work independently of portal sign-in.                                                     |
| Persistence           | A file in a persistent mount survives suspend/resume. A file outside those mounts has no such guarantee.                                                         |
| Ownership and sharing | A second identity cannot use an unshared sandbox. Namespace sharing grants the intended access without transferring VM lifecycle ownership.                      |
| Enforcement           | Disallowed network destinations, direct egress bypasses and prohibited workload settings fail at the expected layer. Badges alone do not prove this.             |
| Limits                | A creator at the configured sandbox count/resource limit cannot exceed it, including through concurrent requests.                                                |
| Recovery              | A controlled portal replacement warns connected users and reconnects ordinary shells without replaying commands. A backup restores into an isolated test target. |
| Cleanup               | Deleting the disposable sandbox retires its native resources and follows the intended volume/namespace retention policy.                                         |

Run these checks separately for each offered backend/runtime combination. Record
the chart/image versions and results; a successful Helm rollout is only part of
acceptance. See [Security](security.md), [Capacity and scaling](scaling.md) and
[Database and persistence](metadata.md) for the relevant boundaries.

## Health and troubleshooting

For the quickstart release `sandbox` in `sandbox-system`:

```sh
kubectl -n sandbox-system get deployments,pods,pvc,ingress
kubectl -n sandbox-system rollout status deployment/sandbox --timeout=10m
kubectl -n sandbox-system logs deployment/sandbox -c metadata-schema --tail=100
kubectl -n sandbox-system logs deployment/sandbox -c portal --tail=100
```

Replace the release and namespace names for your installation. `/healthz` checks
that the portal responds. `/readyz` also rejects draining replicas and checks the
metadata schema and controls. Neither endpoint proves a native gateway, controller,
tool login or workload is healthy.

| Symptom                               | First checks                                                                                                                                                                       |
| ------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Schema init fails                     | Inspect `metadata-schema` logs, Secret access and the expected schema. A required schema change needs a reviewed Recreate upgrade; do not clear tables to bypass the check.        |
| Creation remains pending              | Inspect the card's error details, native Sandbox/Pod events, image pulls, runtime/node compatibility and storage binding. For OpenShell, also inspect gateway and supervisor logs. |
| A timeout leaves an unfinished action | Refresh native status and inspect the saved operation before retrying. A timeout is not proof that creation or deletion failed. Use the supported Retry/recovery path.             |
| Terminal or helper fails              | Copy the diagnostic ID; check ingress WebSockets, portal logs, access/session validity and the selected backend's exec path.                                                       |
| Configuration drift appears           | Review View/Sync Configuration and the native resource identity. Only supported fields/backends can be synced; do not blindly adopt a replaced object.                             |

## Logs and tracing

The portal emits JSON logs to container output. Ship them through the platform's
existing collector and retain audit events according to your organization's policy.
Use `request_id` for one HTTP/terminal connection and `operation_id` for a saved
lifecycle action; `sandbox_id`, namespace, provider and actor connect related
events where available. A retry may have a new request ID for the same operation.

Tracing is optional: set `observability.tracing.endpoint` to your OTLP/HTTP
collector base endpoint and choose `sampleRatio`. Trace/span IDs join logs when
tracing is active. Configure native Agent Sandbox/OpenShell trace export separately
through their chart values; a portal endpoint does not enable every integration.

The included Agent Sandbox controller defaults to INFO/JSON logging with Sandbox
events enabled. The OpenShell gateway defaults to INFO. Collect controller,
gateway and supervisor output as well as portal logs. Keep command transcripts,
tokens and credential files out of routine audit collection; control-plane events
are not a recording of every action inside a shell.
