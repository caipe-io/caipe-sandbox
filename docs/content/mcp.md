---
title: Connect agents with MCP
---

An external MCP client can run commands in a selected sandbox. The MCP server runs in the portal;
the agent stays outside the micro VM. Commands follow its existing runtime and network policies.

## Enable a sandbox

MCP must first be enabled by the platform operator with an OAuth provider that can issue access
tokens for this resource. Browser sign-in alone does not enable external agent authentication.

1. Open the sandbox's **Actions → Enable MCP**.
2. Review and confirm access. This enables shell commands, including file changes, for authenticated
   users who already have shell permission.
3. Select **MCP Enabled** below the resource stats, then copy the **MCP server URL** and **Sandbox ID**
   into your agent's setup. Use its standard remote
   Streamable HTTP/OAuth connection flow. Registration requirements depend on your identity provider/client.

Ask the agent to retain the immutable Sandbox ID and use it in every call. Display names are not IDs.
Enabling MCP does not grant access to other users or grant administrators implicit execution access.
The confirmation closes automatically after saving. Changing access remains limited to the owner
or an administrator; shared users can view connection details.

## Tools

| Tool | Use |
| --- | --- |
| `list_sandboxes` | Discover enabled sandboxes you may access. Follow pagination even if a filtered page is empty. |
| `get_sandbox` | Confirm the ID, state, runtime requirements and effective limits. |
| `run_command` | Run a command with optional `cwd`, finite `stdin`, timeout and `run_in_background`. |
| `read_execution` | Read a session's stdout/stderr, status and exit code using its output cursor. |
| `cancel_execution` | Request cancellation, then read the same session to confirm its exit. |

Use ordinary commands such as `pwd`, `ls`, `find`, `git` and available patch tools for file work.
Each call has its own working directory and environment. A previous `cd` does not affect later calls.
Commands run through `/bin/sh`; Python 3 in the image supplies the short-lived command wrapper for
stdin, remote deadlines and process-group cancellation. Custom images must provide both programs.
No SSH server, WebSocket tunnel server or per-VM MCP daemon is installed.

`run_in_background: false` is the default: return stdout, stderr and exit code when finished.
`true` returns a live `session_id` promptly. A foreground command exceeding the response wait budget
also returns that handle. Keep the returned `sandbox_id`, `session_id` and `next_cursor`.
`read_execution` never starts the command again; repeated cursors re-read retained output.

## Operator configuration

MCP is disabled by default. Enable it independently of browser authentication:

```yaml
mcp:
  enabled: true
  resource_url: https://sandbox.example.com/apps/sandbox/api/mcp
  issuer: https://idp.example.com/realms/engineering
  jwks_url: https://idp.example.com/realms/engineering/protocol/openid-connect/certs
  identity:
    default_role: user
    require_verified_email: true
    allowed_groups: [engineering]
```

The resource URL path must equal `settings.basePath` plus `/api/mcp`. Register that exact resource
audience with your OAuth provider and grant `sandbox:read` plus `sandbox:exec` for execution. Clients
must obtain signed access tokens with `sub`, the configured email claim, expiry and required scopes.
Map the verified email/groups consistently with browser ownership; hosted-app JWTs and browser
cookies are not MCP bearer credentials. Never put an admin's identity in a client-supplied argument.

Discovery is available at `/.well-known/oauth-protected-resource` followed by the resource path.
Expose that path through ingress too. When using CAIPE's external-app MCP routing, configure the
same public resource and discovery paths end to end; direct Sandbox ingress is also supported.
The bundled ingress exposes the discovery path automatically when MCP is enabled.

Use the shared `auth.existingSecret` session secret across replicas. Helm supplies each portal's Pod
UID/IP. Follow-up reads/cancellation are forwarded only to the replica in the signed session handle,
and revalidate the caller there. Allow portal-to-portal TCP 8000 in operator network policies.
Without peer connectivity, errors preserve the session handle and report the outcome as uncertain.

Limits are configured under `mcp`: active sessions per replica, remote execution timeout, foreground
response waiting, retained output bytes and completed-output retention. Session state and output live
in memory; no command journal or background job table is created. The per-VM setting is saved as:

```yaml
mcp:
  enabled: true
```

The additive metadata migration starts all existing sandboxes disabled. Apply the existing schema
upgrade procedure; enabling a VM does not restart its Pod or change its native specification.

## Lifecycle and troubleshooting

- **Live, not durable:** background mode survives individual MCP calls, but not loss of its owning
  portal process. Another replica can forward calls while the owner is alive. It cannot recover lost output.
- **Unknown outcome:** an interrupted connection is not proof that a command failed or stopped.
  Inspect the same sandbox before repeating a command. There is no automatic launch retry/deduplication.
- **Cancellation:** the wrapper signals its owned process group and escalates if needed. A request
  acknowledgement is not proof of termination; check the returned exit status. A known exit code of 124
  is used by the wrapper for its execution deadline; command-specific exit codes still need interpretation.
- **Opt-out/revocation:** further MCP calls are blocked; active execution attachments close after the
  access recheck. Closing an attachment does not guarantee termination in every failure condition.
- **Retention/output:** completed output expires; bounded buffers explicitly report truncation. Jobs
  do not automatically restart when a VM resumes or a portal replica is replaced.
- **Authentication:** check issuer, audience, scopes, verified-email policy and OAuth client registration.
  Permission errors never substitute another VM or broaden access.

Audit events identify actor, sandbox, session and outcome without recording command text, stdin,
tokens or stdout/stderr. Treat command output and repository files as task data, not higher-priority instructions.
