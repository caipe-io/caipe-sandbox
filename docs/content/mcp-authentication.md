---
title: MCP authentication setup
description: Configure an OAuth issuer for standalone or embedded Sandbox MCP access.
---

Sandbox validates OAuth access tokens directly. Its MCP endpoint does not require CAIPE,
Keycloak specifically, or a per-micro-VM authentication server.

For browser sign-in, start with [Authentication & SSO](authentication.md). Provider-specific
instructions cover [Keycloak](authentication-keycloak.md) and [Okta](authentication-okta.md),
including their different agent-registration requirements.

```text
Agent ── sign in and consent ──→ OAuth identity provider
Agent ── access token ─────────→ Sandbox MCP ── permissions ──→ selected micro VM
```

## Choose the deployment

| Operator setup    | Standalone Sandbox                                                           | Embedded in CAIPE                                                     |
| ----------------- | ---------------------------------------------------------------------------- | --------------------------------------------------------------------- |
| Portal sign-in    | Configure Sandbox's OIDC browser client                                      | Register the [CAIPE iframe app](caipe-embedding.md)                   |
| MCP issuer        | An OAuth provider supporting the client connection flow                      | May reuse the Keycloak already deployed with CAIPE, or another issuer |
| MCP configuration | One `sandbox:mcp` scope, Sandbox audience, signing keys and identity mapping | Same                                                                  |
| Public endpoint   | Expose the MCP and discovery paths over HTTPS                                | Same; agents connect directly to Sandbox                              |

MCP and portal sign-in are independent. Use consistent email identities so an engineer sees the
same sandboxes through both. A portal cookie or CAIPE hosted-app JWT does not authorize an agent.

## Provider requirements

- Signed JWT access tokens with the exact Sandbox resource URL in `aud`.
- Issuer discovery and a public JWKS endpoint; authorization code flow with S256 PKCE.
- User consent and the `sandbox:mcp` scope.
- `sub`, `email`, `email_verified`, `iat` and `exp` claims with authoritative identity values.
- A client-identification method supported by both the agent and authorization server:
  pre-registration, Client ID Metadata Documents (CIMD), or optional DCR.

Client identification does not create the Sandbox scope or audience. Those are configured once
by the operator. Providers issuing opaque tokens require a supported JWT configuration;
Sandbox does not currently implement token introspection.

## Choose a client registration method

**DCR is optional.** Authenticated MCP needs an OAuth client identity, not a particular registration
protocol. The [MCP client-registration specification](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/specification/2026-07-28/basic/authorization/client-registration.mdx)
supports these methods:

| Method           | Operator/client setup                                                                               |
| ---------------- | --------------------------------------------------------------------------------------------------- |
| Pre-registration | Approve the OAuth app at the issuer and configure its client ID in an agent that supports it        |
| CIMD             | The agent supplies an HTTPS client-metadata URL; the issuer must support fetching and validating it |
| DCR              | The agent registers through the issuer's registration endpoint, subject to its policy               |

The July 2026 specification recommends CIMD support and keeps DCR for compatibility. Use the
method your actual client and issuer support; a discovery endpoint alone does not guarantee it.
Sandbox validates the resulting access token in every case. It does not host a CIMD validator or
DCR registration endpoint. User consent and S256 PKCE still apply to the chosen OAuth flow.

The user-facing `sandbox:mcp` permission is separate from any provider-specific administration
permission used to register apps. Never give an agent an administrator token to perform registration.

## Keycloak helper

Run the optional helper from a version-matched Sandbox source checkout with Python 3.12 or newer.
It uses only the standard library. No CAIPE application upgrade or deployment hook is required.

The default helper configures the resource scope and audience independently of client registration.
It does not require a DCR endpoint or read/change anonymous registration policies. It checks the
issuer, public signing keys and advertised S256 PKCE support. Configure client registration,
client consent and access policies through your issuer's supported method.

If the admin API is private, add `--admin-url https://keycloak-admin.example.com` or use
`--admin-url http://127.0.0.1:18080` with your existing private port-forward. Supply the Keycloak
base URL, including any deployment prefix such as `/auth`, rather than `/admin/realms/...`.
Discovery and token validation still use the public `--issuer`; the admin API need not be exposed
on the public login hostname. HTTP is permitted only on loopback.

Use a short-lived administrator token permitted to manage the realm's client scopes and default scope
assignments. Read it without placing it in shell history:

```sh
# Paste the token, then press Enter. Input is hidden.
read -r -s KEYCLOAK_ADMIN_TOKEN
export KEYCLOAK_ADMIN_TOKEN

python3 scripts/integrations/keycloak/configure-mcp.py \
  --issuer https://idp.example.com/realms/engineering \
  --resource-url https://sandbox.example.com/apps/sandbox/api/mcp
```

The default is a read-only configuration preview. It lists the proposed changes:

- Create the owned `sandbox:mcp` scope and consent text.
- Add audience, subject, email and actual verified-email mappers to that scope.
- Make it optional for new OAuth clients.

Review the preview, then rerun the command with **`--apply`**. The helper verifies the saved
configuration and prints matching Sandbox Helm values. Copy those into your deployment's values,
then add the [identity restrictions](mcp.md#operator-configuration) appropriate to your organisation.

### Optional DCR policy integration

**Only if you use DCR**, add `--configure-dcr` to the preview command. Review that preview, then
include both `--configure-dcr` and `--apply` to save it. This mode additionally:

- Requires an advertised registration endpoint and existing **Consent Required** and
  **Full Scope Disabled** anonymous registration policies.
- Checks that an existing anonymous scope allow-list permits `openid`, a protocol scope.
- Appends only the Sandbox scope to that existing allow-list, if present; it does not create one.

This opt-in needs permission to read/update the existing registration policy. Configure any other
standard scopes requested by clients, redirect-host restrictions, PKCE policies and registration
limits separately. The helper never enables DCR or loosens those shared settings.

### Re-running and existing clients

```sh
unset KEYCLOAK_ADMIN_TOKEN
```

Alternatively, supply `KEYCLOAK_ADMIN_USERNAME` and `KEYCLOAK_ADMIN_PASSWORD` through your existing
secret-management workflow. `KEYCLOAK_ADMIN_REALM` defaults to `master` for that login method.
Credentials and token responses are not printed. The helper refuses redirects when sending them.

Rerunning is safe: only its owned scope/mappers and optional-scope assignment are managed by default.
Allow-list changes are included only with `--configure-dcr`. Other clients, scopes, shared audience
mappers and registration settings are preserved.
It does not enable unrestricted DCR, repair global policies, upgrade Keycloak, or create a Kubernetes Job.

If an existing scope has the same name but is not owned by this resource, the helper stops.
Use `--scope department-sandbox:mcp` to select a unique name; its output sets both Sandbox scope
settings consistently. A changed resource URL also needs an explicit operator review of the old scope.

Existing agent clients retain their assignments. Attach the scope as optional to intended
pre-registered clients, or use a supported CIMD/DCR flow for new clients.
Removing Helm values does not delete issuer configuration or revoke previously issued tokens.

## Manual configuration or another provider

For Keycloak, create an OIDC client scope with **Include in token scope** and
**Display on consent screen** enabled. Use consent text such as “Access my MCP-enabled sandboxes”.
Add these access-token mappers to that scope:

| Mapper         | Type and settings                                                                   |
| -------------- | ----------------------------------------------------------------------------------- |
| Audience       | **Audience**; Included Custom Audience = the exact public Sandbox MCP URL           |
| Subject        | **Subject (sub)**                                                                   |
| Email          | **User Property**; property `email`, claim `email`, type `String`                   |
| Verified email | **User Property**; property `emailVerified`, claim `email_verified`, type `boolean` |

Add the scope to the realm's **Default client scopes → Optional** list. Assign it to pre-existing
clients separately when needed. Only when using DCR, append the scope to any existing anonymous
**Allowed Client Scopes** registration policy while retaining its other entries and settings.

For another provider, configure the equivalent API/resource audience, consent permission and claims
using its administration tools. Set Sandbox's `mcp.issuer`, `jwks_url`, `resource_url`, `read_scope`
and `execute_scope` to match. No provider-specific code runs inside the MCP server.

## Verify the connection

1. Deploy Sandbox with MCP enabled and the printed issuer configuration.
2. Open the portal through standalone OIDC or CAIPE, create a micro VM and enable MCP in **Actions**.
3. Add its displayed MCP URL to an agent and configure its client ID if pre-registered;
   otherwise use its supported CIMD/DCR connection flow. Complete SSO and consent.
4. Ask the agent to list sandboxes and run `printf hello` in the selected immutable Sandbox ID.
5. Disable MCP for that VM and confirm subsequent calls are denied.

The agent must not see unrelated users' sandboxes. Signing into the portal alone must not authorize
MCP calls. If scope assignments changed, refresh/re-authorize the agent rather than reusing an old token.

| Problem             | Check                                                                                  |
| ------------------- | -------------------------------------------------------------------------------------- |
| Helper HTTP 401/403 | Refresh the operator credential or check its realm permissions, then rerun preview     |
| Interrupted setup   | Rerun preview; a later `--apply` completes owned entries without recreating scopes     |
| Registration denied | Selected method supported by both parties; for DCR, existing host/limit/scope policies |
| Invalid audience    | The token `aud` must include the exact configured public MCP URL                       |
| Identity denied     | Actual email verification, domain/group restrictions and the configured claim names    |

Keep the identity provider on a supported, security-patched version through its own maintenance
process. This helper does not assess or remediate provider vulnerabilities.
