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
- Dynamic client registration (DCR) for clients that connect using only the MCP URL.
  Without DCR, pre-register the agent client if that client supports supplying its own registration.

DCR creates agent clients; it does not create the Sandbox scope or audience. Those are configured
once by the operator. Providers issuing opaque tokens require a supported JWT configuration;
Sandbox does not currently implement token introspection.

## Keycloak helper

Run the optional helper from a version-matched Sandbox source checkout with Python 3.12 or newer.
It uses only the standard library. No CAIPE application upgrade or deployment hook is required.

The realm must already allow the intended DCR flow, with **Consent Required** and
**Full Scope Disabled** anonymous registration policies. If its anonymous **Allowed Client Scopes**
policy exists, explicitly allow `openid` and any other standard scopes requested by your clients
(such as `email`, `profile` and `offline_access`). `openid` is a protocol scope, not another Sandbox permission. Its host restrictions, PKCE policies,
client limits and existing applications remain operator-managed. Discovery support alone does not
prove that a particular agent's redirect URI is permitted.

Use a short-lived administrator token permitted to manage the realm's client scopes, default scope
assignments and existing registration policy. Read it without placing it in shell history:

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
- Make it optional for newly registered clients.
- Append only its name to an existing anonymous scope allow-list, if one exists.

Review the preview, then rerun the command with **`--apply`**. The helper verifies the saved
configuration and prints matching Sandbox Helm values. Copy those into your deployment's values,
then add the [identity restrictions](mcp.md#operator-configuration) appropriate to your organisation.

```sh
unset KEYCLOAK_ADMIN_TOKEN
```

Alternatively, supply `KEYCLOAK_ADMIN_USERNAME` and `KEYCLOAK_ADMIN_PASSWORD` through your existing
secret-management workflow. `KEYCLOAK_ADMIN_REALM` defaults to `master` for that login method.
Credentials and token responses are not printed. The helper refuses redirects when sending them.

Rerunning is safe: only its owned scope/mappers and that scope's optional/allow-list entries are
managed. Other clients, scopes, shared audience mappers and registration settings are preserved.
It does not enable unrestricted DCR, repair global policies, upgrade Keycloak, or create a Kubernetes Job.

If an existing scope has the same name but is not owned by this resource, the helper stops.
Use `--scope department-sandbox:mcp` to select a unique name; its output sets both Sandbox scope
settings consistently. A changed resource URL also needs an explicit operator review of the old scope.

Existing agent clients retain their assignments. After setup, create a fresh client registration,
or attach the scope as optional to the intended existing client through Keycloak administration.
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

Add the scope to the realm's **Default client scopes → Optional** list. If an anonymous
**Allowed Client Scopes** registration policy exists, append the scope while retaining its existing
entries and settings. Assign it to pre-existing clients separately when needed.

For another provider, configure the equivalent API/resource audience, consent permission and claims
using its administration tools. Set Sandbox's `mcp.issuer`, `jwks_url`, `resource_url`, `read_scope`
and `execute_scope` to match. No provider-specific code runs inside the MCP server.

## Verify the connection

1. Deploy Sandbox with MCP enabled and the printed issuer configuration.
2. Open the portal through standalone OIDC or CAIPE, create a micro VM and enable MCP in **Actions**.
3. Add its displayed MCP URL to an agent, then complete SSO and consent.
4. Ask the agent to list sandboxes and run `printf hello` in the selected immutable Sandbox ID.
5. Disable MCP for that VM and confirm subsequent calls are denied.

The agent must not see unrelated users' sandboxes. Signing into the portal alone must not authorize
MCP calls. If scope assignments changed, refresh/re-authorize the agent rather than reusing an old token.

| Problem             | Check                                                                               |
| ------------------- | ----------------------------------------------------------------------------------- |
| Helper HTTP 401/403 | Refresh the operator credential or check its realm permissions, then rerun preview  |
| Interrupted setup   | Rerun preview; a later `--apply` completes owned entries without recreating scopes  |
| Registration denied | Existing redirect-host restrictions, registration limits and allowed client scopes  |
| Invalid audience    | The token `aud` must include the exact configured public MCP URL                    |
| Identity denied     | Actual email verification, domain/group restrictions and the configured claim names |

Keep the identity provider on a supported, security-patched version through its own maintenance
process. This helper does not assess or remediate provider vulnerabilities.
