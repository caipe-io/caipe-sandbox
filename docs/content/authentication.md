---
title: Authentication & SSO
description: Set up portal sign-in, admission rules and optional agent authentication.
---

Configure authentication at deployment time. Workload profiles do not control portal sign-in.

| Deployment                      | Start here                                                                    |
| ------------------------------- | ----------------------------------------------------------------------------- |
| Standalone portal with Keycloak | [Keycloak setup](authentication-keycloak.md)                                  |
| Standalone portal with Okta     | [Okta setup](authentication-okta.md)                                          |
| Portal inside CAIPE             | [CAIPE embedding](caipe-embedding.md); use its signed hosted-app identity     |
| Agents connecting over MCP      | [MCP authentication](mcp-authentication.md), independently of browser sign-in |
| Another OIDC provider           | Use the requirements and settings below with its administration tools         |

## What signs in where

```text
Browser ── corporate SSO ──→ Sandbox portal session
Agent   ── OAuth consent ─→ Sandbox MCP access token
```

The portal and MCP can share an identity provider, but use separate authentication flows.
Portal sign-in does not authorize an external agent. Neither flow signs tools inside a micro VM
into Claude, Codex or another service.

MCP client identification can use pre-registration, CIMD or optional DCR. See the
[registration-method comparison](mcp-authentication.md#choose-a-client-registration-method)
before enabling an issuer's registration features.

Sandbox enforces its own roles, ownership, namespace sharing and resource controls after sign-in.
Use the same enterprise-controlled email identity across both flows: email identifies sandbox owners.

## 1. Choose the public URL

For these guides, the portal is `https://sandbox.example.com/apps/sandbox/`:

| Setting                                  | Value                                                    |
| ---------------------------------------- | -------------------------------------------------------- |
| `settings.origin`                        | `https://sandbox.example.com`                            |
| `settings.basePath`                      | `/apps/sandbox`                                          |
| OIDC callback registered at the provider | `https://sandbox.example.com/apps/sandbox/auth/callback` |

For a dedicated root deployment, use `basePath: ""` and callback
`https://sandbox.example.com/auth/callback`. Register the exact callback; avoid wildcard redirects.
The browser and portal must reach the HTTPS issuer. The portal also needs discovery, token and
signing-key access; UserInfo access is needed when configured.

## 2. Register the portal and provide its Secret

For standalone SSO, register a confidential **OIDC web application** using authorization code flow
and S256 PKCE. Sandbox discovers endpoints from `ISSUER/.well-known/openid-configuration`.
The issuer must match the discovery response exactly.

Prepare a private `oidc-client-secret` file with the provider-issued client secret. Generate a
separate session-signing key and create a Secret through your normal secret-management process:

```sh
umask 077
openssl rand -hex 32 | tr -d '\n' > session-secret
kubectl -n sandbox-system create secret generic sandbox-auth \
  --from-file=client-secret=./oidc-client-secret \
  --from-file=session-secret=./session-secret
```

Keep these files outside source control and remove local copies after secure delivery. Replicas of
one portal share its session key. The CAIPE adapter uses a separate hosted-app verification key;
see its guide rather than creating a standalone OIDC browser client for that mode.

## 3. Set identity and admission rules

The provider guides include complete authentication overlays. These settings apply to standalone OIDC:

| Value                                    | Purpose                                                                        |
| ---------------------------------------- | ------------------------------------------------------------------------------ |
| `auth.mode: oidc`                        | Use the provider directly for portal sign-in                                   |
| `auth.existingSecret`                    | Secret containing `client-secret` and `session-secret`                         |
| `auth.oidc.issuer`, `client_id`          | The trusted issuer and portal's web client                                     |
| `auth.oidc.scopes`                       | Start with `openid email profile`; request group claims if using group policy  |
| `auth.oidc.require_verified_email: true` | Require a Boolean `email_verified: true`                                       |
| `auth.oidc.use_userinfo`                 | Supplement identity claims from UserInfo, bound to the same subject            |
| `auth.oidc.allowed_email_domains`        | Limit the accepted enterprise email domains                                    |
| `auth.oidc.allowed_groups`               | Optionally require membership in an admitted group                             |
| `auth.oidc.default_role` / `role_groups` | Explicitly grant `user` or `viewer`; otherwise sign-in is denied               |
| `auth.adminEmails`                       | Operator-managed administrator list; identity and admission checks still apply |
| `auth.oidc.session_seconds`              | Portal session lifetime; defaults to 3,600 seconds                             |

Identity claims must include `sub` and the configured email field. Group claims, when used, must
be arrays of strings. Configure mappings with the provider and select matching `email_claim` and
`groups_claim` names in Sandbox. Treat email changes as an ownership change to plan explicitly.

For a smaller pilot, emit only relevant groups and use a policy such as:

```yaml
auth:
  oidc:
    groups_claim: groups
    allowed_groups: [sandbox-engineers, sandbox-observers]
    default_role: ""
    role_groups:
      user: [sandbox-engineers]
      viewer: [sandbox-observers]
```

SSO groups do not grant the Sandbox administrator role. Signing out clears the portal session;
it does not guarantee logout from the identity provider or immediate revocation of every issued token.

## 4. Verify before admitting users

1. Sign in as an assigned engineer; confirm the expected role and owner email.
2. Try an unassigned or disallowed identity; confirm access is rejected.
3. Confirm only the intended `auth.adminEmails` receive Sandbox administration.
4. Open a terminal through the real ingress and test logout/session expiry.

If enabling MCP, validate it separately with the [MCP connection checks](mcp-authentication.md#verify-the-connection).
MCP validates JWT access tokens directly; it does not use the browser's UserInfo option.

| Symptom                                       | Check                                                                                  |
| --------------------------------------------- | -------------------------------------------------------------------------------------- |
| Redirect mismatch                             | Public origin, base path and provider callback are identical                           |
| Discovery mismatch                            | Use the issuer value itself, not its discovery URL; avoid trailing-slash differences   |
| Missing/invalid identity                      | ID token or configured UserInfo supplies subject, email and authoritative verification |
| Sign-in succeeds at IdP but Sandbox denies it | Domain/group admission and explicit role mappings                                      |
| Sessions break across replicas                | Shared session key, HTTPS cookies and consistent external origin                       |
