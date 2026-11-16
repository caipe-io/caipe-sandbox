---
title: Keycloak
description: Configure Keycloak SSO and optional Sandbox MCP authorization.
---

Use an existing operator-managed Keycloak realm. Keycloak is not required to run with CAIPE;
Sandbox consumes its OIDC endpoints directly.

## Register the portal web client

Follow [common SSO preparation](authentication.md#1-choose-the-public-url), then create an
**OpenID Connect** client in the intended realm:

| Client setting                          | Example                                                  |
| --------------------------------------- | -------------------------------------------------------- |
| Client ID                               | `sandbox-portal`                                         |
| Client authentication                   | On; store the issued client secret in `sandbox-auth`     |
| Standard flow                           | On                                                       |
| Direct access grants / service accounts | Off for this browser client                              |
| Valid redirect URI                      | `https://sandbox.example.com/apps/sandbox/auth/callback` |
| Web origin                              | `https://sandbox.example.com`                            |
| PKCE method                             | Require `S256`                                           |

Allow the `openid`, `email` and `profile` scopes. Supply an authoritative email and verification
status. Local users can verify through the realm's email-verification flow. For federated users,
configure the upstream identity mapping and verification policy rather than asserting verification
for every account.

Keycloak documents [OIDC discovery and endpoints](https://www.keycloak.org/securing-apps/oidc-layers)
and [client administration](https://www.keycloak.org/docs/latest/server_admin/index.html).

## Configure Sandbox

Merge this authentication overlay with your normal runtime, storage and ingress values:

```yaml
settings:
  origin: https://sandbox.example.com
  basePath: /apps/sandbox
auth:
  mode: oidc
  existingSecret: sandbox-auth
  adminEmails: [operator@example.com]
  oidc:
    issuer: https://idp.example.com/realms/engineering
    client_id: sandbox-portal
    scopes: openid email profile
    require_verified_email: true
    allowed_email_domains: [example.com]
    default_role: user
```

The issuer is the realm URL, not the admin console or discovery-document URL. The associated
discovery document is at `/realms/engineering/.well-known/openid-configuration`.

For group-based admission, add a **Group Membership** mapper to the portal client or its client
scope. Emit a `groups` array in the ID token (or UserInfo when `use_userinfo: true`) and match the
exact values in Sandbox's [group policy](authentication.md#3-set-identity-and-admission-rules).
If Keycloak emits full paths such as `/sandbox-engineers`, include those paths in the policy too.

## Use corporate SSO behind Keycloak

Keycloak can broker an upstream OIDC or SAML identity provider while Sandbox continues to use the
same Keycloak realm issuer:

1. Add the upstream provider under the realm's **Identity providers** settings.
2. Register the broker callback displayed by Keycloak with that provider.
3. Map enterprise-controlled email and the required groups; configure account linking deliberately.
4. Test an ordinary user's first and subsequent sign-ins, including verification and group restrictions.

See Keycloak's [identity brokering documentation](https://www.keycloak.org/docs/latest/server_admin/index.html#_identity_broker).
Configure this at the issuer; no broker code is needed inside Sandbox.

## Enable MCP separately

The portal's confidential browser client is not an external agent client. Use the
[Keycloak MCP helper](mcp-authentication.md#keycloak-helper) to configure `sandbox:mcp`, its audience
and token claims. Agent clients then use the realm's approved OAuth registration/consent flow.

Keep the same canonical owner email across browser and MCP identities. Finish the
[portal checks](authentication.md#4-verify-before-admitting-users) and
[MCP checks](mcp-authentication.md#verify-the-connection) independently.
