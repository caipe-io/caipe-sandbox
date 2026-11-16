---
title: Okta
description: Configure Okta portal SSO, token claims and optional MCP client access.
---

| Use case          | Okta configuration                                                          |
| ----------------- | --------------------------------------------------------------------------- |
| Portal SSO        | An OIDC web application; an org or custom authorization-server issuer       |
| Direct MCP access | A custom authorization server with Sandbox's audience, scope and JWT claims |
| Agent onboarding  | An approved OAuth client the agent supports; do not assume anonymous DCR    |

These are configuration instructions checked against Okta's documentation. Validate them in your
tenant before rollout; no live Okta tenant has been tested for this guide.

## 1. Register the portal for SSO

In Okta's application administration, create an **OIDC Web Application** for the standalone portal:

- Use authorization code flow and client-secret authentication compatible with `client_secret_basic`.
- Register `https://sandbox.example.com/apps/sandbox/auth/callback` as the sign-in callback.
- Assign only the intended users/groups to the application.
- Deliver its client secret through the [shared Secret setup](authentication.md#2-register-the-portal-and-provide-its-secret).

Merge this with your normal Sandbox values; replace the illustrative domain and client ID:

```yaml
settings:
  origin: https://sandbox.example.com
  basePath: /apps/sandbox
auth:
  mode: oidc
  existingSecret: sandbox-auth
  adminEmails: [operator@example.com]
  oidc:
    issuer: https://login.example.com
    client_id: YOUR_OKTA_WEB_CLIENT_ID
    scopes: openid email profile
    use_userinfo: true
    require_verified_email: true
    allowed_email_domains: [example.com]
    default_role: user
```

`use_userinfo` supplements verified ID-token claims using the same user's UserInfo response;
it does not turn an ID token into an MCP access token. Confirm the returned email is enterprise-controlled
and its verification status meets your organisation's identity policy.
For group restrictions, configure an appropriate group claim and the matching
[Sandbox admission rules](authentication.md#3-set-identity-and-admission-rules).

See Okta's [web-app redirect setup](https://developer.okta.com/docs/guides/sign-into-web-app-redirect/main/)
and [email verification claim notes](https://support.okta.com/help/s/article/how-to-return-the-email-verified-claim?language=en_US).

## 2. Prepare a custom authorization server for MCP

The org authorization server's access tokens are for Okta's own APIs. Use a **custom authorization
server** for Sandbox MCP. Okta requires API Access Management for custom authorization servers
in production; confirm your tenant's entitlement. See [authorization-server types](https://developer.okta.com/docs/concepts/auth-servers/).

Under **Security → API**, create or select a suitable server:

| Setting       | Value                                                                         |
| ------------- | ----------------------------------------------------------------------------- |
| Audience      | Exact public MCP URL, e.g. `https://sandbox.example.com/apps/sandbox/api/mcp` |
| Scope         | `sandbox:mcp`, requiring user consent; expose it in metadata                  |
| Access policy | Approved agent clients and assigned users/groups                              |
| Grant types   | Authorization code with S256 PKCE; refresh tokens if needed                   |

Use a dedicated server when changing a shared server's audience would affect existing APIs.
The issuer includes its server ID, for example `https://login.example.com/oauth2/ausSandbox`;
replace `ausSandbox` with your real ID. Obtain its `jwks_uri` from issuer discovery.

See Okta's [custom-server configuration](https://developer.okta.com/docs/guides/customize-authz-server/main/)
and [consent configuration](https://developer.okta.com/docs/guides/request-user-consent/main/).

## 3. Include the access-token claims Sandbox reads

On that custom server's **Claims** tab, add access-token claims limited to the `sandbox:mcp` scope:

| Claim                  | Expression or source                                                              |
| ---------------------- | --------------------------------------------------------------------------------- |
| `scope`                | `String.replace(Arrays.toCsvString(access.scope),","," ")`                        |
| `email`                | `user.email`, provided this is the enterprise-controlled owner identity           |
| `email_verified`       | An authoritative Boolean verification attribute, e.g. `user.sandboxEmailVerified` |
| `client_id` (optional) | `app.clientId`, for client-level audit correlation                                |

Okta normally emits granted scopes as an `scp` array. Sandbox currently reads the standard
space-delimited `scope` string; the expression above is Okta's documented conversion. Configure
it as an **access-token** claim, not an ID-token claim.
See [Okta's scope expression](https://developer.okta.com/docs/reference/okta-expression-language/#accessscope-samples).

`sandboxEmailVerified` is an **example custom attribute**, not a built-in Okta field. An identity
administrator must create/map it from a trusted source and restrict who can change it. Do not
map verification to constant `true` or disable Sandbox verification to make a test pass.
An ID-token/UserInfo `email_verified` claim does not automatically appear in the access token.
If your tenant cannot issue the required authoritative access-token identity claims, use an
existing compatible issuer/broker rather than treating this direct connection as ready.

Custom claims are described in [Okta's token customization guide](https://developer.okta.com/docs/guides/customize-tokens-returned-from-okta/main/).
Group-based MCP restrictions additionally need the configured groups claim as an array of strings.

## 4. Choose the agent's client registration method

MCP does not require DCR. The following uses a pre-registered client; CIMD is another option only
when your actual authorization server and agent support it. See the
[registration-method comparison](mcp-authentication.md#choose-a-client-registration-method).

For a CLI/native agent, create a **Native OIDC Application** using authorization code + S256 and
client authentication **None**. Enable refresh tokens when needed. Use the agent's actual callback
URI and provide its client ID through that agent's supported OAuth settings. Hosted agent clients
may need a web/confidential registration instead; follow that client's requirements.
Ensure both the scope and the app require user consent (`consent_method: REQUIRED`).
See [PKCE client setup](https://developer.okta.com/docs/guides/implement-grant-type/authcodepkce/main/).

Okta's DCR endpoint requires authorized registration (`okta.clients.register`); it is not anonymous
registration merely because discovery lists an endpoint. Never give an agent an Okta administration
token to get past registration. A client requiring anonymous DCR cannot use that protected API
directly. Use a compatible pre-registered/CIMD client flow or an operator-provided registration
broker if necessary; this guide does not install one.
See the [registration API](https://developer.okta.com/docs/api/openapi/okta-oauth/oauth/client/createclient).

## 5. Configure and verify Sandbox MCP

```yaml
mcp:
  enabled: true
  resource_url: https://sandbox.example.com/apps/sandbox/api/mcp
  issuer: https://login.example.com/oauth2/ausSandbox
  jwks_url: https://login.example.com/oauth2/ausSandbox/v1/keys
  read_scope: sandbox:mcp
  execute_scope: sandbox:mcp
  identity:
    default_role: user
    require_verified_email: true
    allowed_email_domains: [example.com]
```

The portal's base path must match the resource URL. This MCP issuer may differ from the browser
issuer. An agent should request `sandbox:mcp` and, when configured for refresh, `offline_access`.
Use access tokens from the custom server; ID tokens have a different audience and are rejected.

Complete the [portal SSO checks](authentication.md#4-verify-before-admitting-users) and
[MCP connection checks](mcp-authentication.md#verify-the-connection). Before accepting the setup,
confirm the token's exact issuer/audience, granted `scope` string, Boolean verification claim and
owner email locally. Keep tokens out of shared logs and external token-inspection sites.
