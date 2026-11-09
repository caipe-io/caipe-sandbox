# Connect a private coding sandbox to CAIPE

The portal provisions and manages the environment. CAIPE's existing Harness Engine owns the conversation, run admission, tool policy and replay. Its trusted worker connects through a private non-PTY ACP data plane; no CAIPE provisioning API or worker/database credential is installed in the coding container.

The first coding connection is qualified for direct Agent Sandbox profiles. Existing OpenShell profiles keep their current behavior, but cannot add `acp` until their effective mutable policy is included in the admitted binding and qualified separately. The catalog rejects that unsupported combination and runtime admission also rejects an older unqualified allocation.

## User flow

1. In **Create sandbox**, choose **Claude coding sandbox (experimental)** and a resource size. This creates a private namespace and persistent HOME.
2. Choose **Connect to CAIPE** on its card. Its nonsecret registration reference is available while model setup is pending. The page shows registration status and any conversation already assigned.
3. For this PoC, an operator completes the approved model route/Secret or workload identity in that namespace and registers the connection. Send the reference and your CAIPE identity to that operator. The operator maps the verified CAIPE subject; email is not a substitute. No service credential is pasted into an agent prompt or browser form.
4. Wait for **Running** and a registered connection. A referenced model Secret must exist before the container can start; the card shows provisioning/setup failures.
5. In CAIPE Agent Builder choose **Claude (ACP)** and that sandbox's operator profile. Write instructions and select supported MCP tools. On first use start one new conversation; the first accepted process permanently binds that owner and conversation to the sandbox.
6. Reopen the assigned conversation to continue its native Claude session. Use another private sandbox for another conversation.

Model access for this PoC comes from the approved profile: a scoped model-gateway credential or approved workload identity. Opening a sandbox does not authenticate Claude to a model. Each binding uses a separate native configuration directory; a login made in the terminal's default configuration is not automatically imported. Do not mount general CAIPE, cloud orchestration or database credentials into its HOME.

Selected GitHub MCP tools use the caller's connected CAIPE account through the existing broker. Native `git`/SSH do not inherit those connector or service credentials. They require a separately approved credential helper, user login or scoped provider path appropriate to the profile. The minimal coding image includes Git/SSH, not `gh`; selecting GitHub MCP does not authenticate a native private-repository clone or push.

## Operator setup

Use `examples/claude-acp.values.yaml` with the immutable Claude coding-image digest. The image includes the fixed protected runner and `@agentclientprotocol/claude-agent-acp@0.100.0`. Configure the approved model route and enforced runtime/network policy. The portal's default Agent Sandbox policy allows DNS and public HTTPS while excluding private destination ranges; it is not a named-destination allowlist. OpenShell profiles expose their supported policy panels separately.

After the user creates a sandbox, register its exact UID and current configuration revision:

```yaml
acp:
  existingSecret: sandbox-acp-service
  secretKey: token
  connections:
    primary:
      title: Private coding sandbox
      owner: user@example.test
      owner_subject: verified-caipe-subject
      sandbox_name: example-sandbox
      sandbox_uid: exact-native-uid
      policy_revision: sha256:0000000000000000000000000000000000000000000000000000000000000000
```

The Secret contains a distinct random service credential of at least 32 characters. It is available to the trusted portal and CAIPE worker only. The configuration revision hashes the retained profile and deployment namespace-policy configuration. It identifies approved configuration; it does not attest live enforcement or detect changes made out of band by a cluster administrator. Keep the private data-plane route reachable only from approved services over TLS. Browser cookies and Origin-bearing WebSocket clients are rejected.

Configure the matching connection in CAIPE's admitted worker profile, including the private WebSocket URL, original owner subject, exact UID/configuration revision and workspace root. [The upstream design](https://github.com/caipe-io/ai-platform-engineering/pull/3215) documents the shared gateway and runtime contract. The endpoint is `<portal-base>/api/acp/connections/<alias>/stdio`; it does not grant sandbox create, delete or arbitrary administration.

## What users can manage

| Task | Where and behavior |
| --- | --- |
| Inspect setup | **View/Sync Configuration** shows the retained profile and effective native configuration. |
| Files and native tools | **Open terminal** and profile-owned helpers. Each sandbox's private HOME retains native session/configuration files. Model access is configured by the operator profile. |
| CPU/memory and lifecycle | Existing portal controls; Stop the CAIPE run first. Active or unconfirmed ACP processes block ordinary suspend/resource/policy changes. |
| Filesystem/network policy | Platform operators change approved profiles/runtime/deployment policy; applicable runtime integration panels expose their own supported policy edits. Prompts and MCP approval do not widen these boundaries. |
| Sharing | ACP profiles prohibit shared shell grants. CAIPE transcript sharing does not grant shell ownership. |
| Delete | An explicit portal action. An active or unconfirmed ACP process blocks deletion until its drain is confirmed. Deletion removes native state. CAIPE text history alone cannot recreate it. Deleting history does not prove sandbox files were deleted. |

Reopen a bound conversation from CAIPE history; creating another chat does not move the existing session. A changed admitted configuration revision requires a newly qualified connection/environment for this PoC rather than silently reinterpreting its retained binding. Model-token rotation through the same approved Secret reference does not change that configuration identity.

## Disconnect and recovery

The runner is immutable and starts with isolated Python imports, nondumpable process protection and Linux subreaping. Agent stdout/stderr are separate framed streams. Same-UID tools cannot open the runner's control descriptors through `/proc`; killing the runner still produces an uncertain outcome, never a successful drain receipt.

Cancellation tracks the admitted remote process handle, terminates its process group and reaps adopted descendants, including detached tools. The portal releases the active reservation only for an exact matching run/process receipt with confirmed drain. A closed WebSocket, expired HTTP timeout or missing runner cannot release it or start another prompt automatically.

An active or unconfirmed reservation has no expiry takeover. After transport/portal loss, an operator must reconcile the actual process/environment before recovery; this PoC does not provide automatic live-process adoption. Recreating the sandbox changes its UID and requires a new registered connection/conversation. A normal acknowledged idle restart can continue using the same native files. Include the portal metadata and native persistent volume in the backup/restore plan.

The database migration adds only the retained sandbox/conversation binding and active process fence. It is not another prompt, event or conversation history store.

ACP coding sandboxes require an exclusive namespace. The portal blocks namespace network-policy edits for these sandboxes and does not admit a connection when a mutable policy is already recorded. Operators must still enforce the deployment policy and prevent out-of-band changes.
