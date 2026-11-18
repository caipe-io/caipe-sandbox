---
title: Connect your agent
---

Connect an MCP client to run commands in a remote micro VM. Enable your sandbox, then follow
the guide for your client below.
One connection can discover all MCP-enabled sandboxes you have shell permission to use.

## 1. Enable your sandbox

1. In the portal, choose **Actions → Enable MCP** on your sandbox and confirm.
2. Select **MCP Enabled** below its resource stats. Copy the **Server URL** and **Sandbox ID**.
   Use the MCP URL, not the portal page URL.
   The connection works whether you open the portal directly or inside CAIPE.

![MCP access dialog showing the Sandbox ID, Server URL and copy buttons](../static/img/mcp-access.jpg)

_Example with sample data and a local preview URL. Copy the values from your own portal._

Your operator must first enable MCP and [configure OAuth](mcp-authentication.md).
You sign in with your own account; there is no need to copy a browser cookie or bearer token.

## 2. Choose your client

| Client                    | Setup guide                                   |
| ------------------------- | --------------------------------------------- |
| Codex in a terminal       | [Connect via Codex CLI](mcp-codex-cli.md)     |
| Claude Code in a terminal | [Connect via Claude CLI](mcp-claude-cli.md)   |
| ChatGPT                   | [Connect via ChatGPT App](mcp-chatgpt-app.md) |
| Codex desktop             | [Connect via Codex App](mcp-codex-app.md)     |
| Claude desktop or web     | [Connect via Claude App](mcp-claude-app.md)   |

Name the connection **`caipe-sandboxes`** so its tool family is easy to recognise.
Clients choose their own tool prefixes and may normalise hyphens. Existing saved connections
keep their client-side names until you rename or re-add them and reconnect.

## 3. Verify the connection

Send this prompt to your agent:

```text
Can you list all the CAIPE sandboxes?
```

The agent should use **caipe-sandboxes** to list the MCP-enabled sandboxes you can access.
An empty list is valid if none are enabled for your account.

To also check remote execution, use the following prompt with your copied **Sandbox ID**:

```text
Use only the caipe-sandboxes MCP connection to list my enabled sandboxes.
Select sandbox_id <paste Sandbox ID here>.
Remember this immutable ID and include it in every sandbox tool call.
Run pwd and uname -a there. Show stdout, stderr and the exit code.
```

The result should contain your sandbox's ID and remote command output. Display names can change;
keep using the immutable ID. For longer commands, ask the agent to run in the background and poll
the returned session ID. See the [available tools](mcp.md#tools).

## Switch between dev and production

Keep two connections instead of changing the URL on an authenticated connection:

| Connection             | Server URL                                    |
| ---------------------- | --------------------------------------------- |
| `caipe-sandboxes-dev`  | Copy from the dev portal's MCP dialog.        |
| `caipe-sandboxes-prod` | Copy from the production portal's MCP dialog. |

Use these distinct names when connecting to both environments. Repeat the client setup for
`caipe-sandboxes-prod` and sign in separately. Enable MCP on the production VM, then select only
that connection or disable `caipe-sandboxes-dev` in your client's MCP settings.
Start a new chat and ask it to use only `caipe-sandboxes-prod`, listing sandboxes before running commands.

Use the ID from the selected environment. Switching connections does not move a VM or its files;
dev credentials are not production credentials. Each deployment needs its own
[operator MCP/OAuth setup](mcp-authentication.md).

## If something is missing

| Symptom                     | Check                                                                                                                                      |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| No sandboxes listed         | Enable MCP on the VM and sign in with the account that has shell access.                                                                   |
| Sign-in or permission error | Authenticate again. Ask your operator to check the OAuth scope, audience and client registration. DCR is one optional registration method. |
| Tools do not appear         | Check `/mcp`, the copied Server URL and that you started a new session after setup.                                                        |
| A command disconnects       | Inspect the same sandbox before repeating it: disconnection does not prove the command stopped.                                            |

To stop MCP access to a VM, select its **MCP Enabled** badge and choose **Disable MCP**.
This blocks further MCP calls to that sandbox from all clients.
