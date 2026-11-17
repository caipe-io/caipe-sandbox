---
title: Connect Codex & Claude Code
---

Use Codex or Claude Code on your computer to run commands in a remote micro VM through MCP.
One connection can discover all MCP-enabled sandboxes you have shell permission to use.

## 1. Enable your sandbox

1. In the portal, choose **Actions → Enable MCP** on your sandbox and confirm.
2. Select **MCP Enabled** below its resource stats. Copy the **Server URL** and **Sandbox ID**.
3. In your local terminal, set the URL you copied:

   ```bash
   export SANDBOX_MCP_URL='https://sandbox.example.com/apps/sandbox/api/mcp'
   ```

Replace the example URL with your deployment's value. Use the MCP URL, not the portal page URL.
The connection works whether you open the portal directly or inside CAIPE.

Your operator must first enable MCP and [configure OAuth](mcp-authentication.md).
You sign in with your own account; there is no need to copy a browser cookie or bearer token.

## 2. Connect your client

### Codex

Run these commands in your local terminal:

```bash
codex mcp add sandbox --url "$SANDBOX_MCP_URL"
codex mcp login sandbox --scopes sandbox:mcp
```

Complete the browser sign-in and consent prompts. `sandbox:mcp` is the default permission;
use the scope your operator provides if it differs.

Start a new Codex session and enter `/mcp` to check the connection. Codex CLI and the desktop
app share MCP configuration on the same host; start a new chat in the app after setup.

[Official Codex MCP documentation](https://developers.openai.com/codex/mcp)

### Claude Code

Run this in your local terminal:

```bash
claude mcp add --transport http --scope user sandbox "$SANDBOX_MCP_URL"
```

Then start Claude Code:

1. Enter `/mcp`.
2. Select **sandbox**, then **Authenticate**.
3. Complete the browser sign-in and consent prompts.

`--scope user` makes this connection available across your local projects; it does not share it
with other users.

[Official Claude Code MCP documentation](https://code.claude.com/docs/en/mcp#authenticate-with-remote-mcp-servers)

## 3. Try a command

Paste this into your agent, replacing the placeholder with the **Sandbox ID** you copied:

```text
Use the Sandbox MCP tools to list my enabled sandboxes.
Select sandbox_id <paste Sandbox ID here>.
Remember this immutable ID and include it in every sandbox tool call.
Run pwd and uname -a there. Show stdout, stderr and the exit code.
```

The result should contain your sandbox's ID and remote command output. Display names can change;
keep using the immutable ID. For longer commands, ask the agent to run in the background and poll
the returned session ID. See the [available tools](mcp.md#tools).

## If something is missing

| Symptom                     | Check                                                                                                                                      |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| No sandboxes listed         | Enable MCP on the VM and sign in with the account that has shell access.                                                                   |
| Sign-in or permission error | Authenticate again. Ask your operator to check the OAuth scope, audience and client registration. DCR is one optional registration method. |
| Tools do not appear         | Check `/mcp`, the copied Server URL and that you started a new session after setup.                                                        |
| A command disconnects       | Inspect the same sandbox before repeating it: disconnection does not prove the command stopped.                                            |

To stop MCP access to a VM, select its **MCP Enabled** badge and choose **Disable MCP**.
This blocks further MCP calls to that sandbox from all clients.
