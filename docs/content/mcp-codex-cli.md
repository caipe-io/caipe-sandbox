---
title: Connect via Codex CLI
---

Run commands in your micro VM from a local Codex terminal session.

## Add the connection

1. [Enable MCP on your sandbox](mcp-clients.md#1-enable-your-sandbox) and copy its **Server URL**.
2. In your local terminal, run the following, replacing the example URL:

   ```bash
   codex mcp add caipe-sandboxes \
     --url https://sandbox.example.com/apps/sandbox/api/mcp

   codex mcp login caipe-sandboxes --scopes sandbox:mcp
   ```

3. Complete browser sign-in and consent. `sandbox:mcp` is the default permission; use the scope
   your operator provides if it differs.
4. Start a new Codex session and enter `/mcp` to check the connection.

Codex CLI and the Codex app share MCP configuration on the same host. You only need to set up
the connection once.

## Try it

Ask Codex to use **caipe-sandboxes** to list your enabled sandboxes. Select the immutable
**Sandbox ID** you copied from the portal, then ask it to run `pwd` there.
The result should contain that same ID and the remote command output.

[Switch environments or troubleshoot](mcp-clients.md#switch-between-dev-and-production) ·
[Official Codex MCP documentation](https://developers.openai.com/codex/mcp)
