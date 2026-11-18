---
title: Connect via Codex App
---

Add the remote MCP connection directly in the Codex desktop app.

## Add the connection

1. [Enable MCP on your sandbox](mcp-clients.md#1-enable-your-sandbox) and copy its **Server URL**.
2. Open **Settings** and find **MCP servers** or **Integrations and MCP**.
3. Add a server named **caipe-sandboxes**, choose **Streamable HTTP**, and paste the copied URL.
4. Save and authenticate. Complete browser sign-in and consent.
5. Start a new chat to use the connection.

Codex app and CLI share MCP configuration on the same host. If you already added this connection
through the CLI, use that existing entry.

## Try it

Ask the agent to use **caipe-sandboxes** to list your enabled sandboxes. Give it your immutable
**Sandbox ID** and ask it to run `pwd` there. Check that its result includes that same ID.

[Switch environments or troubleshoot](mcp-clients.md#switch-between-dev-and-production) ·
[Official Codex app settings](https://learn.chatgpt.com/docs/developer-settings#integrations-and-mcp)
