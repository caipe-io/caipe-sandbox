---
title: Connect via Claude CLI
---

Use the Claude Code CLI on your computer to run commands in a remote micro VM.

## Add the connection

1. [Enable MCP on your sandbox](mcp-clients.md#1-enable-your-sandbox) and copy its **Server URL**.
2. In your local terminal, replace the example URL and run:

   ```bash
   claude mcp add --transport http --scope user caipe-sandboxes \
     https://sandbox.example.com/apps/sandbox/api/mcp
   ```

3. Start Claude Code and enter `/mcp`.
4. Select **caipe-sandboxes → Authenticate**, then complete browser sign-in and consent.

`--scope user` makes the connection available across your local projects. It does not share
the connection with other users.

## Try it

Ask Claude to use **caipe-sandboxes** to list your enabled sandboxes. Give it the immutable
**Sandbox ID** copied from the portal and ask it to run `pwd` there. Check that the returned ID
matches your chosen VM.

[Switch environments or troubleshoot](mcp-clients.md#switch-between-dev-and-production) ·
[Official Claude Code MCP documentation](https://code.claude.com/docs/en/mcp#authenticate-with-remote-mcp-servers)
