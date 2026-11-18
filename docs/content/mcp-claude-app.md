---
title: Connect via Claude App
---

Connect from Claude desktop or the web interface, without a CLI.

## Add the connection

1. [Enable MCP on your sandbox](mcp-clients.md#1-enable-your-sandbox) and copy its **Server URL**.
2. Open **Customize → Connectors → Add custom connector**.
3. Name it **caipe-sandboxes** and paste the copied URL.
4. Choose OAuth sign-in. If asked about client registration, choose **Register automatically** when
   your operator supports DCR; otherwise use the registered client details they provide.
5. Complete sign-in and consent, then enable the connector from **+ → Connectors** in your chat.

Managed team accounts may need an organisation administrator to add the connector first.
Remote connectors run from Anthropic's servers, including when using Claude desktop, so the
endpoint must be reachable from there.

## Try it

Send this prompt to Claude:

```text
Can you list all the CAIPE sandboxes?
```

Claude should use **caipe-sandboxes** to list the MCP-enabled sandboxes you can access.
Give it the immutable
**Sandbox ID** copied from the portal, then ask it to run `pwd` there and check the returned ID.

[Switch environments or troubleshoot](mcp-clients.md#switch-between-dev-and-production) ·
[Official Claude connector setup](https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp)
