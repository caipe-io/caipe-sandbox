---
title: Connect via ChatGPT App
---

Connect ChatGPT through a custom MCP plugin, without installing a CLI.
Account and workspace permissions determine whether you can add custom MCP servers.

## Add the connection

1. [Enable MCP on your sandbox](mcp-clients.md#1-enable-your-sandbox) and copy its **Server URL**.
2. Open [ChatGPT Plugins](https://chatgpt.com/plugins) with the account you use in the app.
3. Select **+ → Add custom MCP server** and name it **caipe-sandboxes**.
4. Enter the copied HTTPS URL under **Connection**, including its full path, and select OAuth
   authentication.
5. Review the permissions and confirmation, choose **Create as a plugin**, and review the tools.
6. Install and connect the plugin, completing sign-in and consent when prompted.

If custom MCP setup is unavailable, ask your workspace administrator about its plugin permissions.
The service must be reachable from ChatGPT's servers; your laptop's VPN connection alone does
not make a private endpoint reachable to ChatGPT.

## Try it

Start a new chat, type **@** and select **caipe-sandboxes**. Ask it to list your enabled sandboxes,
then run `pwd` using the immutable **Sandbox ID** copied from the portal. Check the ID in its result.

[Switch environments or troubleshoot](mcp-clients.md#switch-between-dev-and-production) ·
[Official ChatGPT custom MCP setup](https://developers.openai.com/plugins/deploy/connect-chatgpt#add-the-mcp-server)
