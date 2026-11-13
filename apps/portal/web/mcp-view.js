import {icon} from "./icons.js";

const esc = value => String(value ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));

export function mcpAction(row, configuration, allowed, attributes = "") {
  if (!allowed || !row?.portal_id || (!configuration?.enabled && !row.mcp?.enabled)) return "";
  return `<button class="secondary" type="button" data-action="mcp" data-id="${esc(row.id)}" ${attributes}>${icon("terminal")}${row.mcp?.enabled ? "Disable MCP" : "Enable MCP"}</button>`;
}

export function mcpDialogContent(row, configuration, enabled) {
  const docs = configuration.docs_url ? `<p><a href="${esc(configuration.docs_url)}" target="_blank" rel="noopener noreferrer">Connect your agent with MCP ${icon("external-link")}</a></p>` : "";
  return `<div class="dialog-top"><h2>${enabled ? "Disable" : "Enable"} MCP</h2><button class="icon-button close-button" type="button" data-mcp-close aria-label="Close MCP settings">${icon("close")}</button></div>
    <p><strong>${esc(row.title)}</strong></p><p>${enabled ? "Disable further MCP access to this micro VM. Active attachments will end; a disconnected command is not guaranteed to have stopped." : "Allow authenticated agents to discover this micro VM and run shell commands, including reading and changing files. Existing ownership, sharing and security policies still apply."}</p>
    <label>Sandbox ID<input readonly data-mcp-id value="${esc(row.portal_id)}"></label>
    <label>MCP server URL<input readonly data-mcp-url value="${esc(configuration.resource_url)}"></label>
    <p class="hint">Remember this exact Sandbox ID in your agent. The server can expose several enabled sandboxes; sign-in and shell access are required.</p>${docs}
    <p role="alert" data-mcp-error hidden></p><div class="dialog-actions"><button class="secondary" type="button" data-mcp-close>Cancel</button><button class="${enabled ? "warning" : ""}" type="button" data-mcp-confirm>${enabled ? "Disable" : "Enable"} MCP</button></div>`;
}

export function openMCP(dialog, row, configuration, save, refresh) {
  const enabled = !!row.mcp?.enabled;
  dialog.innerHTML = mcpDialogContent(row, configuration, enabled);
  for (const button of dialog.querySelectorAll("[data-mcp-close]")) button.onclick = () => dialog.close();
  dialog.querySelector("[data-mcp-confirm]").onclick = async event => {
    const button = event.currentTarget;
    button.disabled = true;
    const error = dialog.querySelector("[data-mcp-error]");
    error.hidden = true;
    try {
      const result = await save({revision: row.revision, mcp: {enabled: !enabled}});
      row.mcp = result.mcp; row.revision = result.revision;
      const heading = dialog.querySelector("h2");
      heading.textContent = result.mcp.enabled ? "MCP enabled" : "MCP disabled";
      button.remove();
      const close = dialog.querySelector(".dialog-actions [data-mcp-close]");
      close.textContent = "Done";
      for (const [name, label] of [["id", "Copy sandbox ID"], ["url", "Copy server URL"]]) {
        const input = dialog.querySelector(`[data-mcp-${name}]`);
        const copy = document.createElement("button"); copy.type = "button"; copy.className = "secondary"; copy.textContent = label;
        copy.onclick = async () => { try { await navigator.clipboard.writeText(input.value); copy.textContent = "Copied"; } catch { input.focus(); input.select(); } };
        input.after(copy);
      }
      try { await refresh(); } catch {
        error.textContent = "The MCP setting was saved. Refresh the sandbox list to see its latest status.";
        error.hidden = false;
      }
    } catch (err) {
      error.textContent = err.message + " Refresh the sandbox before trying again.";
      error.hidden = false; button.disabled = false;
    }
  };
  dialog.showModal();
}
