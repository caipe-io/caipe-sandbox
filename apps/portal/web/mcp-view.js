import {icon} from "./icons.js";

const esc = value => String(value ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));

export function mcpAction(row, configuration, allowed, attributes = "") {
  if (!allowed || !row?.portal_id || (!configuration?.enabled && !row.mcp?.enabled)) return "";
  return `<button class="secondary" type="button" data-action="mcp" data-id="${esc(row.id)}" ${attributes}>${icon("terminal")}${row.mcp?.enabled ? "Disable MCP" : "Enable MCP"}</button>`;
}

export function mcpEnabledRow(row, configuration) {
  if (!configuration?.enabled || !row?.portal_id || !row.mcp?.enabled) return "";
  return `<div class="machine-feature-row"><button class="mcp-enabled-badge" type="button" data-action="mcp" data-id="${esc(row.id)}" aria-haspopup="dialog" title="View MCP connection details. Sign-in and existing shell permissions are required.">MCP Enabled</button></div>`;
}

export function mcpDialogContent(row, configuration, enabled, canManage = true) {
  const docs = configuration.docs_url ? `<a class="mcp-docs-link" href="${esc(configuration.docs_url)}" target="_blank" rel="noopener noreferrer">Connect your agent with MCP ${icon("external-link")}</a>` : "";
  const field = (name, label, value) => `<div class="mcp-connection-row"><label for="mcp-${name}">${label}</label><div class="mcp-connection-value"><input id="mcp-${name}" readonly data-mcp-${name} value="${esc(value)}"><button class="icon-button secondary" type="button" data-mcp-copy="${name}" aria-label="Copy ${label === "Sandbox ID" ? "sandbox ID" : "server URL"}" title="Copy ${label === "Sandbox ID" ? "sandbox ID" : "server URL"}">${icon("copy")}</button></div></div>`;
  return `<div class="dialog-top"><div class="mcp-heading"><h2>${enabled ? "MCP access" : "Enable MCP"}</h2><span class="mcp-access-state" data-mcp-state ${enabled ? "" : "hidden"}>Enabled</span></div><button class="icon-button close-button" type="button" data-mcp-close aria-label="Close MCP settings">${icon("close")}</button></div>
    <p class="mcp-target"><strong>${esc(row.title)}</strong></p><p class="mcp-description" data-mcp-description>${enabled ? "Authenticated agents with shell permission can discover this micro VM and run commands." : "Allow authenticated agents to discover this micro VM and run shell commands, including reading and changing files. Existing ownership, sharing and security policies still apply."}</p>
    <div class="mcp-connection-fields">${field("id", "Sandbox ID", row.portal_id)}${field("url", "Server URL", configuration.resource_url)}</div>
    <p class="hint mcp-id-hint">Use this exact Sandbox ID when connecting your agent.</p><p class="hint mcp-copy-status" data-mcp-copy-status role="status" hidden></p>
    ${enabled && canManage ? '<p class="hint mcp-disable-note" data-mcp-disable-note>Disabling ends active attachments. A disconnected command is not guaranteed to have stopped.</p>' : ""}
    <p role="alert" data-mcp-error hidden></p><div class="mcp-footer">${docs}<div class="dialog-actions"><button class="secondary" type="button" data-mcp-close>${canManage ? "Cancel" : "Done"}</button>${canManage ? `<button class="${enabled ? "warning" : ""}" type="button" data-mcp-confirm>${enabled ? "Disable" : "Enable"} MCP</button>` : ""}</div></div>`;
}

export function openMCP(dialog, row, configuration, save, refresh, {canManage = true} = {}) {
  const view = Symbol();
  dialog.mcpView = view;
  const current = () => dialog.mcpView === view && dialog.open;
  const enabled = !!row.mcp?.enabled;
  dialog.innerHTML = mcpDialogContent(row, configuration, enabled, canManage);
  for (const button of dialog.querySelectorAll("[data-mcp-close]")) button.onclick = () => dialog.close();
  for (const button of dialog.querySelectorAll("[data-mcp-copy]")) button.onclick = async () => {
    const input = dialog.querySelector(`[data-mcp-${button.dataset.mcpCopy}]`);
    const status = dialog.querySelector("[data-mcp-copy-status]");
    try {
      await navigator.clipboard.writeText(input.value);
      status.textContent = button.dataset.mcpCopy === "id" ? "Sandbox ID copied." : "Server URL copied.";
    } catch {
      input.focus(); input.select();
      status.textContent = "Use your browser’s Copy command to copy the selected value.";
    }
    status.hidden = false;
  };
  const confirm = dialog.querySelector("[data-mcp-confirm]");
  if (confirm) confirm.onclick = async event => {
    const button = event.currentTarget;
    button.disabled = true;
    const error = dialog.querySelector("[data-mcp-error]");
    error.hidden = true;
    try {
      const result = await save({revision: row.revision, mcp: {enabled: !enabled}});
      row.mcp = result.mcp; row.revision = result.revision;
      if (current()) dialog.close();
      await refresh();
    } catch (err) {
      if (!current()) return;
      error.textContent = err.message + " Refresh the sandbox before trying again.";
      error.hidden = false; button.disabled = false;
    }
  };
  dialog.showModal();
}
