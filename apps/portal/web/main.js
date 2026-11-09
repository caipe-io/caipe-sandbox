import { terminalLoader } from "./terminal-loader.js";
import "@xterm/xterm/css/xterm.css";
import "./style.css";
import { icon } from "./icons.js";
import { TerminalConnection } from "./terminal-connection.js";
import { TerminalSessions } from "./terminal-sessions.js";
import { TerminalNavigationGuard } from "./navigation-guard.js";
import { RestartNotifications } from "./restart-notifications.js";
import { restartWarning } from "./restart-warning.js";
import { terminalText, terminalFilename } from "./terminal-output.js";
import { helperButton, cardHelperGroups } from "./helper-view.js";
import { sandboxConfiguration, profileDetails } from "./configuration-view.js";
import { acpConnectionView } from "./acp-view.js";
import { filterSandboxes, inventoryProfiles } from "./inventory-filter.js";
import { resourceInputs } from "./resource-controls.js";
import { integrationBadges, integrationTooltips } from "./integration-badges.js";
import { openWorkspace } from "./workspace-view.js";
import { runtimeError, runtimeStatus, copyRuntimeError, failedCreation, deletionConfirmation } from "./error-view.js";
import { cardLayout } from "./card-layout.js";
import { namespaceOptions, namespaceLockBadge } from "./namespace-view.js";
import { openIntegrationPanel, openSecurityPanel, mountIntegrationCreation, HostedNavigationGuard, createCAIPEQueryBridge } from "./integrations/index.js";
import { copyJson } from "./json-view.js";
import { sandboxMetadata } from "./timestamps.js";
import { createInventoryQueryNavigation } from "./query-navigation.js";
import { renderGlobalPolicySummary, sandboxPolicyBadges } from "./admin-policy-view.js";

for (const element of document.querySelectorAll("[data-icon]")) element.innerHTML = icon(element.dataset.icon);

const base = location.pathname.replace(/\/$/, "");
const sharedOwner = new URLSearchParams(location.search).get("owner");
const adminView = new URLSearchParams(location.search).get("view") === "admin";
const scope = sharedOwner && !adminView ? "?owner=" + encodeURIComponent(sharedOwner) : "";
const byId = (id) => document.getElementById(id);
for (const button of document.querySelectorAll("[data-close-dialog]")) button.onclick = () => byId(button.dataset.closeDialog).close();
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const badgeTooltips = integrationTooltips();
const sandboxLayout = cardLayout(byId("sandboxes"));
let activeSession = null, refreshBusy = false;
let terminalExit = null;
let configurationTarget = null;
const terminalSessions = new TerminalSessions();
const loadTerminal = terminalLoader();
const terminalLoadError = "Could not load the terminal. Check your connection and try Open terminal again.";
let terminalLoading = 0;
const restartNotifications = new RestartNotifications({
  changed: renderNotificationToggle,
  activate: key => {
    const session = terminalSessions.get(key);
    if (session) openTerminal(session.id, session.namespace, null, {sessionKey:key});
  },
});
function renderNotificationToggle() {
  const state = restartNotifications.state();
  const button = byId("restart-notifications");
  button.disabled = state.disabled;
  button.title = state.label;
  button.setAttribute("aria-label", state.label);
  button.setAttribute("aria-pressed", String(state.enabled));
}
byId("restart-notifications").onclick = () => restartNotifications.toggle();
renderNotificationToggle();
let creationId = crypto.randomUUID();
let creationIntegrations = null;
const busy = new Set();
const sandboxRows = new Map();
const toolStatuses = new Map(), toolChecks = new Set(), toolRefreshPending = new Set();
let profiles = [];
let namespaceDefault, namespaceChoices = [], sharingRevision;
let availableNamespaces = [], currentUser, currentRole;
let profileFilterOptions = "";
let resourcePolicy, editingId, sharingId, sharingMembers = {}, canManage = false;
let adminControls, editingControls, editingSandbox, editingUser, globalAnnouncement;
const selectedSandboxes = new Set();
let loginUrl = base + "/auth/login";
let authConfig = {};
const hostedNavigationGuard = new HostedNavigationGuard();
let terminalNavigationState = {active:false};
const terminalNavigationGuard = new TerminalNavigationGuard(state => {
  terminalNavigationState = state;
  hostedNavigationGuard.update(authConfig, state);
});
let signedIn = false;
let editingInventorySearch = false;
const inventoryNavigation = createInventoryQueryNavigation({
  basePath: base,
  bridge: createCAIPEQueryBridge(),
  onRestore({query, profile}) {
    editingInventorySearch = false;
    byId("admin-filter").value = query;
    refreshProfileFilter([...sandboxRows.values()]);
    byId("admin-profile-filter").value = profile;
    filterInventory();
  },
  beforeScopeChange() {
    if (!terminalNavigationState.active) return true;
    if (!confirm(`${terminalNavigationState.title}\n\n${terminalNavigationState.message}`)) return false;
    // The explicit confirmation replaces the otherwise duplicate unload prompt.
    window.removeEventListener("beforeunload", terminalNavigationGuard.beforeUnload);
    return true;
  },
  onScopeChange: () => location.reload(),
});
function showSignin(message = "") {
  message ||= authConfig.login_message || "";
  badgeTooltips.hide();
  sandboxLayout.clear();
  signedIn = false;
  canManage = false;
  closeAllTerminals();
  sandboxRows.clear();
  toolStatuses.clear();
  for (const dialog of document.querySelectorAll("dialog[open]")) dialog.close();
  byId("admin-row-actions").hidePopover();
  byId("sandboxes").replaceChildren();
  byId("app-main").hidden = true;
  byId("signin-screen").hidden = false;
  byId("signin-error").hidden = !message;
  byId("signin-error").textContent = message;
  if (!byId("sso-signin").disabled) byId("sso-signin").focus({preventScroll: true});
}
byId("sso-signin").onclick = () => location.assign(loginUrl);
async function api(path, method = "GET", payload) {
  const response = await fetch(base + "/api" + path + (scope ? (path.includes("?") ? "&" + scope.slice(1) : scope) : ""), {method, credentials: "same-origin", headers: {"Accept": "application/json", ...(payload ? {"Content-Type": "application/json"} : {})}, body: payload ? JSON.stringify(payload) : undefined});
  const body = await response.json();
  if (response.status === 401) {
    showSignin();
    const err = new Error("Sign in to access the sandbox portal");
    err.loginRequired = true;
    throw err;
  }
  if (!response.ok) {
    const detail = body.detail;
    const err = new Error(Array.isArray(detail) ? detail.map(e => e.msg).join("; ") : detail || "Request failed");
    err.status = response.status; throw err;
  }
  return body;
}
function fillResources(prefix, size, bounds) {
  const controls = resourceInputs(size, bounds, resourcePolicy);
  for (const control of controls) {
    const input = byId(`${prefix}-${control.id}`);
    input.min = control.min; input.max = control.max; input.value = control.value;
    input.readOnly = control.min === control.max;
  }
  return controls.every(control => control.min <= control.max);
}
function resourceInput(prefix) {
  const number = (id, scale) => Number(byId(`${prefix}-${id}`).value) * scale;
  const size = {cpu_request_millicores: number("cpu-request",1000), cpu_limit_millicores: number("cpu-limit",1000), memory_request_mib: number("memory-request",1024), memory_limit_mib: number("memory-limit",1024), workspace_gib: number("workspace",1)};
  for (const [key, value] of Object.entries(size)) {
    if (!Number.isFinite(value) || Math.abs(value - Math.round(value)) > 0.00001) throw new Error(key.startsWith("cpu") ? "CPU must be in increments of 0.001 cores" : key.startsWith("memory") ? "Memory must be a whole number of MiB" : "Disk size must be a whole number of GiB");
    size[key] = Math.round(value);
  }
  if (size.cpu_request_millicores > size.cpu_limit_millicores || size.memory_request_mib > size.memory_limit_mib) throw new Error("Reserved resources must not exceed their limits");
  return size;
}
for (const prefix of ["create","edit"]) {
  for (const key of ["cpu","memory"]) byId(`${prefix}-${key}-limit`).onchange = () => {
    const request = byId(`${prefix}-${key}-request`), limit = byId(`${prefix}-${key}-limit`);
    if (Number(request.value) > Number(limit.value)) request.value = limit.value;
  };
}
function error(err) {
  if (err.loginRequired) return;
  if (!signedIn) {
    if (err.status === 403 || byId("app-main").hidden) { showSignin(err.message); return; }
    byId("startup-message").textContent = "Could not load your sandboxes. Check your connection and try again.";
    byId("startup-retry").hidden = false;
    return;
  }
  const box = byId(byId("create-dialog").open ? "create-error" : "error"); box.hidden = false; box.textContent = err.message;
}
function renderSessions() {
  terminalNavigationGuard.update([...terminalSessions.values()].filter(session => session.connection && !session.retry && !session.connection.closed).length);
  const open = byId("terminal-panel").open;
  const rows = [...terminalSessions.values()].map(session => {
    const selected = open && activeSession === session.key;
    const state = session.retry ? "error" : session.connection?.shellReady ? "running" : "provisioning";
    return `<div class="session-row ${selected ? "selected" : ""}${session.restartNotice ? " session-draining" : ""}"><button class="session-open" type="button" data-session="${esc(session.key)}" aria-label="Open session: ${esc(session.title)} · Shell ${session.number}" ${selected ? 'aria-current="true"' : ""}><span class="session-name" title="${esc(session.title)} · Shell ${session.number}">${icon("terminal")}<span class="session-title">${esc(session.title)} · Shell ${session.number}</span></span><span class="session-state"><i class="led ${state}"></i>${esc(session.status)}</span></button>${restartWarning(session.restartNotice, session.key)}<button class="session-end icon-button" type="button" data-end-session="${esc(session.key)}" aria-label="Terminate session: ${esc(session.title)} · Shell ${session.number}" title="Terminate session">${icon("close")}</button></div>`;
  }).join("");
  const content = `<div class="session-heading">${icon("terminal")}SESSIONS <span>${terminalSessions.size}</span></div><div class="session-list">${rows}</div><button class="secondary action-delete session-close-all" type="button" data-end-all-sessions aria-label="Close all terminal sessions" title="Terminate every shell in this tab">${icon("close")}Close all sessions</button>`;
  for (const id of ["session-sidebar", "terminal-session-sidebar"]) {
    const rail = byId(id);
    rail.hidden = !terminalSessions.size || (id === "session-sidebar" && open);
    if (rail.innerHTML !== content) {
      const focusedWarning = rail.contains(document.activeElement) ? document.activeElement.dataset.restartKey : null;
      rail.innerHTML = content;
      if (focusedWarning) rail.querySelector(`[data-restart-key="${CSS.escape(focusedWarning)}"]`)?.focus({preventScroll:true});
      if (!rail.hidden) {
        const list = rail.querySelector(".session-list"), selected = rail.querySelector('[aria-current="true"]');
        if (list && selected) {
          const view = list.getBoundingClientRect(), tab = selected.getBoundingClientRect();
          // Keep scrolling inside the tab strip, including when embedded in another app.
          list.scrollLeft += tab.left < view.left ? tab.left - view.left : Math.max(0, tab.right - view.right);
        }
      }
    }
  }
  byId("app-main").classList.toggle("has-sessions", terminalSessions.size > 0);
}
function sandboxRestartWarning(key) {
  return `<span data-sandbox-restart="${esc(key)}">${restartWarning(terminalSessions.restartNotice(key))}</span>`;
}
function renderRestartWarnings() {
  for (const holder of document.querySelectorAll("[data-sandbox-restart]")) {
    const markup = restartWarning(terminalSessions.restartNotice(holder.dataset.sandboxRestart));
    if (holder.innerHTML === markup) continue;
    const focused = holder.contains(document.activeElement);
    holder.innerHTML = markup;
    if (focused) holder.querySelector(".restart-warning")?.focus({preventScroll:true});
  }
}
function updateTerminal(session) {
  renderSessions();
  renderRestartWarnings();
  if (activeSession !== session.key) return;
  byId("terminal-status").textContent = session.status + (session.retry && session.pendingCommand ? " Action command was not sent." : "");
  byId("terminal-restart").hidden = !session.restartNotice;
  byId("terminal-restart").textContent = session.restartNotice || "";
  byId("terminal-tool-status").textContent = session.helperResult?.text || "";
  byId("terminal-tool-status").dataset.tone = session.helperResult?.tone || "";
  byId("retry-terminal").hidden = !session.retry || !!session.helper;
  const detail = session.error;
  byId("terminal-error").hidden = !detail;
  byId("terminal-error").textContent = detail ? `${detail.message} [${detail.code}${detail.stage ? ` · ${detail.stage}` : ""}]${detail.request_id ? ` Diagnostic ID: ${detail.request_id}` : ""}` : "";
  byId("terminal-tips").hidden = !detail || !["client-timeout", "browser-connection", "connection-closed"].includes(detail.code);
  renderHelperActions(session);
}
function requestTermination(key = activeSession) {
  const session = terminalSessions.get(key);
  if (session && confirm(`Terminate Shell ${session.number} for ${session.title}? This closes this shell connection. Other sessions and the sandbox keep running.`)) closeTerminal(key);
}
function closeTerminal(key = activeSession) {
  const session = terminalSessions.get(key);
  if (!session) return;
  session.connection?.close(); session.observer.disconnect(); session.terminal.dispose(); session.element.remove();
  restartNotifications.clear(session.key);
  terminalSessions.delete(key);
  if (activeSession === key) {
    const next = [...terminalSessions.values()].at(-1);
    activeSession = next?.key || null;
    if (next && byId("terminal-panel").open) openTerminal(next.id, next.namespace, null, {sessionKey:next.key});
    else if (!next) closeTerminalDrawer();
  }
  renderSessions();
  renderRestartWarnings();
  const previous = sandboxRows.get(session.sandboxKey);
  if (signedIn && previous?.can_shell && !adminView) checkTools(previous);
}
function closeSandboxTerminals(sandboxKey) {
  for (const [key, session] of terminalSessions) if (session.sandboxKey === sandboxKey) closeTerminal(key);
}
function closeAllTerminals() {
  closeTerminalDrawer(true);
  for (const key of [...terminalSessions.keys()]) closeTerminal(key);
}
function closeTerminalDrawer(immediate = false) {
  const panel = byId("terminal-panel");
  if (!panel.open) return;
  if (immediate || matchMedia("(prefers-reduced-motion: reduce)").matches) {
    terminalExit?.cancel(); terminalExit = null;
    panel.close(); renderSessions(); return;
  }
  if (terminalExit) return;
  const animation = panel.animate([{clipPath:"inset(0)",opacity:1},{clipPath:"inset(100% 0 0)",opacity:0}], {duration:120,easing:"ease-in",fill:"forwards"});
  terminalExit = animation;
  animation.finished.then(() => {
    if (terminalExit !== animation) return;
    panel.close(); terminalExit = null; animation.cancel(); renderSessions();
  }).catch(() => {});
}
function hideTerminal() {
  terminalSessions.get(activeSession)?.observer.disconnect();
  closeTerminalDrawer();
  byId("terminal-helper-menu").open = false;
  renderSessions();
  const current = sandboxRows.get(terminalSessions.get(activeSession)?.sandboxKey);
  if (signedIn && current?.can_shell && !adminView) checkTools(current);
}
function sendPendingCommand(session) {
  if (session.pendingCommand && session.connection?.shellReady) {
    session.connection.send({type: "input", data: session.pendingCommand});
    session.pendingCommand = null;
  }
}
async function openTerminal(id, namespace = null, command = null, {newSession = false, sessionKey = null, helper = null} = {}) {
  const sandboxKey = namespace ? `${namespace}/${id}` : id;
  let row = sandboxRows.get(sandboxKey);
  if (!row || row.state !== "Running" || (!adminView && !row.can_shell)) return;
  let session = sessionKey ? terminalSessions.get(sessionKey) : newSession ? null : terminalSessions.latest(sandboxKey);
  let runtime;
  if (!session) {
    const uid = row.uid;
    if (byId("error").textContent === terminalLoadError) byId("error").hidden = true;
    void restartNotifications.firstTerminalCreated();
    terminalLoading++;
    byId("terminal-loading").hidden = false;
    try { runtime = await loadTerminal(); }
    catch {
      error(new Error(terminalLoadError));
      return;
    } finally {
      terminalLoading--;
      byId("terminal-loading").hidden = !terminalLoading;
    }
    row = sandboxRows.get(sandboxKey);
    if (!signedIn || !row || row.uid !== uid || row.state !== "Running" || row.disabled || (!adminView && !row.can_shell)) return;
    session = sessionKey ? terminalSessions.get(sessionKey) : newSession ? null : terminalSessions.latest(sandboxKey);
    if (sessionKey && !session) return;
  }
  terminalSessions.get(activeSession)?.observer.disconnect();
  byId("terminal-helper-menu").open = false;
  if (!session) {
    const {Terminal, FitAddon, SearchAddon} = runtime;
    const element = document.createElement("div"); element.className = "terminal-session";
    byId("terminal").append(element);
    const terminal = new Terminal({cursorBlink: true, fontSize: 14, disableStdin: true, theme: {background: "#111827", foreground: "#e5e7eb"}});
    const fit = new FitAddon(), search = new SearchAddon(); terminal.loadAddon(fit); terminal.loadAddon(search); terminal.open(element);
    session = terminalSessions.create(sandboxKey, {id, namespace, uid:row.uid, title:row.title, element, terminal, fit, search, searchTerm:"", status:"Connecting…", retry:false, error:null, pendingCommand:command, helper});
    session.observer = new ResizeObserver(() => {
      if (!byId("terminal-panel").open || activeSession !== session.key) return;
      fit.fit(); session.connection?.send({type:"resize",cols:terminal.cols,rows:terminal.rows});
    });
    terminal.onData(data => session.connection?.send({type:"input",data}));
    let target = namespace ? `/admin/sandboxes/${encodeURIComponent(id)}/terminal?namespace=${encodeURIComponent(namespace)}` : `/sandboxes/${encodeURIComponent(id)}/terminal${scope}`;
    if (helper) target += (target.includes("?") ? "&" : "?") + "helper=" + encodeURIComponent(helper);
    const terminalBase = authConfig.terminal_url || `${location.protocol === "https:" ? "wss:" : "ws:"}//${location.host}${base}`;
    session.connection = new TerminalConnection(`${terminalBase}/api${target}`, {
      status:(text, retry) => { session.status = text; session.retry = retry; updateTerminal(session); },
      ready:() => {
        restartNotifications.clear(session.key);
        terminal.options.disableStdin = false;
        session.connection.send({type:"resize",cols:terminal.cols,rows:terminal.rows});
        sendPendingCommand(session); updateTerminal(session);
        if (activeSession === session.key && byId("terminal-panel").open) terminal.focus();
      },
      output:text => terminal.write(text),
      disconnected:() => { session.pendingCommand = null; terminal.options.disableStdin = true; updateTerminal(session); },
      notice:message => { session.restartNotice = message; updateTerminal(session); },
      restart:seconds => restartNotifications.warn(session.key, seconds),
      error:detail => { session.error = detail; updateTerminal(session); },
      complete:exitCode => {
        session.helper = null;
        session.helperResult = exitCode === 0 ? {text:"Helper completed",tone:"success"} : {text:exitCode == null ? "Helper exit status unavailable" : `Helper exited with code ${exitCode}`,tone:"error"};
        terminal.write("\r\n");
        updateTerminal(session);
        const current = sandboxRows.get(session.sandboxKey);
        if (signedIn && current && !adminView) void checkTools(current, true);
      },
    }, {maxRetries:helper ? 0 : 3, authenticate:authConfig.terminal_credentials ? async url => {
      const query = new URL(url).searchParams;
      // api() already supplies the active sharing owner.
      query.delete("owner");
      const path = target.split("?")[0].replace(/\/terminal$/, "/terminal-credentials");
      const result = await api(path + (query.size ? "?" + query : ""), "POST");
      return result.credential;
    } : undefined});
  }
  activeSession = session.key;
  byId("terminal-search-query").value = session.searchTerm;
  byId("terminal-search").hidden = !session.searchTerm;
  byId("terminal-search-result").textContent = "";
  terminalExit?.cancel(); terminalExit = null;
  if (!byId("terminal-panel").open) byId("terminal-panel").showModal();
  byId("terminal-title").textContent = `${row.title} · Shell ${session.number}`;
  byId("terminal-title").title = row.title + (namespace ? ` · ${namespace}` : "");
  for (const item of terminalSessions.values()) item.element.hidden = item !== session;
  session.fit.fit(); session.observer.observe(byId("terminal"));
  updateTerminal(session);
  if (session.connection.shellReady) session.terminal.focus();
}
function handleSessionAction(event) {
  if (event.target.closest("[data-end-all-sessions]")) {
    if (confirm(`Close all ${terminalSessions.size} terminal sessions?\n\nThis terminates every shell in this tab. Your micro VMs keep running.`)) closeAllTerminals();
    return;
  }
  const end = event.target.closest("[data-end-session]");
  if (end) { requestTermination(end.dataset.endSession); return; }
  const button = event.target.closest("[data-session]");
  const session = button && terminalSessions.get(button.dataset.session);
  if (session) openTerminal(session.id, session.namespace, null, {sessionKey:session.key});
}
byId("session-sidebar").onclick = handleSessionAction;
byId("terminal-session-sidebar").onclick = handleSessionAction;
function helperButtons(row, definitions, attributes) {
  const ready = row.state === "Running" && !row.disabled && (adminView || row.can_shell);
  const states = row.state === "Running" ? toolStatuses.get(row.id)?.tools : {};
  return definitions.map(h => helperButton(h, states, {attributes:attributes(h),disabled:!ready})).join("");
}
function integrationActions(row, attributes) {
  const panels=row?.control_panels || [];
  return (panels.some(panel=>panel.category==="security") ? `<button class="secondary" type="button" data-action="network-security" ${attributes}>${icon("shield")}Network &amp; security</button>` : "")+
    panels.filter(panel=>panel.category!=="security").map(panel=>`<button class="secondary" type="button" data-action="integration-panel" data-panel="${esc(panel.id)}" ${attributes}>${icon(panel.icon)}${esc(panel.title)}</button>`).join("");
}

function cardHelpers(s) {
  const configured = profiles.find(profile => profile.id === s.profile?.id)?.helpers;
  const {visible, overflow} = cardHelperGroups(s.helpers, configured);
  if (!visible.length) return "";
  const attributes = helper => `data-action="helper" data-id="${esc(s.id)}" data-helper="${esc(helper.id)}"`;
  const more = overflow.length ? `<details class="card-helper-menu"><summary aria-label="More helpers"><span class="helpers-collapsed">More (${overflow.length})</span><span class="helpers-expanded">Show less</span>${icon("chevron")}</summary><div class="tool-row">${helperButtons(s, overflow, attributes)}</div></details>` : "";
  return `<div class="integration-heading"><strong>Helpers</strong></div><div class="tool-row">${helperButtons(s, visible, attributes)}${more}</div>`;
}
async function checkTools(s, fresh = false) {
  if (!s.helpers.some(h => h.status_available) || s.state !== "Running" || !s.can_shell) { toolStatuses.delete(s.id); return; }
  if (toolChecks.has(s.id)) { if (fresh) toolRefreshPending.add(s.id); return; }
  if (!fresh && Date.now() - (toolStatuses.get(s.id)?.checked || 0) < 30000) return;
  toolChecks.add(s.id);
  try {
    const result = await api(`/sandboxes/${encodeURIComponent(s.id)}/tools${fresh ? "?fresh=true" : ""}`);
    if (!signedIn || sandboxRows.get(s.id)?.state !== "Running") return;
    toolStatuses.set(s.id, {tools:result.tools, checked:Date.now()});
  } catch (err) {
    if (err.loginRequired) return;
    if (signedIn) toolStatuses.set(s.id, {tools:Object.fromEntries(s.helpers.map(h => [h.id,"unknown"])),checked:Date.now()});
  } finally {
    const row = signedIn && document.querySelector(`[data-sandbox="${CSS.escape(s.id)}"] .helper-section`);
    if (row) {
      const open = row.querySelector(".card-helper-menu")?.open;
      const focused = row.contains(document.activeElement) ? document.activeElement : null;
      const selector = focused?.tagName === "SUMMARY" ? "summary" : focused?.dataset.helper ? `[data-helper="${CSS.escape(focused.dataset.helper)}"]` : null;
      const sandbox = sandboxRows.get(s.id);
      row.innerHTML = cardHelpers(sandbox);
      row.hidden = !row.innerHTML;
      const menu = row.querySelector(".card-helper-menu");
      if (menu && open) menu.open = true;
      if (selector) row.querySelector(selector)?.focus({preventScroll:true});
    }
    const session = terminalSessions.get(activeSession);
    if (session?.sandboxKey === s.id) renderHelperActions(session);
    toolChecks.delete(s.id);
    if (toolRefreshPending.delete(s.id) && signedIn && sandboxRows.has(s.id)) checkTools(sandboxRows.get(s.id), true);
  }
}
function sandboxCard(s) {
  const running = s.state === "Running", a = s.allocation;
  const stateClass = ({Running:"running", Suspended:"suspended", Provisioning:"provisioning", Suspending:"provisioning", Deleting:"deleting", Error:"error", Unknown:"provisioning"})[s.state] || "suspended";
  const button = (action, text, glyph, disabled = false, className = "secondary", content = "") => {
    const denied = ["configuration", "integration-panel"].includes(action) ? false : s.disabled || (action === "sharing" ? !s.can_share : (action === "terminal" || action === "workspace") ? !s.can_shell : action !== "chat" && !s.can_manage);
    return `<button class="${className}" data-action="${action}" data-id="${esc(s.id)}" aria-label="${esc(text)}" title="${esc(text)}" ${disabled || denied || busy.has(s.id) ? "disabled" : ""}>${icon(glyph)}${content || `<span>${esc(text)}</span>`}</button>`;
  };
  const retry = s.operation?.state === "needs_attention";
  const cancel = failedCreation(s) && s.operation.creation_rejected;
  const powerAction = cancel ? "delete" : retry ? "retry" : s.state === "Suspended" ? "resume" : "suspend";
  const powerText = cancel ? "Cancel creation" : retry ? (s.operation.kind === "create" ? "Retry creation" : "Retry action") : s.state === "Suspended" ? "Resume" : "Suspend";
  const powerContent = `<span class="power-label"><strong>${esc(retry && !running ? "Needs attention" : s.state)}</strong><small>${s.disabled ? "Access locked" : !s.can_manage ? "Owner only" : retry || ["Running","Suspended","Error"].includes(s.state) ? powerText : "Please wait"}</small></span>`;
  const stateButton = button(powerAction,`${s.state} — ${powerText}`,cancel ? "trash" : retry ? "refresh" : "power",!retry && (!!s.operation || !["Running","Suspended","Error"].includes(s.state) || (s.state !== "Suspended" && s.capabilities?.suspend === false)),"power-button " + stateClass,powerContent);
  const overflow = `<details class="card-menu"><summary aria-label="Sandbox actions" title="Sandbox actions">Actions${icon("chevron")}</summary><div class="overflow-actions">${s.operation && s.can_manage && !cancel ? button("retry","Retry operation","refresh") : ""}${button("configuration","View/Sync Configuration","file")}${integrationActions(s,`data-id="${esc(s.id)}"`)}${s.can_shell ? button("workspace","Startup & services","code",s.state!=="Running") : ""}${s.can_share ? button("sharing","Share sandbox","share") : ""}${s.can_manage ? `${button("resources","Edit CPU / memory","settings",!a || s.state!=="Suspended" || !!s.operation || s.capabilities?.resize === false)}${button("delete",failedCreation(s) ? "Cancel creation" : "Delete sandbox","trash",s.state==="Deleting","secondary danger")}<small>${s.capabilities?.resize === false ? "Resources are set at creation" : "Suspend to edit resources"}</small>` : ""}</div></details>`;

  const note = s.admin_control?.notice;
  const helpers = cardHelpers(s);
  return `<article class="sandbox-card ${stateClass}${s.disabled ? " access-disabled" : ""}" data-sandbox="${esc(s.id)}">
    ${note ? `<button class="sandbox-notice" type="button" data-action="notice" data-id="${esc(s.id)}" aria-label="Message from admin: ${esc(note.title)}. Read message"><span class="sandbox-notice-icon">${icon("message")}</span><span class="sandbox-notice-copy"><span class="sandbox-notice-heading">Message from admin<span class="sandbox-notice-link">Read message ${icon("chevron")}</span></span><strong>${esc(note.title)}</strong><span class="sandbox-notice-preview">${esc(note.body.replace(/\s+/g, " ").slice(0,180))}</span></span></button>` : ""}
    ${s.disabled ? `<div class="sandbox-disabled-note">${icon("shield")}<span><strong>Access disabled</strong> · ${esc(s.disabled_reason)}</span></div>` : ""}
    <div class="machine-top"><div class="machine-symbol">${icon("server")}</div><div class="machine-title"><h2 title="${esc(s.title)}">${esc(s.title)}</h2><code class="machine-id" title="Sandbox ID">${esc(s.native_id || s.id)}</code>${integrationBadges(s.integrations,{key:`card-${s.namespace}/${s.id}/${s.uid || ""}`,assetBase:base + "/assets/integrations",limit:3})}</div><div class="machine-controls">${stateButton}</div></div>${sandboxRestartWarning(s.id)}
    <div class="machine-status-row">${runtimeStatus(s)}${overflow}</div>
    ${a ? `<div class="capacity-grid">
      <div class="capacity" title="${esc(a.cpu_request_millicores/1000)} cores reserved; ${esc(a.cpu_limit_millicores/1000)} cores limit"><span>${icon("cpu")}CPU</span><strong>${esc(a.cpu_limit_millicores/1000)}<small>cores</small></strong></div>
      <div class="capacity" title="${esc(a.memory_request_mib/1024)} GiB reserved; ${esc(a.memory_limit_mib/1024)} GiB limit"><span>${icon("memory")}Memory</span><strong>${esc(a.memory_limit_mib/1024)}<small>GiB</small></strong></div>
      <div class="capacity" title="Persistent disk"><span>${icon("disk")}Disk</span><strong>${esc(a.workspace_gib)}<small>GiB</small></strong></div>
    </div>` : ""}
    <section class="helper-section" aria-label="Profile helpers" ${helpers ? "" : "hidden"}>${helpers}</section>
    <div class="machine-actions">${s.acp_available && s.can_manage ? button("acp-connection","Connect to CAIPE","caipe") : ""}${button("terminal","Open terminal","terminal",!running,"terminal-button")}</div>
    <footer class="machine-footer">${sandboxMetadata(s)}</footer>

  </article>`;
}

function updateSelection() {
  byId("selection-count").textContent = `${selectedSandboxes.size} selected`;
  for (const id of ["suspend-selected", "disable-selected", "enable-selected"]) byId(id).disabled = !selectedSandboxes.size;
}
function adminInventory(rows) {
  const filtered = filterSandboxes(rows, byId("admin-filter").value, byId("admin-profile-filter").value);
  return `<div class="admin-inventory"><table><thead><tr><th>Select</th><th>Sandbox</th><th>Owner</th><th>Profile</th><th>Namespace</th><th>Status</th><th>CPU / RAM / disk</th><th>Actions</th></tr></thead><tbody>${filtered.map(s => {
    const key = s.namespace + "/" + s.id;
    const action = (name, label, glyph, disabled = false, className = "") => `<button class="secondary ${className}" type="button" data-action="admin-${name}" data-id="${esc(s.id)}" data-namespace="${esc(s.namespace)}" ${disabled ? "disabled" : ""}>${icon(glyph)}${label}</button>`;
    return `<tr data-sandbox="${esc(key)}"><td><input type="checkbox" data-select-sandbox="${esc(key)}" aria-label="Select ${esc(s.title)}" ${selectedSandboxes.has(key) ? "checked" : ""}></td><td><strong>${esc(s.title)}</strong>${sandboxRestartWarning(key)}<small>${esc(s.native_id || s.id)}</small>${sandboxPolicyBadges(s, adminControls)}${s.admin_control?.notice ? `<small class="admin-message-marker">${icon("message")}${esc(s.admin_control.notice.title)}</small>` : ""}</td><td>${esc(s.owner || "Unassigned")}${s.owner ? action("user", "User restrictions", "shield") : ""}</td><td>${s.profile ? `<span class="profile-badge" title="${esc(s.profile.id)} · ${esc(s.profile.revision)}">${esc(s.profile.title)}</span>` : "—"}</td><td><span class="admin-namespace"><code>${esc(s.namespace)}</code>${namespaceLockBadge(s.namespace_locked,s.id)}</span></td><td><span class="admin-status ${esc(s.state.toLowerCase())}"><i class="led ${s.state === "Running" ? "running" : s.state === "Error" ? "error" : "provisioning"}"></i>${esc(s.state)}</span>${integrationBadges(s.integrations,{key:`admin-${key}/${s.uid || ""}`,assetBase:base + "/assets/integrations",limit:1})}${s.disabled ? `<small class="access-lock-label">${icon("shield")}Access disabled</small>` : ""}<small>${esc(s.disabled ? s.disabled_reason : s.state === "Error" ? "Needs attention" : s.reason || "")}</small>${runtimeError(s)}</td><td>${s.allocation ? `${esc(s.allocation.cpu_limit_millicores/1000)} cores · ${esc(s.allocation.memory_limit_mib/1024)} GiB · ${esc(s.allocation.workspace_gib)} GiB` : "—"}</td><td><div class="admin-actions"><div class="admin-tools-actions" role="group" aria-label="Sandbox tools">${action("terminal", "Terminal", "terminal", s.state !== "Running")}<button class="secondary admin-more" type="button" data-action="admin-menu" data-id="${esc(s.id)}" data-namespace="${esc(s.namespace)}" aria-label="More actions for ${esc(s.title)}" aria-haspopup="true" aria-controls="admin-row-actions" title="Sandbox actions">Actions${icon("chevron")}</button></div><div class="admin-lifecycle-actions" role="group" aria-label="Sandbox lifecycle">${action(s.state === "Suspended" ? "resume" : "suspend", s.state === "Suspended" ? "Resume" : "Suspend", "power", s.state === "Deleting" || s.state === "Suspending" || (s.state !== "Suspended" && s.capabilities?.suspend === false) || (s.disabled && s.state === "Suspended"), s.state === "Suspended" ? "action-resume" : "action-suspend")}${action("delete", failedCreation(s) ? "Cancel creation" : "Delete", "trash", s.state === "Deleting", "action-delete")}</div></div></td></tr>`;
  }).join("") || `<tr><td colspan="8">No matching sandboxes.</td></tr>`}</tbody></table></div>`;
}
function renderAdminInventory(rows) {
  const openErrors = new Set([...byId("sandboxes").querySelectorAll(".runtime-error[open]")].map(e => e.dataset.errorKey));
  const left = byId("sandboxes").querySelector(".admin-inventory")?.scrollLeft || 0;
  byId("sandboxes").innerHTML = adminInventory(rows);
  byId("sandboxes").querySelector(".admin-inventory").scrollLeft = left;
  for (const detail of byId("sandboxes").querySelectorAll(".runtime-error")) detail.open = openErrors.has(detail.dataset.errorKey);
}
function filterInventory() {
  if (!adminView) return;
  selectedSandboxes.clear();
  renderAdminInventory([...sandboxRows.values()]);
  updateSelection();
}
byId("admin-filter").oninput = () => {
  const mode = editingInventorySearch ? "replace" : "push";
  inventoryNavigation.filters(byId("admin-filter").value, byId("admin-profile-filter").value, mode);
  editingInventorySearch = true;
};
byId("admin-filter").onblur = () => { editingInventorySearch = false; };
byId("admin-profile-filter").onchange = () => inventoryNavigation.filters(byId("admin-filter").value, byId("admin-profile-filter").value);
function refreshProfileFilter(rows) {
  const choices = inventoryProfiles(profiles, rows);
  const requested = inventoryNavigation.read().profile;
  if (requested && !choices.some(profile => profile.id === requested)) choices.push({id:requested,title:"Unavailable profile"});
  const markup = choices.map(profile => `<option value="${esc(profile.id)}">${esc(profile.title)}</option>`).join("");
  if (markup === profileFilterOptions) return;
  const selected = requested;
  byId("admin-profile-filter").innerHTML = markup;
  if (choices.some(profile => profile.id === selected)) byId("admin-profile-filter").value = selected;
  profileFilterOptions = markup;
}
byId("sandboxes").addEventListener("change", event => {
  const key = event.target.dataset.selectSandbox;
  if (!key) return;
  if (event.target.checked) selectedSandboxes.add(key); else selectedSandboxes.delete(key);
  updateSelection();
});
function showMessage(note) {
  if (!note) return;
  byId("message-title").textContent = note.title;
  byId("message-body").textContent = note.body;
  byId("message-author").textContent = `${note.author} · ${new Date(note.updated_at).toLocaleString()}`;
  byId("message-dialog").showModal();
}
byId("global-announcement").onclick = () => showMessage(globalAnnouncement);
byId("close-message").onclick = () => byId("message-dialog").close();
function controlsPayload(control) {
  return {resource_version:control.resource_version, creation_disabled:control.creation_disabled, sandboxes_disabled:control.sandboxes_disabled, reason:control.reason, announcement:{title:control.announcement?.title || "",body:control.announcement?.body || ""}, users:control.users || {}};
}
function fillNotice(prefix, note) {
  byId(prefix + "-message-title").value = note?.title || "";
  byId(prefix + "-message-body").value = note?.body || "";
}
function readNotice(prefix) { return {title:byId(prefix + "-message-title").value,body:byId(prefix + "-message-body").value}; }
async function saveAdminForm(event, name, save) {
  event.preventDefault();
  const submit = byId("save-admin-" + name), box = byId("admin-" + name + "-error");
  submit.disabled = true; box.hidden = true;
  try { if (await save() === false) return; byId("admin-" + name + "-dialog").close(); await refresh(); }
  catch (err) { if (!err.loginRequired) { box.textContent = err.message + (err.status === 409 ? " Close and reopen this dialog to review the latest values." : ""); box.hidden = false; } await refresh(); }
  finally { submit.disabled = false; }
}
byId("admin-controls").onclick = () => {
  editingControls = structuredClone(adminControls);
  byId("global-creation-disabled").checked = editingControls.creation_disabled;
  byId("global-sandboxes-disabled").checked = editingControls.sandboxes_disabled;
  byId("global-control-reason").value = editingControls.reason;
  fillNotice("global", editingControls.announcement);
  byId("user-restrictions-summary").innerHTML = `<strong>User policies (${Object.keys(editingControls.users).length})</strong><div class="user-policy-list">${Object.keys(editingControls.users).map(email=>`<button type="button" class="secondary" data-user-policy="${esc(email)}">${esc(email)}</button>`).join("")}</div>`;
  byId("admin-controls-error").hidden = true;
  byId("admin-controls-dialog").showModal();
};
function openUserPolicy(email) {
  editingControls = structuredClone(adminControls); editingUser = email;
  const policy = adminControls.users[email] || {};
  byId("admin-user-title").textContent = email;
  byId("user-creation-disabled").checked = !!policy.creation_disabled;
  byId("user-sandboxes-disabled").checked = !!policy.sandboxes_disabled;
  byId("user-control-reason").value = policy.reason || "";
  byId("admin-controls-dialog").close();
  byId("admin-user-error").hidden = true; byId("admin-user-dialog").showModal();
}
byId("user-restrictions-summary").onclick = event => { const email = event.target.closest("[data-user-policy]")?.dataset.userPolicy; if (email) openUserPolicy(email); };
byId("lookup-user-policy").onclick = () => {
  const input = byId("user-policy-email");
  if (input.value.trim() && input.reportValidity()) openUserPolicy(input.value.trim().toLowerCase());
};
byId("admin-controls-form").onsubmit = event => saveAdminForm(event, "controls", async () => {
  const payload = {...controlsPayload(editingControls),creation_disabled:byId("global-creation-disabled").checked,sandboxes_disabled:byId("global-sandboxes-disabled").checked,reason:byId("global-control-reason").value,announcement:readNotice("global")};
  if (payload.sandboxes_disabled && !editingControls.sandboxes_disabled && !confirm("Disable user access to all sandboxes? Running processes will stop; persistent disk is retained. Re-enabling does not restart them.")) return false;
  const result = await api("/admin/controls", "PUT", payload); editingControls = result.controls;
  if (result.suspension_failures?.length) {
    await refresh();
    throw new Error("Restrictions saved; some sandboxes have not stopped yet. Automatic retry is active: " + result.suspension_failures.map(s=>`${s.namespace}/${s.name}: ${s.error}`).join("; "));
  }
});
byId("admin-sandbox-form").onsubmit = event => saveAdminForm(event, "sandbox", async () => {
  if (byId("sandbox-disabled").checked && !editingSandbox.disabled && !confirm("Disable user access to this sandbox? Its processes will stop; persistent disk is retained. Re-enabling does not restart it.")) return false;
  await api(`/admin/sandboxes/${encodeURIComponent(editingSandbox.id)}/control?namespace=${encodeURIComponent(editingSandbox.namespace)}&uid=${encodeURIComponent(editingSandbox.uid)}`, "PUT", {resource_version:editingSandbox.resource_version,disabled:byId("sandbox-disabled").checked,reason:byId("sandbox-control-reason").value,notice:readNotice("sandbox")});
});
byId("admin-user-form").onsubmit = event => saveAdminForm(event, "user", async () => {
  const payload = controlsPayload(editingControls), policy = {creation_disabled:byId("user-creation-disabled").checked,sandboxes_disabled:byId("user-sandboxes-disabled").checked,reason:byId("user-control-reason").value};
  if (policy.sandboxes_disabled && !editingControls.users[editingUser]?.sandboxes_disabled && !confirm(`Disable user access to all sandboxes owned by ${editingUser}? Their processes will stop; persistent disk is retained.`)) return false;
  if (policy.creation_disabled || policy.sandboxes_disabled) payload.users[editingUser] = policy; else delete payload.users[editingUser];
  const result = await api("/admin/controls", "PUT", payload); editingControls = result.controls;
  if (result.suspension_failures?.length) {
    await refresh();
    throw new Error("Restrictions saved; some sandboxes have not stopped yet. Automatic retry is active: " + result.suspension_failures.map(s=>`${s.namespace}/${s.name}: ${s.error}`).join("; "));
  }
});
for (const name of ["controls", "sandbox", "user"]) byId("cancel-admin-" + name).onclick = () => byId("admin-" + name + "-dialog").close();
async function bulkControl(update, verb) {
  const rows = [...selectedSandboxes].map(key=>sandboxRows.get(key)).filter(Boolean);
  if (!confirm(`${verb} ${rows.length} selected sandbox(s)? Disabling stops processes and blocks startup. Re-enabling leaves sandboxes suspended.`)) return;
  for (const id of ["suspend-selected", "disable-selected", "enable-selected"]) byId(id).disabled = true;
  const failed = [];
  for (const row of rows) {
    try { await api(`/admin/sandboxes/${encodeURIComponent(row.id)}/control?namespace=${encodeURIComponent(row.namespace)}&uid=${encodeURIComponent(row.uid)}`, "PUT", {resource_version:row.resource_version,...update}); }
    catch(err) { if (err.loginRequired) return; failed.push(`${row.title}: ${err.message}`); }
  }
  selectedSandboxes.clear(); await refresh(); updateSelection();
  if (failed.length) error(new Error("Some actions failed: " + failed.join("; ")));
}
byId("suspend-selected").onclick = () => bulkControl({operating_mode:"Suspended"}, "Suspend");
byId("disable-selected").onclick = () => bulkControl({disabled:true,reason:"Access disabled by an administrator"}, "Disable");
byId("enable-selected").onclick = () => bulkControl({disabled:false,reason:""}, "Re-enable");

async function refresh() {
  if (refreshBusy) return;
  refreshBusy = true;
  try {
    const data = await api(adminView ? "/admin/sandboxes" : "/sandboxes");
    for (const row of data.sandboxes) { row.native_id = row.id; row.id = row.portal_id || row.id; }
    currentUser = data.user_id;
    currentRole = data.role;
    byId("admin-nav").hidden = data.role !== "admin";
    byId("admin-controls").hidden = !adminView;
    profiles = data.profiles || [];
    namespaceDefault = data.namespace_strategy;
    namespaceChoices = data.namespace_choices || [];
    if (adminView) refreshProfileFilter(data.sandboxes);
    byId("profile-catalog").hidden = data.role !== "admin";
    if (!byId("create-dialog").open) {
      const selected = byId("sandbox-profile").value || data.default_profile;
      byId("sandbox-profile").innerHTML = profiles.map(p => `<option value="${esc(p.id)}" data-revision="${esc(p.revision)}">${esc(p.title)}</option>`).join("");
      if (profiles.some(p => p.id === selected)) byId("sandbox-profile").value = selected;
      updateProfileDescription();
    }
    renderHelperActions();
    adminControls = data.controls;
    renderGlobalPolicySummary(byId("admin-policy-summary"), adminView ? adminControls : undefined);
    globalAnnouncement = data.announcement;
    byId("global-announcement").hidden = !globalAnnouncement;
    byId("announcement-title").textContent = globalAnnouncement?.title || "";
    byId("announcement-preview").textContent = globalAnnouncement?.body.slice(0,180) || "";
    const restriction = data.creation_disabled_reason || (adminView && (adminControls.creation_disabled || adminControls.sandboxes_disabled) ? adminControls.reason || "Global restrictions are active" : "");
    byId("creation-restriction").hidden = !restriction;
    byId("creation-restriction").textContent = restriction;
    byId("admin-toolbar").hidden = !adminView;
    byId("admin-warning").hidden = !adminView;
    byId("my-sandboxes").setAttribute("aria-current", adminView ? "false" : "page");
    byId("all-sandboxes").setAttribute("aria-current", adminView ? "page" : "false");
    byId("user").textContent = data.user_id;
    byId("user").title = data.user_id;
    byId("avatar").textContent = data.user_id.slice(0,2).toUpperCase();
    if (adminView) {
      byId("page-title").textContent = "All sandboxes";
      byId("page-description").textContent = "Cluster inventory. Inspect terminals and remove sandboxes across all users and namespaces.";
      byId("scope-label").textContent = "ADMINISTRATOR";
    } else if (sharedOwner && sharedOwner !== data.user_id) {
      byId("page-title").textContent = "Shared sandboxes";
      byId("page-description").textContent = "micro VMs shared with you by " + sharedOwner;
      byId("own-sandboxes").hidden = false;
      byId("scope-label").textContent = "SHARED";
    }
    byId("role").textContent = data.role;
    canManage = data.can_manage;
    byId("new-sandbox").hidden = !canManage;
    byId("new-sandbox").disabled = !canManage || !!data.creation_disabled_reason;
    byId("create").disabled = !canManage || !!data.creation_disabled_reason;
    byId("namespace").textContent = data.namespace;
    if (!resourcePolicy) {
      resourcePolicy = data.resource_policy;
      fillResources("create", resourcePolicy.defaults);
      byId("create").disabled = !canManage || !!data.creation_disabled_reason;
    }
    sandboxRows.clear();
    for (const row of data.sandboxes) sandboxRows.set(adminView ? `${row.namespace}/${row.id}` : row.id,row);
    for (const [key, session] of terminalSessions) {
      const row = sandboxRows.get(session.sandboxKey);
      if (!row || row.uid !== session.uid || row.state !== "Running" || (!adminView && !row.can_shell)) closeTerminal(key);
      else session.title = row.title;
    }
    for (const key of selectedSandboxes) if (!sandboxRows.has(key)) selectedSandboxes.delete(key);
    updateSelection();
    renderSessions();
    const count = state => data.sandboxes.filter(s=>s.state === state).length;
    byId("stat-total").textContent = data.sandboxes.length;
    byId("stat-running").textContent = count("Running");
    byId("stat-suspended").textContent = count("Suspended");
    byId("stat-starting").textContent = count("Provisioning");
    byId("stat-errors").textContent = count("Error") + count("Unknown");
    const total = data.sandboxes.filter(s=>s.allocation).reduce((v,s)=>({cpu:v.cpu+s.allocation.cpu_limit_millicores/1000,memory:v.memory+s.allocation.memory_limit_mib/1024,disk:v.disk+s.allocation.workspace_gib}),{cpu:0,memory:0,disk:0});
    const format = value => Number(value.toFixed(3)).toLocaleString();
    byId("configured-capacity").textContent = `${adminView ? "Reported: " : ""}${format(total.cpu)} cores · ${format(total.memory)} GiB memory · ${format(total.disk)} GiB disk configured`;
    const openMenus = new Set([...document.querySelectorAll(".card-menu[open]")].map(e => e.closest(".sandbox-card").dataset.sandbox));
    const openHelperMenus = new Set([...document.querySelectorAll(".card-helper-menu[open]")].map(e => e.closest(".sandbox-card").dataset.sandbox));
    const expandedErrors = new Set([...document.querySelectorAll(".sandbox-card .runtime-error[open]")].map(e => e.dataset.errorKey));
    const focused = document.activeElement;
    const focusedCard = focused?.closest(".sandbox-card");
    const focusKey = focusedCard ? {id:focusedCard.dataset.sandbox,action:focused.dataset.action,helper:focused.dataset.helper,warning:focused.classList.contains("restart-warning"),summary:focused.tagName === "SUMMARY" ? (focused.closest(".card-menu") ? ".card-menu" : focused.closest(".card-helper-menu") ? ".card-helper-menu" : focused.closest(".runtime-error") ? ".runtime-error" : null) : null} : null;
    badgeTooltips.beforeRender();
    if (adminView) renderAdminInventory(data.sandboxes);
    else byId("sandboxes").innerHTML = data.sandboxes.length ? data.sandboxes.map(sandboxCard).join("") : `<div class="empty">${icon("server")}<h2>${sharedOwner ? "No shared sandboxes" : "No sandboxes yet"}</h2><p>${sharedOwner ? "This owner has not shared a sandbox with your account." : "Create your first environment to get started."}</p></div>`;
    for (const card of document.querySelectorAll(".sandbox-card")) {
      const menu = card.querySelector(".card-menu");
      if (menu && openMenus.has(card.dataset.sandbox)) menu.open = true;
      if (openHelperMenus.has(card.dataset.sandbox) && card.querySelector(".card-helper-menu")) card.querySelector(".card-helper-menu").open = true;
      const detail = card.querySelector(".runtime-error");
      if (detail && expandedErrors.has(detail.dataset.errorKey)) detail.open = true;
      if (focusKey?.id === card.dataset.sandbox) {
        const target = focusKey.warning ? card.querySelector(".restart-warning") : focusKey.summary ? card.querySelector(focusKey.summary + " summary") : card.querySelector(`[data-action="${CSS.escape(focusKey.action || "")}"]${focusKey.helper ? `[data-helper="${CSS.escape(focusKey.helper)}"]` : ""}`);
        if (target && !target.disabled) target.focus({preventScroll:true});
      }
    }
    byId("refresh-state").textContent = "Refreshed " + new Date().toLocaleTimeString();
    signedIn = true;
    byId("startup").hidden = true;
    byId("inventory-content").hidden = false;
    byId("account").hidden = false;
    byId("signin-screen").hidden = true;
    byId("app-main").hidden = false;
    sandboxLayout.update();
    badgeTooltips.afterRender();
    if (!adminView) for (const row of data.sandboxes) void checkTools(row);
  } catch (err) { error(err); } finally { refreshBusy = false; }
}
function updateProfileDescription() {
  const profile = profiles.find(p => p.id === byId("sandbox-profile").value);
  byId("profile-description").textContent = profile?.description || "";
  creationIntegrations?.dispose();
  creationIntegrations = mountIntegrationCreation(byId("create-integrations"), profile, () => { creationId = crypto.randomUUID(); });
}
byId("profile-info").onkeydown = event => {
  if (event.key !== "Escape") return;
  event.preventDefault(); event.stopPropagation(); byId("sandbox-profile").focus();
};
byId("sandbox-profile").onchange = () => {
  updateProfileDescription();
  const profile = profiles.find(p => p.id === byId("sandbox-profile").value);
  if (profile?.resources) fillResources("create", profile.resources, profile.resource_bounds);
  fillNamespaceChoices();
};
function showConfiguration(title, markup, target = null) {
  configurationTarget = target;
  byId("configuration-title").textContent = title;
  byId("configuration-content").innerHTML = markup;
  byId("configuration-dialog").showModal();
}
async function loadSandboxConfiguration(id, namespace, expectedTarget = null) {
  const path = namespace ? `/admin/sandboxes/${encodeURIComponent(id)}` : `/sandboxes/${encodeURIComponent(id)}`;
  const query = namespace ? `?namespace=${encodeURIComponent(namespace)}` : "";
  const data = await api(path + "/configuration" + query);
  if (expectedTarget && (configurationTarget !== expectedTarget || !byId("configuration-dialog").open)) return null;
  const row = sandboxRows.get(namespace ? `${namespace}/${id}` : id);
  showConfiguration("Sandbox configuration", sandboxConfiguration(data, row), {path,query,uid:data.uid,revision:data.revision,id,namespace});
  return data;
}
byId("close-configuration").onclick = () => { configurationTarget = null; byId("configuration-dialog").close(); };
byId("configuration-content").onkeydown = event => {
  if (event.key !== "Escape" || !event.target.closest("#configuration-profile-info")) return;
  event.preventDefault(); event.stopPropagation();
  byId("configuration-content").querySelector("[data-refresh-configuration]").focus();
};
byId("configuration-content").onclick = async (event) => {
  const action = event.target.closest("[data-refresh-configuration], [data-sync-configuration]");
  if (action && configurationTarget) {
    const target = configurationTarget;
    const syncing = action.hasAttribute("data-sync-configuration");
    if (syncing && !confirm("WARNING: Apply the saved configuration to this micro VM?\n\nCurrent resource settings will be overwritten. Processes may restart and terminal sessions may disconnect.\n\nYour persistent disk is retained.\n\nContinue with configuration sync?")) return;
    const controls = [...byId("configuration-content").querySelectorAll("[data-refresh-configuration], [data-sync-configuration]")];
    for (const control of controls) control.disabled = true;
    const result = byId("configuration-content").querySelector("[data-configuration-result]");
    try {
      if (syncing) await api(target.path + "/sync" + target.query, "POST", {uid:target.uid,revision:target.revision});
      if (configurationTarget === target && byId("configuration-dialog").open) {
        const data = await loadSandboxConfiguration(target.id, target.namespace, target);
        if (data) {
          const status = byId("configuration-content").querySelector("[data-configuration-result]");
          status.textContent = syncing ? data.configuration_drift ? "Sync requested. Review the remaining differences." : "Configuration is in sync." : "Status refreshed.";
          status.hidden = false;
        }
      }
      await refresh();
    } catch (err) {
      if (!err.loginRequired && configurationTarget === target) { result.textContent = err.message; result.hidden = false; }
    } finally { for (const control of controls) control.disabled = false; }
    return;
  }
  const compare = event.target.closest("[data-compare-profile]");
  if (compare) {
    const showDiff = compare.getAttribute("aria-expanded") !== "true";
    compare.setAttribute("aria-expanded", String(showDiff));
    compare.textContent = showDiff ? "Show full JSON" : "Compare with profile";
    byId("configuration-content").querySelector("[data-effective-configuration]").hidden = showDiff;
    byId("configuration-content").querySelector("[data-profile-comparison]").hidden = !showDiff;
    return;
  }
  const button = event.target.closest("[data-copy-json]");
  if (!button) return;
  await copyJson(button);
};
byId("profile-catalog").onclick = async () => {
  try {
    const data = await api("/admin/profiles");
    const selected = data.profiles.find(p => p.id === data.default) || data.profiles[0];
    showConfiguration("Profiles", `<p class="hint">Starting settings for new sandboxes. Managed by platform admins through deployment/GitOps.</p><label for="catalog-profile">Profile</label><select id="catalog-profile">${data.profiles.map(p => `<option value="${esc(p.id)}" ${p.id === selected.id ? "selected" : ""}>${esc(p.title)}${p.id === data.default ? " (default)" : ""}</option>`).join("")}</select><div id="catalog-profile-details">${profileDetails(selected)}</div>`);
    byId("catalog-profile").onchange = () => {
      const profile = data.profiles.find(p => p.id === byId("catalog-profile").value);
      byId("catalog-profile-details").innerHTML = profileDetails(profile);
    };
  } catch (err) { error(err); }
};
byId("create-form").addEventListener("input", () => { creationId = crypto.randomUUID(); byId("create-error").hidden = true; });
function fillNamespaceChoices() {
  const input = byId("sandbox-namespace");
  const profile = profiles.find(item => item.id === byId("sandbox-profile").value);
  if (profile?.acp_available) {
    input.innerHTML = '<option value="">New private namespace for this coding sandbox</option>';
    input.disabled = true;
    input.onchange();
    return;
  }
  input.innerHTML = namespaceOptions(availableNamespaces, profile?.provider, namespaceChoices, currentUser);
  if (namespaceDefault === "perUser" && input.options.length > 1) input.selectedIndex = input.options[0].value ? 0 : 1;
  input.disabled = input.options.length < 2;
  input.onchange();
}
byId("sandbox-namespace").onchange = () => {
  const selected = availableNamespaces.find(item => item.name === byId("sandbox-namespace").value);
  byId("namespace-description").textContent = selected ? `Owned by ${selected.owner}. The namespace owner and its shell collaborators can access this micro VM; you keep its lifecycle controls.` : "You own the new namespace. It is cleaned up after its last micro VM and native storage are removed.";
};
byId("create-form").onsubmit = async (event) => {
  event.preventDefault();
  const title = byId("sandbox-name").value.trim();
  if (!title) return;
  byId("create").disabled = true;
  try {
    const resources = resourceInput("create");
    const selected = byId("sandbox-profile").selectedOptions[0];
    const namespace = byId("sandbox-namespace").value;
    const privateACP = profiles.find(profile => profile.id === selected.value)?.acp_available;
    await api("/sandboxes", "POST", {title, request_id: creationId, resources, profile:selected.value, profile_revision:selected.dataset.revision, integrations:creationIntegrations?.read() || {}, namespace_strategy:privateACP ? "perSandbox" : namespace ? "perUser" : namespaceChoices.includes("perSandbox") ? "perSandbox" : "perUser", ...(namespace ? {namespace} : {})});
    creationId = crypto.randomUUID();
    byId("sandbox-name").value = "";
    byId("create-dialog").close();
    await refresh();
  } catch (err) { error(err); }
  finally { byId("create").disabled = !canManage; }
};
byId("refresh").onclick = async () => {
  byId("refresh").classList.add("refreshing");
  await refresh(); byId("refresh").classList.remove("refreshing");
};
byId("new-sandbox").onclick = async () => {
  try {
    availableNamespaces = (await api("/namespaces")).namespaces;
    creationId = crypto.randomUUID(); byId("create-error").hidden = true; byId("sandbox-profile").onchange();
    byId("create-dialog").showModal(); byId("sandbox-name").focus();
  } catch (err) { error(err); }
};
byId("cancel-create").onclick = () => byId("create-dialog").close();
byId("close-terminal").onclick = hideTerminal;
byId("terminate-terminal").onclick = () => requestTermination();
byId("retry-terminal").onclick = () => terminalSessions.get(activeSession)?.connection.retry();
byId("terminal-panel").addEventListener("cancel", (event) => { event.preventDefault(); hideTerminal(); });
const terminalPanel = byId("terminal-panel");
let backdropPress = null;
function onTerminalBackdrop(event) {
  const bounds = terminalPanel.getBoundingClientRect();
  return event.target === terminalPanel && (event.clientX > bounds.right || event.clientY > bounds.bottom || event.clientX < bounds.left || event.clientY < bounds.top);
}
terminalPanel.onpointerdown = (event) => {
  backdropPress = event.isPrimary && event.button === 0 && onTerminalBackdrop(event) ? {x:event.clientX,y:event.clientY} : null;
};
terminalPanel.onpointercancel = () => { backdropPress = null; };
terminalPanel.onclick = (event) => {
  const menu = byId("terminal-helper-menu");
  if (!menu.contains(event.target)) menu.open = false;
  const press = backdropPress; backdropPress = null;
  if (press && onTerminalBackdrop(event) && Math.hypot(event.clientX-press.x,event.clientY-press.y) <= 5) hideTerminal();
};
function searchTerminal(previous = false) {
  const session = terminalSessions.get(activeSession);
  if (!session) return;
  const query = byId("terminal-search-query").value;
  session.searchTerm = query;
  if (!query) {
    session.search.clearDecorations();
    session.terminal.clearSelection();
    byId("terminal-search-result").textContent = "";
    return;
  }
  const found = previous ? session.search.findPrevious(query) : session.search.findNext(query, {incremental:false});
  byId("terminal-search-result").textContent = found ? "Match found" : "No matches";
}
function showTerminalSearch() {
  byId("terminal-helper-menu").open = false;
  byId("terminal-search").hidden = false;
  byId("terminal-search-query").focus();
  byId("terminal-search-query").select();
}
byId("search-terminal").onclick = showTerminalSearch;
byId("terminal-search-query").oninput = () => searchTerminal();
byId("terminal-search-next").onclick = () => searchTerminal();
byId("terminal-search-previous").onclick = () => searchTerminal(true);
byId("close-terminal-search").onclick = () => {
  byId("terminal-search").hidden = true;
  terminalSessions.get(activeSession)?.terminal.focus();
};
terminalPanel.addEventListener("keydown", event => {
  if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "f") {
    event.preventDefault(); event.stopPropagation(); showTerminalSearch();
  } else if (event.key === "Escape" && byId("terminal-helper-menu").open) {
    event.preventDefault(); event.stopPropagation();
    byId("terminal-helper-menu").open = false;
    byId("terminal-helper-menu").querySelector("summary").focus();
  } else if (byId("terminal-search").contains(event.target) && ["Enter", "Escape"].includes(event.key)) {
    event.preventDefault(); event.stopPropagation();
    if (event.key === "Escape") byId("close-terminal-search").click();
    else searchTerminal(event.shiftKey);
  }
}, true);
byId("copy-terminal").onclick = async () => {
  const session = terminalSessions.get(activeSession);
  if (!session) return;
  try {
    await navigator.clipboard.writeText(terminalText(session.terminal));
    byId("terminal-tool-status").textContent = "Output copied";
    byId("terminal-tool-status").dataset.tone = "success";
  } catch {
    byId("terminal-tool-status").textContent = "Clipboard access failed. Use Download output instead.";
    byId("terminal-tool-status").dataset.tone = "error";
  }
};
byId("download-terminal").onclick = () => {
  const session = terminalSessions.get(activeSession);
  if (!session) return;
  const url = URL.createObjectURL(new Blob([terminalText(session.terminal)], {type:"text/plain;charset=utf-8"}));
  const link = document.createElement("a"); link.href = url; link.download = terminalFilename(session); link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  byId("terminal-tool-status").textContent = "Output downloaded";
  byId("terminal-tool-status").dataset.tone = "success";
};
function renderHelperActions(session = terminalSessions.get(activeSession)) {
  const row = session && sandboxRows.get(session.sandboxKey);
  const groups = row && cardHelperGroups(row.helpers, profiles.find(profile => profile.id === row.profile?.id)?.helpers);
  const helpers = groups ? [...groups.visible, ...groups.overflow] : [];
  const menu = byId("helper-actions");
  const markup = row ? helperButtons(row, helpers, h => `data-helper="${esc(h.id)}"`) : "";
  if (menu.innerHTML !== markup) {
    const focused = menu.contains(document.activeElement) ? document.activeElement.dataset.helper : null;
    menu.innerHTML = markup;
    if (focused) menu.querySelector(`[data-helper="${CSS.escape(focused)}"]`)?.focus({preventScroll:true});
  }
  byId("terminal-helper-menu").hidden = !helpers.length;
}
byId("terminal-helper-menu").ontoggle = () => {
  const session = terminalSessions.get(activeSession);
  const row = session && sandboxRows.get(session.sandboxKey);
  if (byId("terminal-helper-menu").open && row && !adminView) void checkTools(row, true);
};
byId("helper-actions").onclick = event => {
  const helper = event.target.closest("[data-helper]");
  const session = terminalSessions.get(activeSession);
  if (helper && !helper.disabled && session) openTerminal(session.id, session.namespace, null, {newSession:true, helper:helper.dataset.helper});
};
byId("new-terminal-session").onclick = () => {
  const session = terminalSessions.get(activeSession);
  if (session) openTerminal(session.id, session.namespace, null, {newSession:true});
};
async function handleAction(event) {
  const button = event.target.closest("button[data-action]");
  if (!button || button.disabled) return;
  const {action, id} = button.dataset;
  if (action === "copy-error") { await copyRuntimeError(button); return; }
  const menu = byId("admin-row-actions");
  if (action === "admin-menu") {
    const namespace = button.dataset.namespace;
    const row = sandboxRows.get(`${namespace}/${id}`);
    const pending = row?.operation;
    menu.innerHTML = `${pending ? `<button class="secondary" type="button" data-action="admin-retry" data-id="${esc(id)}" data-namespace="${esc(namespace)}">${icon("refresh")}Retry operation</button>` : ""}<button class="secondary" type="button" data-action="admin-configuration" data-id="${esc(id)}" data-namespace="${esc(namespace)}">${icon("file")}View/Sync Configuration</button>${integrationActions(row,`data-id="${esc(id)}" data-namespace="${esc(namespace)}"`)}<button class="secondary" type="button" data-action="admin-control" data-id="${esc(id)}" data-namespace="${esc(namespace)}">${icon("settings")}Controls & message</button><button class="secondary" type="button" data-action="admin-namespace-lock" data-id="${esc(id)}" data-namespace="${esc(namespace)}" title="${row?.namespace_locked ? "Allow namespace reuse" : "Prevent anyone creating new sandboxes here; existing micro VMs keep running"}">${icon(row?.namespace_locked ? "unlock" : "lock")}${row?.namespace_locked ? "Unlock namespace" : "Lock namespace"}</button>`;
    menu.showPopover();
    const rect = button.getBoundingClientRect();
    menu.style.left = Math.max(8, Math.min(rect.right - menu.offsetWidth, innerWidth - menu.offsetWidth - 8)) + "px";
    menu.style.top = (rect.bottom + 6 + menu.offsetHeight <= innerHeight ? rect.bottom + 6 : Math.max(8, rect.top - menu.offsetHeight - 6)) + "px";
    menu.querySelector("button").focus();
    return;
  }
  if (button.closest("[popover]")) menu.hidePopover();
  if (["integration-panel", "network-security"].includes(action)) {
    const namespace = button.dataset.namespace;
    const row = sandboxRows.get(namespace ? `${namespace}/${id}` : id);
    const path = `${namespace ? "/admin" : ""}/sandboxes/${encodeURIComponent(id)}`;
    const query = namespace ? `?namespace=${encodeURIComponent(namespace)}` : "";
    const requestFor = panel => {
      const admin = namespace || (currentRole==="admin" && row.control_panels?.some(item=>item.id===panel && item.admin_only));
      const panelPath = admin ? `/admin/sandboxes/${encodeURIComponent(id)}` : path;
      const panelQuery = admin ? `?namespace=${encodeURIComponent(row.namespace)}` : "";
      const target = `${panelPath}/integrations/${encodeURIComponent(panel)}${panelQuery}`;
      return {
        read: () => api(target),
        apply: body => api(target, "PUT", body),
        retry: () => api(path + "/retry" + query + (namespace ? "&uid=" + encodeURIComponent(row.uid) : ""), "POST"),
      };
    };
    try {
      if(action === "network-security") await openSecurityPanel(byId("integration-dialog"),requestFor,row);
      else await openIntegrationPanel(button.dataset.panel,byId("integration-dialog"),requestFor(button.dataset.panel),row);
    } catch (err) { error(err); }
    return;
  }
  if (action === "configuration" || action === "admin-configuration") {
    const namespace = button.dataset.namespace;
    try {
      await loadSandboxConfiguration(id, namespace);
    } catch (err) { error(err); }
    return;
  }
  if (action === "acp-connection") {
    try { showConfiguration("Connect this sandbox to CAIPE", acpConnectionView(await api(`/sandboxes/${encodeURIComponent(id)}/acp`))); }
    catch (err) { error(err); }
    return;
  }
  if (action === "workspace") {
    const row = sandboxRows.get(id);
    if (!row) return;
    const target = `/sandboxes/${encodeURIComponent(id)}/workspace?uid=${encodeURIComponent(row.uid)}`;
    await openWorkspace(byId("workspace-dialog"), body => api(target, body ? "POST" : "GET", body), row);
    return;
  }
  if (action === "helper") {
    openTerminal(id, null, null, {newSession:true, helper:button.dataset.helper});
    return;
  }
  if (action === "notice") { showMessage(sandboxRows.get(id)?.admin_control?.notice); return; }
  if (action.startsWith("admin-")) {
    const namespace = button.dataset.namespace;
    const key = `${namespace}/${id}`, row = sandboxRows.get(key);
    if (!row) { error(new Error("Sandbox is no longer in the inventory. Refresh and try again.")); return; }
    if (action === "admin-namespace-lock") {
      button.disabled = true;
      try { await api(`/admin/namespaces/${encodeURIComponent(row.namespace_key)}`, "PUT", {resource_version:adminControls.resource_version,locked:!row.namespace_locked}); }
      catch (err) { error(err); }
      finally { await refresh(); }
      return;
    }
    if (action === "admin-terminal") { openTerminal(id, namespace); return; }
    if (action === "admin-retry") {
      try { await api(`/admin/sandboxes/${encodeURIComponent(id)}/retry?namespace=${encodeURIComponent(namespace)}&uid=${encodeURIComponent(row.uid)}`, "POST"); }
      catch (err) { error(err); } finally { await refresh(); } return;
    }
    if (action === "admin-control") {
      editingSandbox = structuredClone(row);
      byId("admin-sandbox-title").textContent = row.title;
      byId("admin-sandbox-owner").textContent = `${row.owner || "Unassigned"} · ${row.namespace}`;
      byId("sandbox-scope-restriction").hidden = !row.disabled || row.admin_control.disabled;
      byId("sandbox-scope-restriction").textContent = "A global or user restriction also blocks access: " + row.disabled_reason + ". Clear all applicable restrictions before resuming.";
      byId("sandbox-disabled").checked = row.admin_control.disabled;
      byId("sandbox-control-reason").value = row.admin_control.reason;
      fillNotice("sandbox", row.admin_control.notice);
      byId("admin-sandbox-error").hidden = true; byId("admin-sandbox-dialog").showModal(); return;
    }
    if (action === "admin-user") { openUserPolicy(row.owner); return; }
    if (["admin-suspend", "admin-resume"].includes(action)) {
      if (action === "admin-suspend" && !confirm(`Suspend ${row.title}? Running agents and processes stop; storage is retained.`)) return;
      try { await api(`/admin/sandboxes/${encodeURIComponent(id)}/control?namespace=${encodeURIComponent(namespace)}&uid=${encodeURIComponent(row.uid)}`, "PUT", {resource_version:row.resource_version,operating_mode:action === "admin-suspend" ? "Suspended" : "Running"}); }
      catch (err) { error(err); } finally { await refresh(); } return;
    }
    if (!confirm(failedCreation(row) ? deletionConfirmation(row) : `Delete ${row.title} in ${namespace}, owned by ${row.owner || "an unassigned owner"}? This stops its processes and deletes its persistent disk claim. Retained disks follow the storage policy; external controllers may recreate managed sandboxes.`)) return;
    button.disabled = true;
    try {
      const result = await api(`/admin/sandboxes/${encodeURIComponent(id)}?namespace=${encodeURIComponent(namespace)}&uid=${encodeURIComponent(row.uid)}`, "DELETE");
      if (result.namespace_cleanup === "failed") error(new Error("Sandbox deletion started, but namespace cleanup failed. Check platform logs."));
      closeSandboxTerminals(key);
    } catch (err) { error(err); } finally { button.disabled = false; await refresh(); }
    return;
  }
  button.closest(".card-menu")?.removeAttribute("open");
  if (action === "sharing") {
    const sandbox = sandboxRows.get(id);
    sharingId = id; sharingMembers = {...sandbox.sharing}; sharingRevision = Number(sandbox.resource_version);
    byId("sharing-sandbox").textContent = sandbox.title;
    const siblings = [...sandboxRows.values()].filter(row => row.namespace_key === sandbox.namespace_key);
    byId("sharing-namespace").textContent = sandbox.namespace;
    byId("sharing-scope-description").textContent = `Access covers all ${siblings.length} micro VM${siblings.length === 1 ? "" : "s"} currently in this namespace and any created here later. Removing a collaborator revokes shared access; creators keep access to their own micro VMs.`;
    byId("sharing-scope-members").textContent = siblings.map(row => row.title).join(" · ");
    byId("sharing-email").value = ""; byId("sharing-error").hidden = true;
    const link = location.origin + base + "/?owner=" + encodeURIComponent(sandbox.namespace_owner || sandbox.owner);
    byId("sharing-link").href = link; byId("sharing-link").textContent = link;
    renderSharing(); byId("sharing-dialog").showModal();
    return;
  }
  if (action === "resources") {
    const sandbox = sandboxRows.get(id);
    editingId = id;
    byId("resource-sandbox").textContent = sandbox.title;
    byId("resource-error").hidden = true;
    const available = fillResources("edit", sandbox.allocation, sandbox.resource_bounds);
    byId("save-resources").disabled = !available;
    if (!available) {
      byId("resource-error").textContent = "This profile has no resource choices within the current platform policy. Contact an administrator.";
      byId("resource-error").hidden = false;
    }
    byId("resource-dialog").showModal();
    return;
  }
  if (action === "terminal") { openTerminal(id); return; }
  if (action === "delete" && !confirm(deletionConfirmation(sandboxRows.get(id)))) return;
  if (action === "suspend" && button.id !== "confirm-power") {
    byId("power-name").textContent = sandboxRows.get(id).title;
    byId("confirm-power").dataset.action = "suspend";
    byId("confirm-power").dataset.id = id;
    byId("power-dialog").showModal();
    return;
  }
  if (button.id === "confirm-power") byId("power-dialog").close();
  busy.add(id); button.disabled = true;
  const card = document.querySelector(`[data-sandbox="${CSS.escape(id)}"]`);
  if (card && ["resume","suspend"].includes(action)) {
    card.classList.add("switching");
    card.querySelector(".power-button").disabled = true;
    const status = card.querySelector("[data-status-message]");
    if (status) status.textContent = action === "resume" ? "Powering on…" : "Powering off…";
  }
  try {
    const result = await api(`/sandboxes/${encodeURIComponent(id)}${action === "delete" ? "" : "/" + action}`, action === "delete" ? "DELETE" : "POST");
    if (result.namespace_cleanup === "failed") error(new Error("Sandbox deletion started, but empty namespace cleanup failed. Contact platform support."));
    closeSandboxTerminals(id);
  } catch (err) { error(err); } finally { busy.delete(id); button.disabled = false; await refresh(); }
}
byId("sandboxes").onclick = handleAction;
byId("admin-row-actions").onclick = handleAction;
document.addEventListener("click", event => {
  for (const menu of document.querySelectorAll(".card-menu[open]")) if (!menu.contains(event.target)) menu.open = false;
});
document.addEventListener("keydown", event => {
  if (event.key === "Escape") for (const menu of document.querySelectorAll(".card-menu[open]")) { menu.open = false; menu.querySelector("summary").focus(); }
});
byId("confirm-power").onclick = handleAction;
byId("cancel-power").onclick = () => byId("power-dialog").close();
function renderSharing() {
  byId("sharing-members").innerHTML = Object.entries(sharingMembers).map(([email, access]) => `<p>${esc(email)} — ${access === "shell" ? "View and shell" : "View status"} <button class="secondary" type="button" data-remove="${esc(email)}">Remove</button></p>`).join("") || "<p>No shared access yet.</p>";
}
byId("sharing-members").onclick = event => {
  const button = event.target.closest("button[data-remove]");
  if (button) { delete sharingMembers[button.dataset.remove]; renderSharing(); }
};
byId("add-collaborator").onclick = () => {
  const input = byId("sharing-email");
  if (!input.value || !input.reportValidity()) return;
  sharingMembers[input.value.trim().toLowerCase()] = byId("sharing-access").value;
  input.value = ""; renderSharing();
};
byId("cancel-sharing").onclick = () => byId("sharing-dialog").close();
byId("sharing-form").onsubmit = async event => {
  event.preventDefault();
  byId("save-sharing").disabled = true;
  try {
    if (byId("sharing-email").value.trim()) throw new Error("Click Add collaborator before saving");
    await api(`/sandboxes/${encodeURIComponent(sharingId)}/sharing`, "PUT", {members: sharingMembers, revision:sharingRevision});
    byId("sharing-dialog").close(); await refresh();
  } catch (err) {
    byId("sharing-error").hidden = false; byId("sharing-error").textContent = err.message;
  } finally { byId("save-sharing").disabled = false; }
};
byId("cancel-resources").onclick = () => byId("resource-dialog").close();
byId("resource-form").onsubmit = async (event) => {
  event.preventDefault();
  const id = editingId;
  byId("save-resources").disabled = true;
  busy.add(id);
  try {
    await api(`/sandboxes/${encodeURIComponent(id)}/resources`, "PUT", resourceInput("edit"));
    if (editingId === id) byId("resource-dialog").close();
    await refresh();
  } catch (err) {
    byId("resource-error").hidden = false; byId("resource-error").textContent = err.message;
  } finally { busy.delete(id); byId("save-resources").disabled = false; }
};
setInterval(async () => {
  if (!signedIn) return;
  await refresh();
}, 4000);
window.addEventListener("pagehide", closeAllTerminals);
async function start() {
  inventoryNavigation.initialize();
  byId("startup-message").textContent = "Loading your sandboxes…";
  byId("startup-retry").hidden = true;
  try {
    const response = await fetch(base + "/auth/config", {credentials: "same-origin"});
    if ([401,403].includes(response.status)) {
      byId("sso-signin").hidden = true;
      showSignin("Your host session is unavailable or access was denied. Reopen Sandbox from the host application to continue.");
      return;
    }
    if (!response.ok) throw new Error("Portal login configuration is unavailable");
    const auth = authConfig = await response.json();
    const links = byId("header-links");
    links.replaceChildren(...(auth.header_links || []).map(({title, url}) => {
      const link = document.createElement("a");
      link.textContent = title; link.href = url;
      link.target = "_blank"; link.rel = "noopener noreferrer";
      link.insertAdjacentHTML("beforeend", icon("external"));
      link.title = "Opens in a new tab";
      return link;
    }));
    links.hidden = !links.childElementCount;
    document.body.classList.toggle("embedded", Boolean(auth.embedded));
    if (auth.login_url) {
      const login = new URL(auth.login_url, location.origin);
      if (sharedOwner) {
        if (auth.mode === "oidc") login.searchParams.set("owner", sharedOwner);
        else login.searchParams.set("return_to", base + "/" + scope);
      }
      loginUrl = login.pathname + login.search;
    }
    byId("sso-signin").hidden = !auth.login_url;
    byId("sso-signin").disabled = !auth.login_url;
    byId("sign-out").hidden = auth.mode !== "oidc";
    await refresh();
  } catch (err) { error(err); }
}
byId("sign-out").onclick = async () => {
  closeAllTerminals();
  try {
    const response = await fetch(base + "/auth/logout", {method: "POST", credentials: "same-origin"});
    if (!response.ok) throw new Error("Sign-out failed");
    location.href = base + "/";
  } catch (err) { error(err); }
};
byId("startup-retry").onclick = start;
start();
