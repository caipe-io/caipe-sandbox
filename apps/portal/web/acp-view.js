import { jsonBlock } from "./json-view.js";

const esc = value => String(value ?? "").replace(/[&<>"']/g, char => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[char]));

export function acpConnectionView(data) {
  const admitted = data.connections.filter(item => item.admitted);
  const status = !admitted.length ? "Operator registration needed" : admitted.some(item => item.busy) ? "Active or awaiting reconciliation" : data.state === "Suspended" ? "Resume this sandbox to connect" : data.state !== "Running" ? "Waiting for sandbox readiness" : "Registered sandbox connection";
  return `<p><strong>${esc(status)}</strong></p><p>${esc(data.message)}</p>
    <ol><li>Create this sandbox with the approved Claude coding profile, then open <strong>Connect to CAIPE</strong>. Its reference is available while model setup is pending.</li>
    <li>An operator completes model access in this sandbox's namespace and registers its identity with your verified CAIPE account. This PoC does not copy credentials through the browser.</li>
    <li>Wait for <strong>Running</strong> and the registered connection. Setup errors remain visible on the sandbox card.</li>
    <li>In CAIPE Agent Builder choose <strong>Claude (ACP)</strong>, then your <strong>sandbox operator profile</strong>. Write agent instructions, select permitted MCP tools and start one new conversation on first use. Thereafter, reopen the assigned conversation below.</li></ol>
    <p class="hint">${esc(data.model_access_note || "Your operator configures and verifies the approved model route before use.")}</p>
    ${data.connections.length ? `<table><thead><tr><th>Connection</th><th>State</th><th>Conversation</th></tr></thead><tbody>${data.connections.map(item => `<tr><td>${esc(item.title)}<br><code>${esc(item.id)}</code></td><td>${item.admitted ? item.busy ? "Active or unconfirmed" : "Registered" : "Configuration changed; ask an operator"}</td><td>${esc(item.bound_conversation || "Assigned on first use")}</td></tr>`).join("")}</tbody></table>` : ""}
    <h3>Manage the environment here</h3><p>Your operator configures model access for this coding profile. Use <strong>Open terminal</strong> to inspect files and native tools, and <strong>View/Sync Configuration</strong> to inspect the saved setup. Platform admins manage profile, mount and network restrictions through deployment policy; available runtime policy panels show their own supported controls. A configuration revision identifies approved settings, not a live policy-enforcement attestation.</p>
    <p>Open the listed conversation from CAIPE history to continue it. A new conversation needs another sandbox. Stop the CAIPE run before suspending or changing this environment; an unconfirmed process requires operator reconciliation. Its persistent disk retains native session files. Deleting the sandbox can remove that state and does not retry an interrupted run. Transcript sharing does not share its shell.</p>
    <p>Selected GitHub MCP tools use your connected CAIPE account. Native <code>git</code> and SSH need a separate approved credential path; they do not inherit connector or service credentials. This minimal image includes Git/SSH and does not include <code>gh</code>.</p>
    <details><summary>Connection registration reference</summary><p>Send this nonsecret reference to your operator. They configure the private data-plane trust and map your CAIPE subject server side.</p>${jsonBlock(data.registration)}</details>
    <p class="hint">${esc(data.policy_note)}</p>`;
}
