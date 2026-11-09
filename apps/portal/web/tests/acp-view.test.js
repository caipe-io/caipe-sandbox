import test from "node:test";
import assert from "node:assert/strict";
import { acpConnectionView } from "../acp-view.js";

const base = {connections:[],state:"Running",message:"Ask an operator",registration:{sandbox_uid:"uid"},policy_note:"Configuration identity"};

test("registration is explicit and contains no credential form", () => {
  const html = acpConnectionView(base);
  assert.match(html,/Operator registration needed/);
  assert.match(html,/Claude \(ACP\)/);
  assert.match(html,/agent instructions/);
  assert.match(html,/while model setup is pending/);
  assert.match(html,/operator completes model access/);
  assert.match(html,/do not inherit connector or service credentials/);
  assert.match(html,/network restrictions through deployment policy/);
  assert.doesNotMatch(html,/<input|password|Bearer/);
});

test("busy, changed and owner-visible bound conversation are clear and escaped", () => {
  const html = acpConnectionView({...base, connections:[{id:"primary",title:"<script>",admitted:true,busy:true,bound_conversation:"conversation"}]});
  assert.match(html,/Active or awaiting reconciliation/);
  assert.match(html,/conversation/);
  assert.match(html,/&lt;script&gt;/);
  assert.doesNotMatch(html,/<script>/);
});
