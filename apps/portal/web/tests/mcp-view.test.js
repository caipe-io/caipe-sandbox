import test from "node:test";
import assert from "node:assert/strict";
import {mcpAction, mcpEnabledRow, mcpDialogContent, openMCP} from "../mcp-view.js";

const row = {id:"calm-otter",portal_id:"immutable-sandbox-id",title:"Engineering",mcp:{enabled:false}};
const configuration = {enabled:true,resource_url:"https://sandbox.example.com/api/mcp",docs_url:"https://docs.example.com/mcp"};

test("MCP action needs opt-in availability and owner/admin permission; global opt-out still permits disabling", () => {
  assert.match(mcpAction(row,configuration,true),/Enable MCP/);
  assert.equal(mcpAction(row,configuration,false),"");
  assert.equal(mcpAction(row,{enabled:false},true),"");
  assert.match(mcpAction({...row,mcp:{enabled:true}},{enabled:false},true),/Disable MCP/);
});

test("confirmation identifies capabilities, immutable sandbox ID and authenticated connection", () => {
  const html = mcpDialogContent(row,configuration,false);
  assert.match(html,/authenticated agents/);
  assert.match(html,/reading and changing files/);
  assert.match(html,/immutable-sandbox-id/);
  assert.match(html,/https:\/\/sandbox.example.com\/api\/mcp/);
  assert.match(html,/data-mcp-confirm>Enable MCP/);
  assert.match(html,/Connect your agent with MCP/);
  assert.match(html,/rel="noopener noreferrer"/);
  assert.match(html,/aria-label="Copy sandbox ID"/);
  assert.match(html,/aria-label="Copy server URL"/);
});

test("enabled badge opens details only when both the service and sandbox are enabled", () => {
  assert.equal(mcpEnabledRow(row,configuration),"");
  const enabled = {...row,mcp:{enabled:true}};
  assert.match(mcpEnabledRow(enabled,configuration),/MCP Enabled/);
  assert.match(mcpEnabledRow(enabled,configuration),/data-action="mcp"/);
  assert.match(mcpEnabledRow(enabled,configuration),/aria-haspopup="dialog"/);
  assert.doesNotMatch(mcpEnabledRow(enabled,configuration),/<svg|<img/);
  assert.equal(mcpEnabledRow(enabled,{enabled:false}),"");
});

test("confirmed MCP changes close the modal immediately after saving", async () => {
  for (const enabled of [false,true]) {
    const confirm = {}, error = {};
    const dialog = {open:false,querySelectorAll:()=>[],querySelector:selector=>selector==="[data-mcp-confirm]" ? confirm : error,
      showModal(){this.open=true;},close(){this.open=false;}};
    const sandbox = {...row,mcp:{enabled},revision:4};
    let refreshed = false;
    openMCP(dialog,sandbox,configuration,async body=>{
      assert.deepEqual(body,{revision:4,mcp:{enabled:!enabled}});
      return {revision:5,mcp:{enabled:!enabled}};
    },async()=>{assert.equal(dialog.open,false);refreshed=true;});
    await confirm.onclick({currentTarget:confirm});
    assert.equal(dialog.open,false);
    assert.equal(sandbox.mcp.enabled,!enabled);
    assert.ok(refreshed);
  }
});

test("shared users can view and copy connection details without changing access", () => {
  const html = mcpDialogContent({...row,mcp:{enabled:true}},configuration,true,false);
  assert.match(html,/>MCP access</);
  assert.match(html,/Copy sandbox ID/);
  assert.match(html,/Copy server URL/);
  assert.match(html,/>Done<\/button>/);
  assert.doesNotMatch(html,/data-mcp-confirm|Disable MCP|Enable MCP|data-mcp-disable-note/);
});

test("a late save never replaces connection details for a different sandbox", async () => {
  const heading = {textContent:"Second sandbox"}, confirm = {}, error = {};
  const dialog = {open:false, querySelectorAll:()=>[],
    querySelector: selector => selector === "[data-mcp-confirm]" ? confirm : selector === "[data-mcp-error]" ? error : heading,
    showModal(){this.open=true;}};
  let finish, refreshes = 0;
  openMCP(dialog,{...row},configuration,()=>new Promise(resolve=>finish=resolve),async()=>{refreshes++;});
  const saving = confirm.onclick({currentTarget:confirm});
  openMCP(dialog,{...row,portal_id:"second-sandbox-id"},configuration,async()=>{},async()=>{});
  finish({mcp:{enabled:true},revision:2});
  await saving;
  assert.equal(heading.textContent,"Second sandbox");
  assert.equal(refreshes,1);
});

test("disabling explains uncertain command termination and all display data is escaped", () => {
  const html = mcpDialogContent({...row,title:'<script>bad</script>',portal_id:'" onfocus="bad'},configuration,true);
  assert.match(html,/not guaranteed to have stopped/);
  assert.match(html,/&lt;script&gt;/);
  assert.doesNotMatch(html,/<script>|value="" onfocus=/);
  assert.match(html,/data-mcp-confirm>Disable MCP/);
});
