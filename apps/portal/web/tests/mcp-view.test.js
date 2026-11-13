import test from "node:test";
import assert from "node:assert/strict";
import {mcpAction, mcpDialogContent} from "../mcp-view.js";

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
});

test("disabling explains uncertain command termination and all display data is escaped", () => {
  const html = mcpDialogContent({...row,title:'<script>bad</script>',portal_id:'" onfocus="bad'},configuration,true);
  assert.match(html,/not guaranteed to have stopped/);
  assert.match(html,/&lt;script&gt;/);
  assert.doesNotMatch(html,/<script>|value="" onfocus=/);
  assert.match(html,/data-mcp-confirm>Disable MCP/);
});
