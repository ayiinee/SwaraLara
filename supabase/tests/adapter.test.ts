import {test} from "node:test";
import assert from "node:assert/strict";
import {startContractServer} from "./contract-server.ts";
import {supabasePorts} from "../functions/api/supabase-adapter.ts";

test("Supabase adapter verifies JWT through Auth and transports real RPC/Storage over HTTP",async()=>{
 const f=await startContractServer();
 try{
  const valid=f.issue(f.owner.userId).access_token;
  const ports=supabasePorts(f.origin,f.key,"not-a-service-secret");
  assert.equal((await ports.auth.getUser(valid))?.id,f.owner.userId);
  assert.equal(await ports.auth.getUser(valid.slice(0,-2)+"xx"),null);
  const expired=f.issue(f.owner.userId,-1).access_token;assert.equal(await ports.auth.getUser(expired),null);
  await assert.rejects(ports.db.call(f.owner.userId,"devices"));
  const publicResponse=await fetch(`${f.origin}/functions/v1/api/bootstrap`,{method:"POST",headers:{authorization:`Bearer ${valid}`,"content-type":"application/json"},body:JSON.stringify({displayName:"Network test"})});
  assert.equal(publicResponse.status,200);
 }finally{await f.close();}
});
