import {generateKeyPairSync,sign,randomBytes,createCipheriv,createHash} from "node:crypto";
import {b64,sha,deviceProof,trustProof,policyBytes,uuidBytes} from "../functions/api/protocol.ts";

export async function identity(userId=crypto.randomUUID()) {
 const id=crypto.randomUUID();const signing=generateKeyPairSync("ec",{namedCurve:"prime256v1"});
 const spki=new Uint8Array(signing.publicKey.export({type:"spki",format:"der"}));
 const x=generateKeyPairSync("x25519").publicKey.export({format:"jwk"}).x!;
 const raw=Buffer.from(x,"base64url");const hpkeValue=Buffer.concat([Buffer.from([0x12,6,8,1,16,1,24,2,0x1a,32]),raw]);
 const hpke=new TextEncoder().encode(JSON.stringify({primaryKeyId:1,key:[{keyData:{typeUrl:"type.googleapis.com/google.crypto.tink.HpkePublicKey",keyMaterialType:"ASYMMETRIC_PUBLIC",value:b64(hpkeValue)},status:"ENABLED",keyId:1,outputPrefixType:"TINK"}]}));
 const signature=(payload:Uint8Array)=>b64(sign("sha256",payload,signing.privateKey));
 const data={id,label:"Simulated device",hpkePublicKeysetBase64:b64(hpke),signingPublicSpkiBase64:b64(spki),proofSignatureBase64:signature(await deviceProof(id,hpke,spki))};
 return {id,userId,data,signature,hpkeFingerprint:await sha(hpke),signingFingerprint:await sha(spki)};
}
export function registration(owner:any,holder:any,id=crypto.randomUUID()) {
 const members=[owner,holder].map((d,i)=>({shareIndex:i+1,userId:d.userId,deviceId:d.id,hpkeFingerprint:d.hpkeFingerprint,signingFingerprint:d.signingFingerprint}));
 const policy=policyBytes({id,ownerUserId:owner.userId,sourceDeviceId:owner.id,policyCode:"owner_required_2of2",members});
 return {id,sourceDeviceId:owner.id,kind:"retrospective",policyCode:"owner_required_2of2",sampleRate:16000,channels:1,pcmEncoding:"pcm16le",startedAtDevice:"2026-11-18T00:00:00Z",captureState:"sealed",totalSegments:2,totalSamples:11,policySnapshotBase64:b64(policy),policySignatureBase64:owner.signature(policy)};
}
export function encryptedObjects(id:string) {
 const key=randomBytes(32),prefix=randomBytes(8);let previous=Buffer.alloc(32);
 const result=[8,3].map((frames,index)=>{
  const h=Buffer.alloc(82);h.write("SWL1");h.set(uuidBytes(id),4);h.writeUInt32BE(index,20);h.writeUInt32BE(16000,24);h[28]=1;h[29]=1;
  h.writeUInt32BE(frames,30);h.set(prefix,34);h.writeUInt32BE(index,42);h.set(previous,46);h.writeUInt32BE(frames*2+16,78);
  const c=createCipheriv("aes-256-gcm",key,h.subarray(34,46));c.setAAD(h);
  const bytes=Buffer.concat([h,c.update(Buffer.alloc(frames*2)),c.final(),c.getAuthTag()]);
  previous=createHash("sha256").update(bytes).digest();return {bytes,hash:previous.toString("hex"),index};
 });key.fill(0);return result;
}
export async function seedThroughApi(db:any,ports:any) {
 const [owner,holder,other]=await Promise.all([identity(),identity(),identity()]);
 for(const d of [owner,holder,other]){
  await db.query("insert into auth.users values($1)",[d.userId]);ports.users.set(d.userId,d.userId);
  const a=await ports.request(d.userId,"/bootstrap","POST",{displayName:"Test user"});if(a.status!==200)throw Error(JSON.stringify(a));
  const r=await ports.request(d.userId,"/devices","POST",d.data);if(r.status!==200)throw Error(JSON.stringify(r));
 }
 const invite=await ports.request(owner.userId,"/trust/invitations","POST",{deviceId:owner.id});
 const accepted=await ports.request(holder.userId,"/trust/accept","POST",{deviceId:holder.id,token:invite.data.token});
 const link=accepted.data;
 for(const d of [owner,holder]){const r=await ports.request(d.userId,`/trust/${link.id}/confirm`,"POST",{deviceId:d.id,signatureBase64:d.signature(trustProof(link.id,d.id))});if(r.status!==200)throw Error(JSON.stringify(r));}
 return {owner,holder,other,link};
}
