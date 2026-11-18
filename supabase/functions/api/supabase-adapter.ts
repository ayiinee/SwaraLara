import {createClient} from "@supabase/supabase-js";
import {ApiError,demand} from "./protocol.ts";
import type {Auth,Database,Storage} from "./router.ts";

export function supabasePorts(url:string,publishable:string,serviceSecret:string,publicUrl=url):{auth:Auth,db:Database,storage:Storage}{
 const options={auth:{persistSession:false,autoRefreshToken:false,detectSessionInUrl:false}};
 const authClient=createClient(url,publishable,options),admin=createClient(url,serviceSecret,options);
 const bucket=admin.storage.from("swl-recordings");
 const publicSigned=(signed:string)=>{
  const internal=new URL(url),target=new URL(signed);demand(target.origin===internal.origin,"SIGNED_URL_ORIGIN",500);
  const external=new URL(publicUrl);target.protocol=external.protocol;target.host=external.host;return target.toString();
 };
 return {
  auth:{async getUser(token){const {data,error}=await authClient.auth.getUser(token);return error?null:data.user?{id:data.user.id}:null;}},
  db:{async call(actor,action,p={}){
   const {data,error}=await admin.rpc("swl_m2",{p_actor:actor,p_action:action,p});
   if(error){const known:Record<string,number>={NOT_FOUND:404,CONFLICT:409,INVALID:422,EXPIRED:410,FINGERPRINT_CHANGED:409,UNAUTHENTICATED:401};
    if(error.message in known)throw new ApiError(known[error.message],error.message);throw new ApiError(500,"DATABASE_UNAVAILABLE");}
   return data;
  }},
  storage:{
   async signUpload(path){const {data,error}=await bucket.createSignedUploadUrl(path,{upsert:false});
    if(error)throw new ApiError(503,"STORAGE_UNAVAILABLE");return publicSigned(data.signedUrl);},
   async read(path){const {data,error}=await bucket.download(path);
    if(error){if(String(error.statusCode)==="404"||String(error.statusCode)==="400")return null;throw new ApiError(503,"STORAGE_UNAVAILABLE");}
    demand(data.size<=384098,"OBJECT_TOO_LARGE",422);return new Uint8Array(await data.arrayBuffer());},
   async signRead(path){const {data,error}=await bucket.createSignedUrl(path,60);if(error)throw new ApiError(503,"STORAGE_UNAVAILABLE");return publicSigned(data.signedUrl);}
  }
 };
}
