alter table public.recording_segments add column nonce_prefix text not null check (nonce_prefix ~ '^[0-9a-f]{16}$');
-- The only product RPC; execute is server-only. Every action checks the verified actor again.
create function public.swl_m2(p_actor uuid,p_action text,p jsonb default '{}') returns jsonb
language plpgsql security definer set search_path=public,pg_temp as $$
declare d public.devices; r public.recordings; s public.recording_segments; inv public.trust_invitations;
 l public.trusted_links; m jsonb; n int; frames bigint; hits int; bucket timestamptz; result jsonb;
begin
 if p_actor is null then raise exception 'UNAUTHENTICATED'; end if;
 if p_action='rate' then
  if p->>'operation' not in ('invitation','accept','upload','read','recording','device') then raise exception 'INVALID'; end if;
  bucket:=date_trunc('minute',clock_timestamp());
  insert into api_rate_limits values(p_actor,p->>'operation',bucket,1)
   on conflict(actor_id,operation,window_start) do update set hits=api_rate_limits.hits+1 returning api_rate_limits.hits into hits;
  return jsonb_build_object('allowed',hits<=case when p->>'operation' in ('invitation','accept','device') then 10 else 60 end);
 elsif p_action='bootstrap' then
  insert into profiles(id,display_name) values(p_actor,p->>'displayName') on conflict(id) do nothing;
  return (select to_jsonb(x) from profiles x where id=p_actor);
 elsif p_action='device' then
  select * into d from devices where id=(p->>'id')::uuid and user_id=p_actor and state='active';
  if not found then raise exception 'NOT_FOUND'; end if;
  return to_jsonb(d)||jsonb_build_object('signingBase64',encode(d.signing_public_spki,'base64'));
 elsif p_action='devices' then
  return coalesce((select jsonb_agg(to_jsonb(x)-'hpke_public_keyset'-'signing_public_spki') from devices x where user_id=p_actor),'[]');
 elsif p_action='device_create' then
  select * into d from devices where id=(p->>'id')::uuid;
  if found then
   if d.user_id<>p_actor then raise exception 'NOT_FOUND'; end if;
   if d.hpke_fingerprint<>p->>'hpkeFingerprint' or d.signing_fingerprint<>p->>'signingFingerprint' then raise exception 'CONFLICT'; end if;
   if d.state<>'active' then raise exception 'CONFLICT'; end if;
  else
   insert into devices(id,user_id,label,hpke_public_keyset,hpke_fingerprint,signing_public_spki,signing_fingerprint)
   values((p->>'id')::uuid,p_actor,p->>'label',decode(p->>'hpkePublicKeysetBase64','base64'),p->>'hpkeFingerprint',
    decode(p->>'signingPublicSpkiBase64','base64'),p->>'signingFingerprint') returning * into d;
  end if;
  return to_jsonb(d)-'hpke_public_keyset'-'signing_public_spki';
 elsif p_action='invite' then
  perform 1 from devices where id=(p->>'deviceId')::uuid and user_id=p_actor and state='active';
  if not found then raise exception 'NOT_FOUND'; end if;
  insert into trust_invitations(id,owner_user_id,owner_device_id,token_hash,expires_at)
   values((p->>'id')::uuid,p_actor,(p->>'deviceId')::uuid,p->>'tokenHash',clock_timestamp()+interval '15 minutes');
  return jsonb_build_object('id',p->>'id','expiresAt',(select expires_at from trust_invitations where id=(p->>'id')::uuid));
 elsif p_action='accept' then
  select * into inv from trust_invitations where token_hash=p->>'tokenHash' for update;
  if not found then raise exception 'NOT_FOUND'; end if;
  if inv.expires_at<=clock_timestamp() then raise exception 'EXPIRED'; end if;
  if inv.consumed_at is not null then raise exception 'CONFLICT'; end if;
  if inv.owner_user_id=p_actor then raise exception 'INVALID'; end if;
  perform 1 from devices where id=(p->>'deviceId')::uuid and user_id=p_actor and state='active';
  if not found then raise exception 'NOT_FOUND'; end if;
  perform 1 from devices where id=inv.owner_device_id and state='active';
  if not found then raise exception 'NOT_FOUND'; end if;
  insert into trusted_links(id,owner_user_id,holder_user_id,owner_device_id,holder_device_id)
   values((p->>'linkId')::uuid,inv.owner_user_id,p_actor,inv.owner_device_id,(p->>'deviceId')::uuid) returning * into l;
  update trust_invitations set accepted_by_user_id=p_actor,accepted_device_id=l.holder_device_id,consumed_at=clock_timestamp() where id=inv.id;
  return to_jsonb(l);
 elsif p_action in ('trust','link','confirm') then
  if p_action='trust' then
   return coalesce((select jsonb_agg(to_jsonb(t)||jsonb_build_object('ownerDevice',to_jsonb(a)-'hpke_public_keyset'-'signing_public_spki',
    'holderDevice',to_jsonb(b)-'hpke_public_keyset'-'signing_public_spki')) from trusted_links t join devices a on a.id=t.owner_device_id
    join devices b on b.id=t.holder_device_id where t.owner_user_id=p_actor or t.holder_user_id=p_actor),'[]');
  end if;
  select * into l from trusted_links where id=(p->>'id')::uuid and (owner_user_id=p_actor or holder_user_id=p_actor) for update;
  if not found then raise exception 'NOT_FOUND'; end if;
  if p_action='confirm' then
   if l.state='revoked' then raise exception 'CONFLICT'; end if;
   if p_actor=l.owner_user_id and (p->>'deviceId')::uuid=l.owner_device_id then l.owner_confirmed:=true;
   elsif p_actor=l.holder_user_id and (p->>'deviceId')::uuid=l.holder_device_id then l.holder_confirmed:=true;
   else raise exception 'NOT_FOUND'; end if;
   update trusted_links set owner_confirmed=l.owner_confirmed,holder_confirmed=l.holder_confirmed,
    state=case when l.owner_confirmed and l.holder_confirmed then 'active' else 'pending' end,
    verified_at=case when l.owner_confirmed and l.holder_confirmed then clock_timestamp() else null end where id=l.id returning * into l;
  end if;
  return to_jsonb(l);
 elsif p_action='register' then
  select * into r from recordings where id=(p->>'id')::uuid for update;
  if found then
   if r.owner_user_id<>p_actor then raise exception 'NOT_FOUND'; end if;
   if r.registration_hash<>p->>'registrationHash' then raise exception 'CONFLICT'; end if;
   return to_jsonb(r)-'policy_snapshot_bytes'-'policy_signature';
  end if;
  perform 1 from devices where id=(p->>'sourceDeviceId')::uuid and user_id=p_actor and state='active';
  if not found then raise exception 'NOT_FOUND'; end if;
  n:=jsonb_array_length(p->'members');
  if n<>(case when p->>'policyCode'='owner_required_2of2' then 2 when p->>'policyCode'='recovery_2of3' then 3 else 0 end) then raise exception 'INVALID'; end if;
  if (p->'members'->0->>'userId')::uuid<>p_actor or p->'members'->0->>'deviceId'<>p->>'sourceDeviceId' then raise exception 'INVALID'; end if;
  for m in select value from jsonb_array_elements(p->'members') loop
   select * into d from devices where id=(m->>'deviceId')::uuid and user_id=(m->>'userId')::uuid and state='active' for share;
   if not found then raise exception 'NOT_FOUND'; end if;
   if d.hpke_fingerprint<>m->>'hpkeFingerprint' or d.signing_fingerprint<>m->>'signingFingerprint' then raise exception 'FINGERPRINT_CHANGED'; end if;
   if d.user_id<>p_actor then
    perform 1 from trusted_links where owner_device_id=(p->>'sourceDeviceId')::uuid and holder_device_id=d.id and state='active' for share;
    if not found then raise exception 'NOT_FOUND'; end if;
   end if;
  end loop;
  insert into recordings(id,owner_user_id,source_device_id,kind,policy_code,threshold,share_count,policy_snapshot_bytes,policy_snapshot_hash,
   policy_signature,registration_hash,sample_rate,channels,pcm_encoding,started_at_device,capture_state,total_segments,total_samples)
  values((p->>'id')::uuid,p_actor,(p->>'sourceDeviceId')::uuid,p->>'kind',p->>'policyCode',2,n,
   decode(p->>'policySnapshotBase64','base64'),p->>'policySnapshotHash',decode(p->>'policySignatureBase64','base64'),p->>'registrationHash',
   (p->>'sampleRate')::integer,1,'pcm16le',(p->>'startedAtDevice')::timestamptz,p->>'captureState',(p->>'totalSegments')::integer,(p->>'totalSamples')::bigint) returning * into r;
  for m in select value from jsonb_array_elements(p->'members') loop
   insert into recording_members(recording_id,user_id,device_id,share_index,member_kind,hpke_fingerprint,signing_fingerprint)
   values(r.id,(m->>'userId')::uuid,(m->>'deviceId')::uuid,(m->>'shareIndex')::integer,
    case when (m->>'userId')::uuid=p_actor then 'owner' else 'holder' end,m->>'hpkeFingerprint',m->>'signingFingerprint');
  end loop;
  insert into audit_events(recording_id,actor_user_id,actor_device_id,event_type) values(r.id,p_actor,r.source_device_id,'recording_registered');
  return to_jsonb(r)-'policy_snapshot_bytes'-'policy_signature';
 elsif p_action='list' then
  return coalesce((select jsonb_agg(to_jsonb(x)-'policy_snapshot_bytes'-'policy_signature') from
   (select rr.* from recordings rr where rr.owner_user_id=p_actor and (p->>'before' is null or rr.id::text<p->>'before') order by rr.id::text desc limit 50) x),'[]');
 elsif p_action in ('detail','owner','segments','commit','audit') then
  select * into r from recordings where id=(p->>'id')::uuid for update;
  if not found then raise exception 'NOT_FOUND'; end if;
  if r.owner_user_id<>p_actor then
   if p_action<>'detail' or not exists(select 1 from recording_members where recording_id=r.id and user_id=p_actor) then raise exception 'NOT_FOUND'; end if;
   return jsonb_build_object('id',r.id,'policy_code',r.policy_code,'capture_state',r.capture_state,'recovery_state',r.recovery_state);
  end if;
  if p_action='segments' then return coalesce((select jsonb_agg(to_jsonb(x) order by segment_index) from recording_segments x where recording_id=r.id),'[]'); end if;
  if p_action='audit' then return coalesce((select jsonb_agg(to_jsonb(x) order by created_at) from audit_events x where recording_id=r.id),'[]'); end if;
  if p_action='commit' then
   if (p->>'index')::bigint>=r.total_segments then raise exception 'INVALID'; end if;
   select * into s from recording_segments where recording_id=r.id and segment_index=(p->>'index')::bigint;
   if found then
    if s.object_sha256<>p->>'objectHash' then raise exception 'CONFLICT'; end if;
   else
    select count(*),coalesce(sum(sample_count),0) into n,frames from recording_segments where recording_id=r.id;
    if (p->>'index')::bigint<>n then raise exception 'CONFLICT'; end if;
    if p->>'previousHash'<>(case when n=0 then repeat('0',64) else
     (select object_sha256 from recording_segments where recording_id=r.id and segment_index=n-1) end) then raise exception 'CONFLICT'; end if;
    if n>0 and p->>'noncePrefix'<>(select nonce_prefix from recording_segments where recording_id=r.id and segment_index=0) then raise exception 'CONFLICT'; end if;
    frames:=frames+(p->>'sampleCount')::bigint;
    if frames>r.total_samples or (n+1=r.total_segments and frames<>r.total_samples) then raise exception 'INVALID'; end if;
    if p->>'storagePath'<>r.owner_user_id::text||'/'||r.id::text||'/segments/'||lpad(n::text,10,'0')||'.swseg' then raise exception 'INVALID'; end if;
    insert into recording_segments(recording_id,segment_index,storage_path,object_sha256,previous_sha256,byte_length,sample_count,nonce_prefix)
     values(r.id,n,p->>'storagePath',p->>'objectHash',p->>'previousHash',(p->>'byteLength')::integer,(p->>'sampleCount')::integer,p->>'noncePrefix') returning * into s;
    update recordings set sync_state=case when n+1=r.total_segments then 'synced' else 'partial' end,
     sealed_at=case when n+1=r.total_segments then clock_timestamp() else null end where id=r.id;
    insert into audit_events(recording_id,actor_user_id,event_type,metadata) values(r.id,p_actor,'segment_committed',jsonb_build_object('index',n,'hash',s.object_sha256));
   end if;
   return jsonb_build_object('recordingId',s.recording_id,'index',s.segment_index,'objectHash',s.object_sha256,
    'committedAtServer',floor(extract(epoch from s.received_at)*1000));
  end if;
  return to_jsonb(r)-'policy_snapshot_bytes'-'policy_signature';
 end if;
 raise exception 'UNSUPPORTED_ACTION';
exception when unique_violation then raise exception 'CONFLICT';
end $$;
revoke all on function public.swl_m2(uuid,text,jsonb) from public,anon,authenticated;
grant execute on function public.swl_m2(uuid,text,jsonb) to service_role;
