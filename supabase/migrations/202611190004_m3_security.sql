-- Preserve the deployed M3 function and place transactional lifecycle/replay gates
-- in front of it. Only the service role may execute either function.
alter function public.swl_m2(uuid,text,jsonb) rename to swl_m3_prior;
create table public.m3_request_nonces (
 device_id uuid not null references public.devices(id), nonce uuid not null,
 request_id uuid not null unique, request_bytes bytea not null,
 primary key(device_id,nonce)
);
alter table public.m3_request_nonces enable row level security;
revoke all on public.m3_request_nonces from public,anon,authenticated;

create function public.swl_m2(p_actor uuid, p_action text, p jsonb default '{}') returns jsonb
language plpgsql security definer set search_path=public,pg_temp as $$
declare req public.access_requests; prior public.m3_request_nonces; result jsonb;
begin
 if p_actor is null then raise exception 'UNAUTHENTICATED'; end if;
 if p_action='request_create' then
  perform pg_advisory_xact_lock(hashtextextended(p->>'id',0));
  select * into req from access_requests where id=(p->>'id')::uuid;
  if found then
   if req.requester_user_id<>p_actor or req.recording_id<>(p->>'recordingId')::uuid or
    req.requester_device_id<>(p->>'requesterDeviceId')::uuid or
    req.request_bytes<>decode(p->>'requestBytesBase64','base64') or
    req.request_hpke_public_keyset<>decode(p->>'requestHpkePublicKeysetBase64','base64') or
    req.expires_at<>(p->>'expiresAt')::timestamptz then raise exception 'CONFLICT'; end if;
  else
   if p->>'requestNonce' is null then raise exception 'INVALID'; end if;
   insert into m3_request_nonces values((p->>'requesterDeviceId')::uuid,(p->>'requestNonce')::uuid,
    (p->>'id')::uuid,decode(p->>'requestBytesBase64','base64'));
  end if;
 elsif p_action in ('request_decision','request_releases','request_cancel') then
  select * into req from access_requests where id=(p->>'id')::uuid for update;
  if not found then raise exception 'NOT_FOUND'; end if;
  if p_action='request_cancel' then
   if req.requester_user_id<>p_actor then raise exception 'NOT_FOUND'; end if;
   if req.state in ('pending','ready') then
    update access_requests set state='cancelled',completed_at=clock_timestamp() where id=req.id;
    insert into audit_events(recording_id,request_id,actor_user_id,event_type)
     values(req.recording_id,req.id,p_actor,'access_request_cancelled');
    return jsonb_build_object('requestId',req.id,'state','cancelled');
   end if;
  end if;
  if req.expires_at<=clock_timestamp() then raise exception 'EXPIRED'; end if;
 end if;
 return public.swl_m3_prior(p_actor,p_action,p);
exception when unique_violation then raise exception 'CONFLICT';
end $$;
revoke all on function public.swl_m2(uuid,text,jsonb) from public,anon,authenticated;
grant execute on function public.swl_m2(uuid,text,jsonb) to service_role;
-- The old implementation must not bypass the wrapper even for service callers.
revoke all on function public.swl_m3_prior(uuid,text,jsonb) from public,anon,authenticated,service_role;
