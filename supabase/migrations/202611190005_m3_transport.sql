-- Preserve original signed bytes across the Android/HTTP boundary.
alter table public.devices add column proof_signature bytea;
alter table public.share_envelopes add column ack_bytes bytea;
alter table public.access_requests add column cancellation_bytes bytea;
alter table public.access_requests add column cancellation_signature bytea;

create function public.swl_public_device(d public.devices) returns jsonb
language sql immutable set search_path=public,pg_temp as $$
 select jsonb_build_object('deviceId',d.id,'userId',d.user_id,
  'hpkePublicKeysetBase64',replace(encode(d.hpke_public_keyset,'base64'),E'\n',''),
  'signingPublicSpkiBase64',replace(encode(d.signing_public_spki,'base64'),E'\n',''),
  'proofSignatureBase64',replace(encode(d.proof_signature,'base64'),E'\n',''),
  'hpkeFingerprint',d.hpke_fingerprint,'signingFingerprint',d.signing_fingerprint)
$$;
revoke all on function public.swl_public_device(public.devices) from public,anon,authenticated;

alter function public.swl_m2(uuid,text,jsonb) rename to swl_m3_security;
create function public.swl_m2(p_actor uuid,p_action text,p jsonb default '{}') returns jsonb
language plpgsql security definer set search_path=public,pg_temp as $$
declare result jsonb; rec public.recordings; req public.access_requests;
 dec public.access_decisions; env public.share_envelopes; item jsonb;
begin
 if p_actor is null then raise exception 'UNAUTHENTICATED'; end if;
 if p_action='m3_recordings' then
  perform 1 from devices where id=(p->>'deviceId')::uuid and user_id=p_actor and state='active';
  if not found then raise exception 'NOT_FOUND'; end if;
  return coalesce((select jsonb_agg(jsonb_build_object('id',r.id,
   'policySnapshotBase64',replace(encode(r.policy_snapshot_bytes,'base64'),E'\n',''),
   'policySignatureBase64',replace(encode(r.policy_signature,'base64'),E'\n',''),
   'ownerUserId',r.owner_user_id,'sourceDeviceId',r.source_device_id,'kind',r.kind,
   'startedAtDevice',floor(extract(epoch from r.started_at_device)*1000),'sampleRate',r.sample_rate,
   'totalSamples',r.total_samples,'totalSegments',r.total_segments,'captureState',r.capture_state,
   'syncState',r.sync_state,'recoveryState',r.recovery_state) order by r.created_at desc)
   from recordings r join recording_members m on m.recording_id=r.id
   where m.device_id=(p->>'deviceId')::uuid and m.user_id=p_actor),'[]');
 elsif p_action in ('recovery_recording','recovery_segments') then
  perform public.swl_m3_security(p_actor,'request_releases',p);
  select * into req from access_requests where id=(p->>'id')::uuid;
  select * into rec from recordings where id=req.recording_id;
  if p_action='recovery_segments' then
   return coalesce((select jsonb_agg(to_jsonb(s) order by s.segment_index) from recording_segments s
    where s.recording_id=rec.id and s.segment_index>=(p->>'offset')::bigint and s.segment_index<(p->>'offset')::bigint+50),'[]');
  end if;
  if rec.sync_state<>'synced' then raise exception 'CONFLICT'; end if;
  return jsonb_build_object('id',rec.id,'ownerUserId',rec.owner_user_id,'kind',rec.kind,
   'startedAtDevice',floor(extract(epoch from rec.started_at_device)*1000),'sampleRate',rec.sample_rate,
   'totalSamples',rec.total_samples,'totalSegments',rec.total_segments,'captureState',rec.capture_state,
   'policySnapshotBase64',replace(encode(rec.policy_snapshot_bytes,'base64'),E'\n',''),
   'policySignatureBase64',replace(encode(rec.policy_signature,'base64'),E'\n',''));
 elsif p_action='m3_members' then
  perform public.swl_m3_security(p_actor,'detail',p);
  return coalesce((select jsonb_agg(public.swl_public_device(d) order by m.share_index)
   from recording_members m join devices d on d.id=m.device_id and d.user_id=m.user_id
   where m.recording_id=(p->>'id')::uuid and d.state='active'),'[]');
 elsif p_action='m3_acknowledgments' then
  perform public.swl_m3_security(p_actor,'owner',p);
  return coalesce((select jsonb_agg(jsonb_build_object(
   'payloadBase64',replace(encode(e.ack_bytes,'base64'),E'\n',''),
   'signatureBase64',replace(encode(e.ack_signature,'base64'),E'\n','')) order by e.share_index)
   from share_envelopes e where e.recording_id=(p->>'id')::uuid and e.ack_bytes is not null),'[]');
 elsif p_action='request_decision' then
  select * into req from access_requests where id=(p->>'id')::uuid for update;
  if not found then raise exception 'NOT_FOUND'; end if;
  if req.expires_at<=clock_timestamp() then raise exception 'EXPIRED'; end if;
  if req.state in ('cancelled','expired','completed') then raise exception 'CONFLICT'; end if;
  select * into dec from access_decisions where request_id=req.id and share_index=(p->>'shareIndex')::int;
  if found then
   if dec.holder_user_id<>p_actor or dec.holder_device_id<>(p->>'holderDeviceId')::uuid or dec.decision<>p->>'decision'
    or dec.signed_decision_bytes<>decode(p->>'signedDecisionBase64','base64') then raise exception 'CONFLICT'; end if;
   if dec.decision='approve' and not exists(select 1 from share_releases s where s.request_id=req.id
    and s.share_index=dec.share_index and s.ciphertext_sha256=p->>'ciphertextSha256'
    and s.context_bytes=decode(p->>'contextBytesBase64','base64')
    and s.release_ciphertext=decode(p->>'releaseCiphertextBase64','base64')) then raise exception 'CONFLICT'; end if;
   return jsonb_build_object('requestId',req.id,'decision',dec.decision,'state',req.state);
  end if;
 elsif p_action='envelopes_create' then
  perform public.swl_m3_security(p_actor,'owner',jsonb_build_object('id',p->>'recordingId'));
  for item in select value from jsonb_array_elements(p->'envelopes') loop
   select * into env from share_envelopes where recording_id=(p->>'recordingId')::uuid and share_index=(item->>'shareIndex')::int;
   if found and (env.holder_device_id<>(item->>'holderDeviceId')::uuid
    or env.ciphertext_sha256<>item->>'ciphertextSha256'
    or env.context_bytes<>decode(item->>'contextBytesBase64','base64')) then raise exception 'CONFLICT'; end if;
  end loop;
 end if;
 result:=public.swl_m3_security(p_actor,p_action,p);
 if p_action='device_create' then
  update devices set proof_signature=decode(p->>'proofSignatureBase64','base64') where id=(p->>'id')::uuid and user_id=p_actor;
 elsif p_action='trust' then
  return coalesce((select jsonb_agg(to_jsonb(t)||jsonb_build_object(
   'ownerDevice',(to_jsonb(a)-'hpke_public_keyset'-'signing_public_spki'-'proof_signature')||public.swl_public_device(a),
   'holderDevice',(to_jsonb(b)-'hpke_public_keyset'-'signing_public_spki'-'proof_signature')||public.swl_public_device(b)))
   from trusted_links t join devices a on a.id=t.owner_device_id join devices b on b.id=t.holder_device_id
   where t.owner_user_id=p_actor or t.holder_user_id=p_actor),'[]');
 elsif p_action='envelopes_create' then
  return jsonb_build_object('uploadedCount',(select count(*) from share_envelopes where recording_id=(p->>'recordingId')::uuid),'receipts',coalesce((select jsonb_agg(jsonb_build_object('recordingId',e.recording_id,'shareIndex',e.share_index,
   'ciphertextHash',e.ciphertext_sha256,'receivedAtServer',floor(extract(epoch from e.received_at)*1000)) order by e.share_index)
   from share_envelopes e where e.recording_id=(p->>'recordingId')::uuid),'[]'));
 elsif p_action='my_share_ack' then
  update share_envelopes set ack_bytes=decode(p->>'actionBytesBase64','base64')
   where recording_id=(p->>'recordingId')::uuid and holder_device_id=(p->>'deviceId')::uuid;
 elsif p_action='request_cancel' then
  update access_requests set cancellation_bytes=decode(p->>'actionBytesBase64','base64'),
   cancellation_signature=decode(p->>'signatureBase64','base64') where id=(p->>'id')::uuid;
 elsif p_action='request_detail' then
  select * into req from access_requests where id=(p->>'id')::uuid;
  result:=result||jsonb_build_object('cancellation',case when req.cancellation_bytes is null then null else
   jsonb_build_object('payloadBase64',replace(encode(req.cancellation_bytes,'base64'),E'\n',''),
   'signatureBase64',replace(encode(req.cancellation_signature,'base64'),E'\n','')) end);
 end if;
 return result;
end $$;
revoke all on function public.swl_m2(uuid,text,jsonb) from public,anon,authenticated;
grant execute on function public.swl_m2(uuid,text,jsonb) to service_role;
revoke all on function public.swl_m3_security(uuid,text,jsonb) from public,anon,authenticated,service_role;
