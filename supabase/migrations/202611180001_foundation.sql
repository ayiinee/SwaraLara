-- API-gated: user JWTs never obtain direct product-table or Storage access.
create domain public.swl_hash as text check (value ~ '^[0-9a-f]{64}$');
create table public.profiles (
 id uuid primary key references auth.users(id) on delete restrict,
 display_name text not null check (char_length(display_name) between 1 and 80),
 created_at timestamptz not null default now()
);
create table public.devices (
 id uuid primary key, user_id uuid not null references public.profiles(id),
 label text not null check (char_length(label) between 1 and 80),
 hpke_public_keyset bytea not null check (octet_length(hpke_public_keyset) between 32 and 8192),
 hpke_fingerprint public.swl_hash not null,
 signing_public_spki bytea not null check (octet_length(signing_public_spki) between 80 and 200),
 signing_fingerprint public.swl_hash not null,
 state text not null default 'active' check (state in ('active','revoked')),
 created_at timestamptz not null default now(), revoked_at timestamptz,
 unique(id,user_id), check ((state='revoked')=(revoked_at is not null))
);
create index on public.devices(user_id);
create table public.trust_invitations (
 id uuid primary key, owner_user_id uuid not null, owner_device_id uuid not null,
 token_hash public.swl_hash not null unique, expires_at timestamptz not null,
 accepted_by_user_id uuid, accepted_device_id uuid, consumed_at timestamptz,
 foreign key(owner_device_id,owner_user_id) references public.devices(id,user_id),
 foreign key(accepted_device_id,accepted_by_user_id) references public.devices(id,user_id),
 check ((consumed_at is null)=(accepted_by_user_id is null)),
 check ((consumed_at is null)=(accepted_device_id is null)),
 check (accepted_by_user_id is distinct from owner_user_id)
);
create table public.trusted_links (
 id uuid primary key, owner_user_id uuid not null, holder_user_id uuid not null,
 owner_device_id uuid not null, holder_device_id uuid not null,
 owner_confirmed boolean not null default false, holder_confirmed boolean not null default false,
 state text not null default 'pending' check (state in ('pending','active','revoked')),
 verified_at timestamptz, created_at timestamptz not null default now(), revoked_at timestamptz,
 foreign key(owner_device_id,owner_user_id) references public.devices(id,user_id),
 foreign key(holder_device_id,holder_user_id) references public.devices(id,user_id),
 check (owner_user_id<>holder_user_id),
 check (state<>'active' or (owner_confirmed and holder_confirmed and verified_at is not null))
);
create unique index trusted_active_pair on public.trusted_links(owner_device_id,holder_device_id) where state<>'revoked';
create index on public.trusted_links(holder_user_id);
create table public.recordings (
 id uuid primary key, owner_user_id uuid not null, source_device_id uuid not null,
 kind text not null check (kind in ('live_event','retrospective')),
 policy_code text not null check (policy_code in ('owner_required_2of2','recovery_2of3')),
 threshold smallint not null check (threshold=2), share_count smallint not null,
 policy_snapshot_bytes bytea not null check (octet_length(policy_snapshot_bytes) between 100 and 4096),
 policy_snapshot_hash public.swl_hash not null, policy_signature bytea not null check (octet_length(policy_signature) between 8 and 80),
 registration_hash public.swl_hash not null,
 sample_rate integer not null check (sample_rate in (16000,44100,48000)),
 channels smallint not null check (channels=1), pcm_encoding text not null check (pcm_encoding='pcm16le'),
 started_at_device timestamptz not null,
 capture_state text not null check (capture_state in ('sealed','interrupted')),
 sync_state text not null default 'queued' check (sync_state in ('queued','partial','synced')),
 recovery_state text not null default 'degraded' check (recovery_state in ('degraded','envelopes_uploaded','holders_acknowledged')),
 total_segments integer not null check (total_segments between 1 and 100000),
 total_samples bigint not null check (total_samples>0),
 created_at timestamptz not null default now(), sealed_at timestamptz,
 foreign key(source_device_id,owner_user_id) references public.devices(id,user_id),
 check ((policy_code='owner_required_2of2' and share_count=2) or (policy_code='recovery_2of3' and share_count=3)),
 unique(id,owner_user_id)
);
create index on public.recordings(owner_user_id,created_at,id);
create table public.recording_members (
 recording_id uuid not null references public.recordings(id), user_id uuid not null,
 device_id uuid not null, share_index smallint not null check (share_index between 1 and 3),
 member_kind text not null check (member_kind in ('owner','holder')),
 hpke_fingerprint public.swl_hash not null, signing_fingerprint public.swl_hash not null,
 acknowledged_at timestamptz,
 primary key(recording_id,share_index), unique(recording_id,user_id),
 unique(recording_id,share_index,device_id,user_id),
 foreign key(device_id,user_id) references public.devices(id,user_id)
);
create unique index one_recording_owner on public.recording_members(recording_id) where member_kind='owner';
create index on public.recording_members(user_id,recording_id);
create table public.recording_segments (
 recording_id uuid not null references public.recordings(id), segment_index bigint not null check (segment_index between 0 and 4294967295),
 storage_path text not null unique, object_sha256 public.swl_hash not null, previous_sha256 public.swl_hash not null,
 byte_length integer not null check (byte_length between 100 and 384098), sample_count integer not null check (sample_count between 1 and 192000),
 checkpoint_bytes bytea, checkpoint_signature bytea, received_at timestamptz not null default now(),
 primary key(recording_id,segment_index), check (byte_length=82+sample_count*2+16)
);
create table public.recording_manifests (
 recording_id uuid primary key references public.recordings(id), manifest_bytes bytea not null check (octet_length(manifest_bytes) between 1 and 1048576),
 signature_der bytea not null check (octet_length(signature_der) between 8 and 80),
 signing_fingerprint public.swl_hash not null, manifest_sha256 public.swl_hash not null, received_at timestamptz not null default now()
);
create table public.encrypted_notes (
 recording_id uuid not null references public.recordings(id), revision integer not null check (revision>0),
 nonce bytea not null check (octet_length(nonce)=12), ciphertext bytea not null check (octet_length(ciphertext) between 16 and 65536),
 ciphertext_sha256 public.swl_hash not null, author_device_id uuid not null references public.devices(id),
 created_at timestamptz not null default now(), primary key(recording_id,revision), unique(recording_id,nonce)
);
create table public.share_envelopes (
 recording_id uuid not null, share_index smallint not null, holder_device_id uuid not null,
 scheme_version text not null check (scheme_version='shamir-bc-gf256-v1'),
 envelope_ciphertext bytea not null check (octet_length(envelope_ciphertext) between 32 and 16384),
 context_bytes bytea not null check (octet_length(context_bytes) between 1 and 4096),
 owner_signature bytea not null, ciphertext_sha256 public.swl_hash not null,
 received_at timestamptz not null default now(), acknowledged_at timestamptz, ack_signature bytea,
 primary key(recording_id,share_index), foreign key(recording_id,share_index) references public.recording_members(recording_id,share_index)
);
create table public.access_requests (
 id uuid primary key, recording_id uuid not null references public.recordings(id), requester_user_id uuid not null,
 requester_device_id uuid not null, request_hpke_public_keyset bytea not null,
 request_bytes bytea not null, request_signature bytea not null,
 state text not null default 'pending' check (state in ('pending','ready','denied','cancelled','expired','completed')),
 expires_at timestamptz not null, created_at timestamptz not null default now(), completed_at timestamptz,
 foreign key(requester_device_id,requester_user_id) references public.devices(id,user_id),
 unique(id,recording_id), check (expires_at>created_at and expires_at<=created_at+interval '24 hours')
);
create index on public.access_requests(recording_id,state);
create index on public.access_requests(requester_user_id,created_at);
create table public.access_decisions (
 request_id uuid not null, recording_id uuid not null, share_index smallint not null,
 holder_user_id uuid not null, holder_device_id uuid not null,
 decision text not null check (decision in ('approve','deny')),
 signed_decision_bytes bytea not null, decision_signature bytea not null, created_at timestamptz not null default now(),
 primary key(request_id,share_index), unique(request_id,recording_id,share_index,decision),
 foreign key(request_id,recording_id) references public.access_requests(id,recording_id),
 foreign key(recording_id,share_index,holder_device_id,holder_user_id) references public.recording_members(recording_id,share_index,device_id,user_id)
);
create table public.share_releases (
 request_id uuid not null, recording_id uuid not null, share_index smallint not null, holder_device_id uuid not null,
 decision text not null default 'approve' check (decision='approve'),
 release_ciphertext bytea not null check (octet_length(release_ciphertext) between 32 and 16384),
 context_bytes bytea not null, holder_signature bytea not null, ciphertext_sha256 public.swl_hash not null,
 created_at timestamptz not null default now(), primary key(request_id,share_index),
 foreign key(request_id,recording_id,share_index,decision) references public.access_decisions(request_id,recording_id,share_index,decision)
);
create table public.audit_events (
 id uuid primary key default gen_random_uuid(), recording_id uuid references public.recordings(id), request_id uuid references public.access_requests(id),
 actor_user_id uuid not null references public.profiles(id), actor_device_id uuid references public.devices(id),
 event_type text not null check (char_length(event_type) between 1 and 80), metadata jsonb not null default '{}',
 created_at timestamptz not null default now()
);
create index on public.audit_events(recording_id,created_at);
create index on public.audit_events(request_id,created_at);
-- A shared DB bucket prevents per-instance Edge limiter bypass.
create table public.api_rate_limits (actor_id uuid not null, operation text not null, window_start timestamptz not null,
 hits integer not null, primary key(actor_id,operation,window_start));

do $$ declare t text; begin
 foreach t in array array['profiles','devices','trust_invitations','trusted_links','recordings','recording_members',
 'recording_segments','recording_manifests','encrypted_notes','share_envelopes','access_requests','access_decisions',
 'share_releases','audit_events','api_rate_limits'] loop
 execute format('alter table public.%I enable row level security',t);
 execute format('revoke all on public.%I from public, anon, authenticated',t);
 execute format('grant all on public.%I to service_role',t);
 end loop;
end $$;

create function public.swl_immutable() returns trigger language plpgsql set search_path=public,pg_temp as $$
begin raise exception 'IMMUTABLE' using errcode='P0001'; end $$;
create trigger segment_immutable before update or delete on public.recording_segments for each row execute function public.swl_immutable();
create trigger manifest_immutable before update or delete on public.recording_manifests for each row execute function public.swl_immutable();
create trigger note_immutable before update or delete on public.encrypted_notes for each row execute function public.swl_immutable();
create trigger device_keys_immutable before update of id,user_id,hpke_public_keyset,hpke_fingerprint,signing_public_spki,signing_fingerprint on public.devices for each row execute function public.swl_immutable();
create trigger policy_immutable before update of owner_user_id,source_device_id,policy_code,threshold,share_count,policy_snapshot_bytes,policy_snapshot_hash,policy_signature,registration_hash,sample_rate,channels,pcm_encoding,total_segments,total_samples,capture_state,started_at_device,kind on public.recordings for each row execute function public.swl_immutable();
create trigger membership_immutable before update of recording_id,user_id,device_id,share_index,member_kind,hpke_fingerprint,signing_fingerprint or delete on public.recording_members for each row execute function public.swl_immutable();

insert into storage.buckets(id,name,public,file_size_limit,allowed_mime_types)
 values ('swl-recordings','swl-recordings',false,384098,array['application/octet-stream'])
 on conflict(id) do update set public=false,file_size_limit=384098,allowed_mime_types=array['application/octet-stream'];
-- Bucket-specific restrictive policies also guard against unrelated permissive project policies.
create policy swl_no_direct_insert on storage.objects as restrictive for insert to anon,authenticated with check(bucket_id<>'swl-recordings');
create policy swl_no_direct_select on storage.objects as restrictive for select to anon,authenticated using(bucket_id<>'swl-recordings');
create policy swl_no_direct_update on storage.objects as restrictive for update to anon,authenticated using(bucket_id<>'swl-recordings') with check(bucket_id<>'swl-recordings');
create policy swl_no_direct_delete on storage.objects as restrictive for delete to anon,authenticated using(bucket_id<>'swl-recordings');
revoke all on function public.swl_immutable() from public,anon,authenticated;
