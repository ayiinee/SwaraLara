# Kontrak API M2

Base path `/functions/v1/api`. Semua route kecuali `GET /health` memerlukan
`Authorization: Bearer <access token>`. SDK server memanggil `auth.getUser(token)`;
publishable key tidak menjadi identitas pengguna. Response sukses
`{data,requestId}`; gagal `{error:{code,message},requestId}`; semuanya no-store.
JSON dibatasi 16 KiB, key duplikat/field tambahan ditolak. UUID huruf kecil,
hash SHA-256 hex huruf kecil, signature P-256/SHA-256 ASN.1 DER dalam base64.

| Route | Perilaku dan otorisasi |
|---|---|
| `POST /bootstrap` | `{displayName}`; profil actor sendiri, idempotent |
| `GET /devices/me` | Perangkat actor; hanya public metadata |
| `POST /devices` | `{id,label,hpkePublicKeysetBase64,signingPublicSpkiBase64,proofSignatureBase64}`; key publik dan proof wajib; device ID/key tidak dapat dipindahkan/diubah |
| `POST /trust/invitations` | `{deviceId}` milik actor aktif; token acak satu kali 15 menit, database menyimpan hash |
| `POST /trust/accept` | `{deviceId,token}`; perangkat penerima aktif; konsumsi token dalam transaksi |
| `GET /trust` | Hubungan actor berikut public fingerprints kedua perangkat |
| `POST /trust/:id/confirm` | `{deviceId,signatureBase64}`; pihak terkait menandatangani SWT1; active setelah kedua konfirmasi |
| `POST /recordings` | Registrasi owner, signed policy dan metadata final; retry identik mengembalikan row yang sama, berbeda conflict |
| `GET /recordings?before=<uuid>` | Maksimal 50 rekaman owner, urutan UUID menurun, `{items,nextCursor}` |
| `GET /recordings/:id` | Owner mendapat metadata; anggota snapshot mendapat id/policy/capture/recovery saja; pihak lain 404 |
| `GET /recordings/:id/segments` | Owner saja; indeks objek yang sudah committed |
| `POST /recordings/:id/segments/upload-url` | Owner; `{index,objectHash}`; signed URL tanpa upsert atau `{alreadyCommitted:true}` untuk hash sama |
| `POST /recordings/:id/segments/commit` | Owner; `{index,objectHash}`; server membaca objek dan memvalidasi SWL1/hash/chain/nonce/total sebelum transaksi metadata |
| `POST /recordings/:id/segments/:index/read-url` | Owner; URL baca berlaku 60 detik |
| `GET /recordings/:id/audit` | Owner; registrasi/commit dengan waktu server |

Registrasi hanya menerima: `id,sourceDeviceId,kind,policyCode,sampleRate,channels,
pcmEncoding,startedAtDevice,captureState,totalSegments,totalSamples,
policySnapshotBase64,policySignatureBase64`. Kind `live_event`/`retrospective`,
capture `sealed`/`interrupted`, PCM16LE mono 16000/44100/48000 Hz. Policy hanya
`owner_required_2of2` atau `recovery_2of3`. Anggota harus berbeda user, perangkat
aktif dan fingerprints sama dengan snapshot; owner berada pada share index 1.
Setiap holder harus punya hubungan aktif dengan perangkat source owner.

Objek disimpan pada bucket private `swl-recordings` dengan path
`<owner UUID>/<recording UUID>/segments/<index 10 digit>.swseg`. Client tidak
memilih path. Bucket menerima octet-stream maksimal 384098 byte. Upload URL SDK
berlaku **dua jam**, batas yang didukung `createSignedUploadUrl`; kode tidak
mengklaim TTL lebih pendek. Capability URL harus diperlakukan seperti credential.
URL tidak dicatat ke audit/log. Commit tidak mempercayai deklarasi hash client.
Objek tanpa row committed bukan status synced. Upload conflict diterima client
hanya bila commit berikutnya membuktikan byte yang benar.

Commit mengembalikan `{recordingId,index,objectHash,committedAtServer}` (epoch ms).
DB mengunci rekaman, menerima urutan index berikutnya, total frame dan nonce
prefix konsisten, serta tidak menggandakan receipt/audit saat retry. Sync final
tetap recovery `degraded`; belum ada distribusi share atau penghapusan DEK lokal.

Public key HPKE adalah JSON public keyset Tink: satu key ENABLED/TINK,
`HpkePublicKey`, X25519/HKDF-SHA256/AES256GCM; keyset privat ditolak. Signing key
SPKI P-256. Proof perangkat: `SWD2 || deviceUUID || SHA256(hpkeJSON) || SHA256(spki)`.
Konfirmasi trust: `SWT1 || linkUUID || deviceUUID`. Encoding UUID dan SWP1 mengikuti
[kontrak core](core-contract.md). Fingerprint dibandingkan melalui saluran terpisah
sebelum tombol konfirmasi, lalu dipin di Android.

RLS aktif pada 16 tabel (termasuk nonce request M3); akses langsung anon/authenticated dan execute RPC
`swl_m2` dicabut. Service role hanya tersedia server. Kebijakan restrictive
bucket mencegah policy permisif yang tidak terkait membuka objek rekaman.
Transaksi memeriksa actor/resource lagi. Rate limit per actor/menit: 10 untuk
device/invitation/accept, 60 untuk recording/upload/read; upload-url dan commit
menggunakan kuota upload yang sama. Client retry dengan backoff.

M3 memiliki route share-envelopes, my-share/ack, access-requests, decision,
releases dan cancel. M4 manifest/notes tetap 501. API/M3 diuji pada PGlite dan
HTTP fixture; belum merupakan hasil Supabase live atau integrasi multi-perangkat.

Penguatan 19 November memakai migrasi `202611190004_m3_security.sql` setelah tiga
migrasi sebelumnya. Nonce request unik per perangkat, retry ID harus identik,
expiry mengikat payload bertanda tangan (maksimum 15 menit), keputusan dan release
harus mengikat request/index/holder/policy. Cancel requester menutup pending maupun
ready; release read dan keputusan menolak request expired. Retry keputusan holder
yang sama tidak menambah jumlah bagian. Request expiry tidak mencabut bagian yang
sudah diterima client.

`GET my-share` dan `GET access-requests/:id/releases` wajib memakai query
`actionBase64` dan `signatureBase64`, dengan LP device-action dari M3Wire.
My-share juga membawa `deviceId`; action=my_share, resourceId=recordingId,
objectHash=policyHash. Release read action=release_list, resourceId=requestId,
objectHash=SHA256(requestSignedBytes), expiry sama dengan request. JWT akun saja
tidak menggantikan signature perangkat. Ack mengikat hash ciphertext envelope dan
policy. JSON/base64 publik harus canonical. Signed decision saat ini menggunakan
ASCII `approve:<requestId>:<shareIndex>` atau `deny:<requestId>:<shareIndex>`;
transport Android memakai `M3TransportCodec` untuk mempertahankan bytes asli.
`M3Json` tetap khusus persistence lokal, bukan DTO HTTP.

Migration `202611190005_m3_transport.sql` melengkapi kontrak transport:

| Route | Response / otorisasi tambahan |
|---|---|
| `GET /trust` | Identitas publik owner/holder beserta proof SWD2 asli; hanya kedua pihak |
| `GET /m3/recordings?deviceId=...` | Snapshot dan metadata rekaman yang mencantumkan akun/perangkat tersebut |
| `GET /recordings/:id/members` | Public keyset/SPKI/proof anggota snapshot; hanya anggota |
| `POST /recordings/:id/share-envelopes` | `{uploadedCount, receipts:[{recordingId,shareIndex,ciphertextHash,receivedAtServer}]}` |
| `GET /recordings/:id/acknowledgments` | `{payloadBase64,signatureBase64}[]`, bytes ack asli; hanya owner |
| `GET /access-requests/:id/recording` | Metadata download, hanya requester pada state ready dengan signed action release_list |
| `GET /access-requests/:id/segments?offset=0` | Maksimum 50 referensi segmen + signed URL; gate sama dengan releases |

Query download memakai `actionBase64`/`signatureBase64` yang sama dengan release
read. Offset 0..100000; setiap segmen memuat index, objectHash, previousHash,
byteLength, sampleCount dan readUrl. Klien memeriksa hash/binding sebelum import;
core tetap memerlukan GCM dengan DEK hasil threshold recovery. Ini bukan final manifest M4.

Ack POST memakai `{deviceId,actionBytesBase64,signatureBase64}`. Cancel POST memakai
struktur yang sama dan bytes-nya dikembalikan sebagai `cancellation` pada detail
request. Retry keputusan identik mengembalikan keputusan tersimpan tanpa menambah
share; perubahan keputusan/release pada index yang sama ditolak. Server tidak
mengubah expiry/keyset/bytes request setelah ditandatangani.

Alur, konfigurasi dan batas pengujian: [integrasi M3](m3-integration.md).
