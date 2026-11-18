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

RLS aktif pada 15 tabel; akses langsung anon/authenticated dan execute RPC
`swl_m2` dicabut. Service role hanya tersedia server. Kebijakan restrictive
bucket mencegah policy permisif yang tidak terkait membuka objek rekaman.
Transaksi memeriksa actor/resource lagi. Rate limit per actor/menit: 10 untuk
device/invitation/accept, 60 untuk recording/upload/read; upload-url dan commit
menggunakan kuota upload yang sama. Client retry dengan backoff.

M3/M4: manifest, notes, share-envelopes, my-share/ack mengembalikan 501 sesudah
otorisasi owner; workflow akses lainnya belum memiliki route. Tabel target
tersedia sebagai fondasi, bukan bukti workflow approval/recovery sudah bekerja.
