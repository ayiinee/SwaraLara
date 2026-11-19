# M3 — kontrak inti Orang 2

Branch task `feat/m3-hpke-recovery` dibuat dari hasil M2 `81fd2a3` agar identitas
perangkat, signed policy dan Room v2 tersedia. Scope: core-crypto, recording-core,
pengujian serta kontrak handoff. Integrasi app, migration server dan route API tersedia pada
[panduan integrasi M3](m3-integration.md); validasi hosted tetap terpisah.

## Facade

Panggil `CoreRuntime.get(context).awaitReady()` sebelum operasi, lalu gunakan
`core.keyExchange: SecureKeyExchange`. Semua operasi kriptografi/DAO berjalan di
core; app tidak menerima DEK, private key atau share plaintext.

| Operasi | Kontrak |
|---|---|
| `pinTrustedDevice(userId, device, expectedHpkeFingerprint, expectedSigningFingerprint)` | Core memverifikasi proof SWD2, suite publik HPKE, SPKI P-256 dan hash. Caller menyediakan asosiasi akun/perangkat terverifikasi serta fingerprint yang sudah dicocokkan melalui pemasangan. Perubahan key/user untuk device ID yang sama ditolak; tidak ada auto-repin |
| `exportPolicy(recordingId)` | Snapshot SWP1 asli dan signature DER, tanpa reserialize |
| `acceptPolicyDevices(policy, devices)` | Verifikasi owner yang sudah dipin, membership perangkat sendiri, proof publik dan fingerprint seluruh roster terhadap snapshot bertanda tangan; pin atomik |
| `pendingRequests()` / `outgoingCancellations()` | Pulihkan request dari Room, bersihkan kunci expired, dan ulangi pengiriman cancellation yang telah disetujui pengguna |
| `prepareDistribution(recordingId)` | Owner, capture final dan paket lokal lolos autentikasi. Split DEK yang ada sesuai policy, HPKE ke setiap perangkat snapshot, sign lalu persist semua ciphertext sebelum mengembalikannya. Retry mengembalikan envelope yang sama; tidak resplit/reencrypt |
| `authorizeShareRead(policy)` | Signed action `my_share` untuk anggota/perangkat sendiri; JWT saja tidak cukup pada transport |
| `receiveShare(policy, envelope)` | Verifikasi policy/owner signature/fingerprint/context, buka dengan HPKE lokal, validasi SWB1, simpan ciphertext dan buat acknowledgment bertanda tangan. Tidak mengembalikan share plaintext |
| `acknowledgeEnvelopeUpload(receipt)` | Input dari transport setelah commit server, terikat recording/index/hash/waktu. Core tidak menganggap response HTTP upload sebagai ack pemegang |
| `acceptAcknowledgment(recordingId, signedAck)` | Verifikasi signature holder yang ditugaskan, action, resource, device, hash, expiry dan policy. Semua anggota termasuk owner wajib ack |
| `retireLocalKey(recordingId, thresholdOnlyConsent)` | Caller memperoleh persetujuan eksplisit untuk akses threshold saja. Gate dan batas legacy dijelaskan di bawah; operasi bukan konsekuensi otomatis satu upload |
| `createRequest(policy, lifetimeMillis)` | Hanya perangkat anggota snapshot. Keyset HPKE baru per request, private keyset dibungkus lokal; public keyset/request ditandatangani. Maksimal 15 menit |
| `authorizeReleasesRead(requestId)` | Signed action `release_list`, requester sendiri, request belum ditutup/expired/cancelled |
| `approveAndRelease(request, userApproved)` | Panggil hanya dari persetujuan pengguna. Verifikasi signature requester/policy, membership, expiry dan cancellation yang sudah diterima; buka share lokal, HPKE ulang ke key request, sign dan persist untuk retry identik |
| `recover(requestId, releases)` | Verifikasi semua signature/binding, tolak bagian ganda/kurang, buka memakai private key request, rekonstruksi sesuai policy lalu autentikasi GCM seluruh paket lokal dengan DEK hasil rekonstruksi. Tidak memakai full DEK lokal sebagai fallback |
| `cancelRequest` / `receiveCancellation` | Buat/verifikasi cancellation bertanda tangan; blok release berikutnya pada perangkat yang sudah menerima cancellation, tutup request lokal dan hapus request KEK. Transport server tetap harus menegakkan cancellation atomik |
| `closeRecovery(requestId)` | Bersihkan DEK sesi, hapus private envelope request dan request KEK. Playback release/background juga menutup sesi OPEN |
| `closeOpenSessions()` | Tutup lease dan request OPEN melalui antrean operasi core. Hook background menunggu operasi pemulihan yang sedang berjalan lalu membersihkannya |

`SignedPolicyPackage`, `ShareEnvelope`, `DeviceSignedAction`, `KeyAccessRequest`
dan `ShareRelease` hanya memuat identifier publik, metadata, base64 ciphertext,
context dan signature. Base64 kanonik tanpa whitespace. Hash SHA-256 hex lowercase.
Signature JCA SHA256withECDSA P-256 berupa ASN.1 DER. Codec JSON lokal hanya untuk
persistence; signature selalu atas bytes biner asli, bukan JSON yang diserialisasi ulang.

`recover` membutuhkan ciphertext/indeks rekaman sudah tersedia di vault lokal.
Transport kini mengunduh ciphertext sesudah request ready dan mengimpornya melalui
`SecureVault.importEncryptedRecording`. Tidak ada API yang menyerahkan raw DEK
ke app. Verifikasi final manifest tetap M4; perangkat peminta harus anggota snapshot.

## Encoding kriptografi

Share integrated **SWB1** berukuran tepat 104 byte, big-endian. Tidak kompatibel
dengan codec demo SWD1. Skema `shamir-bc-gf256-v1`, BC 1.83, GF(256) basis AES/Table.

| Offset | Panjang | Isi |
|---|---|---|
| 0 | 4 | ASCII SWB1 |
| 4 | 16 | recording UUID |
| 20 | 32 | policy snapshot hash |
| 52 | 1 | policy code: 1=owner_required_2of2, 2=recovery_2of3 |
| 53 | 1 | threshold=2 |
| 54 | 1 | count=2 atau 3 sesuai policy |
| 55 | 1 | share index 1..count, owner index 1 |
| 56 | 16 | holder device UUID |
| 72 | 32 | share y (rahasia, hanya di dalam core) |

Public keyset Tink dibatasi satu key ENABLED/TINK, ASYMMETRIC_PUBLIC,
HpkePublicKey versi 0, KEM X25519=1, KDF HKDF-SHA256=1, AEAD AES256GCM=2.
HPKE memakai Tink 1.17.0, bukan implementasi HPKE buatan aplikasi. Private device
keyset M2 tetap Keystore-wrapped; fingerprint dan serialisasi publik M2 dipertahankan.

Semua payload M3 berikut memakai encoder **LP**: setiap field, termasuk domain,
diawali uint32 panjang big-endian kemudian bytes field. Domain/action ASCII,
UUID 16 byte big-endian, hash 32 byte, index uint32, waktu epoch ms int64.
Batas context 4096 byte, ciphertext 8192 byte, public keyset 4096 byte.
Scheme/domain versi lain ditolak. Anggota/threshold berasal dari SWP1 bertanda
tangan, tidak dipilih oleh pemohon atau backend response `ready`.

| Payload | Field LP berurutan setelah domain |
|---|---|
| `swaralara/share-envelope/v1` | recordingId, policyHash, shareIndex, holderDeviceId |
| `swaralara/share-envelope-signature/v1` | contextBytes, SHA256(ciphertext) |
| `swaralara/key-request/v1` | requestId, recordingId, requesterDeviceId, policyHash, SHA256(requestPublicKeysetJSONBytes), issuedAt, expiresAt, nonceUUID |
| `swaralara/share-release/v1` | requestId, recordingId, requesterDeviceId, policyHash, SHA256(requestSignedBytes), shareIndex, holderDeviceId, requestExpiresAt, issuedAt, nonceUUID |
| `swaralara/share-release-signature/v1` | releaseContextBytes, SHA256(releaseCiphertext) |
| `swaralara/device-action/v1` | actionASCII, recordingId, resourceId, deviceId, policyHash, objectHash, issuedAt, expiresAt, nonceUUID |

`requestSignedBytes` adalah payload `key-request/v1` di atas, tanpa signature DER.
Initial envelope signature mengikat HPKE context dan hash ciphertext. Release
signature mengikat context lengkap termasuk pemohon/key request/expiry/nonce dan
hash ciphertext. Setelah HPKE terbuka, SWB1 diperiksa lagi terhadap snapshot.

Action `share_ack`: resourceId=recordingId, objectHash=envelope ciphertext hash.
Action `my_share`: resourceId=recordingId, objectHash=policy hash.
Action `release_list`/`request_cancel`: resourceId=requestId,
objectHash=SHA256(requestSignedBytes). Expiry aksi request sama dengan expiry request;
aksi share memakai window maksimal 15 menit. Waktu client tidak menjadi waktu
server tepercaya; toleransi issuedAt masa depan 30 detik untuk pemeriksaan lokal.
Ack lama yang sudah diterima secara valid tetap dapat menjadi syarat retirement;
freshness diperiksa saat penerimaan, signature/binding diperiksa lagi sebelum delete.

## Persistence dan siklus hidup

Room v3 menambahkan enam tabel: LocalTrustedDevice, LocalShareEnvelope,
LocalM3Request, LocalM3Release, LocalM3Cancellation dan LocalKeyRetirement.
Migration 1→2→3 bersifat aditif. Envelope keluar/masuk dan release tersimpan
sebagai ciphertext; private request keyset tersimpan sebagai envelope AES-GCM.
Tidak ada share plaintext atau DEK utuh terbuka pada Room/file.

State recovery baru: ENVELOPES_QUEUED, ENVELOPES_UPLOADED,
HOLDERS_ACKNOWLEDGED, terpisah dari capture/sync/integrity. Tidak ada key/FP yang
belum tersedia diganti diam-diam; kegagalan distribusi mempertahankan DEK dan
status DEGRADED. App/worker Orang 1 perlu menangani seluruh state integrated,
bukan membatasi tombol/antrean hanya pada DEGRADED seperti shell M2.

Rekaman integrated baru memakai `local_dek_v2` dan KEK Android Keystore unik per
recording. Full-key envelope hanya dihapus jika capture final, audio SYNCED,
seluruh envelope memiliki receipt terikat, semua anggota memberi ack valid,
bagian owner lokal masih tersedia, dan pengguna menyetujui akses threshold saja.
Transaksi mencatat retirement sekaligus menghapus row DEK, lalu menghapus alias
KEK rekaman. Retry/startup reconciliation mengulang penghapusan alias bila proses
mati di antara kedua langkah. Salinan ciphertext pembungkus lama dalam SQLite/WAL
tidak dapat dibuka melalui alias yang telah dihapus. Ini bergantung pada keamanan
Android Keystore, bukan klaim penghapusan fisik seluruh flash atau memori JVM.

Rekaman legacy `local_dek_v1` memakai KEK bersama dan **ditolak untuk retirement**;
DEK tetap dipertahankan. Mengubah label row atau rewrap saja tidak menghapus salinan
lama yang masih dibuka oleh KEK bersama. Migrasi kunci legacy membutuhkan task
eksplisit. Demo selalu lokal dan tidak dapat didistribusikan sebagai policy integrated.

Request HPKE memakai KEK unik per request. Close/cancel/expiry check menghapus
private envelope dan alias; reconciliation menyelesaikan cleanup sesudah crash.
Hasil rekonstruksi hanya disimpan dalam lease memori sampai expiry maksimal
15 menit, release, cancellation atau background. Timer membersihkan lease expired;
playback memeriksa lease selama penulisan PCM. Key yang hilang tidak dibuat ulang
diam-diam saat decrypt. Setelah retirement, inspect tanpa lease mengembalikan
KEY_REQUIRED, bukan menyatakan audio telah rusak. Tidak ada full DEK cache persisten.

Share dengan signature valid tetap dapat salah isinya. Rekonstruksi harus lolos
GCM sebelum lease dibuka; kegagalan tidak menunjukkan siapa pemegang yang salah
dan tidak membuktikan audio asli berubah. Manifest/checkpoint lengkap tetap M4.

## Handoff Orang 1 dan batas pengujian

Audit 19 November 2026: route backend M3 kini tersedia pada API produksi dan diuji
melalui PGlite/HTTP fixture; penguatan signature/context, nonce request dan expiry
memakai migrasi `202611190004_m3_security.sql`. Kontrak HTTP terbaru dijelaskan di
`backend-api.md`. Transport Android kini tersedia melalui migration 005 dan
codec/worker bersama. Hasil JVM/backend fixture tidak menggantikan validasi
Supabase hosted atau beberapa ponsel fisik. Cakupan dan hasil integrasi dicatat
di [m3-integration.md](m3-integration.md).

Transport Android kini memakai `M3TransportCodec`, `M3CloudTransport` dan `M3Sync`.
Migration 005 menyimpan proof SWD2 perangkat dan bytes acknowledgment/cancellation
asli, menyediakan roster publik berotorisasi serta receipt terikat per share.
Pairing mengisi pin core setelah pengguna mencocokkan fingerprint. Roster anggota
lain harus sesuai snapshot yang ditandatangani pemilik yang telah dipin.
Server tetap menegakkan actor, binding, expiry, nonce, idempotensi dan cancellation.

Response M3 harus menyertakan snapshot SWP1 dan signature aslinya agar holder
dapat memverifikasi roster secara lokal. Backend menerima/menolak masa berlaku
yang ditandatangani berdasarkan jam server; jangan mengubah field expiry/key
request setelah signature dibuat tanpa meminta penandatanganan ulang.

Pengujian JVM menjalankan Tink/JCA dan codec produksi yang sama tanpa meniru
Android Keystore/Room. M3ProtocolTest mencakup HPKE, release, seluruh pasangan
policy yang sah, replay/binding, signature, malformed input dan autentikasi GCM.
Fixture signature publik mencantumkan `origin=jvm` dan diverifikasi pada Node
serta Deno/WebCrypto; ini tidak disebut hasil eksekusi Android.

Catatan historis 18 November: suite Android disiapkan dengan identitas JCA/Tink, database dan namespace
terpisah pada satu emulator. Receipt transport sintetis diberi label test-only;
ack pemegang harus dibuat lewat decrypt/validate. Pada task ini emulator gagal
boot karena commit memory tidak cukup (1726 MB tersedia, 2048 MB diperlukan),
dan pengguna meminta melanjutkan tanpa emulator. Suite Android belum dijalankan.
Fixture writer Android tersedia untuk dipakai ketika lingkungan uji siap.
Tidak ada klaim pengujian beberapa perangkat fisik atau backend M3 aktif.

Rujukan implementasi: [Tink Hybrid Encryption](https://developers.google.com/tink/hybrid)
menjelaskan context dan perlunya autentikasi pengirim terpisah;
[source serialization Tink 1.17.0](https://github.com/tink-crypto/tink-java/blob/v1.17.0/src/main/java/com/google/crypto/tink/TinkJsonProtoKeysetFormat.java)
mendukung pemeriksaan API versi terpin. Hasil aktual dicatat di progress.md.

Implementasi transport dan runner perangkat fisik terbaru: [m3-integration.md](m3-integration.md).
