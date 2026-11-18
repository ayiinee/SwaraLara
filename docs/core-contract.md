# Kontrak core — M1–M2 / format segmen v1

Kode otoritatif: `android/recording-core/src/main/kotlin/id/swaralara/core/Contract.kt`.
Orang 1 hanya mengakses facade dan panel Compose; file/DAO/key adapter bukan API aplikasi utama.

```kotlin
val core = CoreRuntime.get(applicationContext)
// Dalam Compose:
RecorderPanel(core.recorder) // izin mikrofon + gestur 1500 ms dimiliki core
SecurePlaybackPanel(core.playback) // prepare(id) dahulu
// observeRecordings(), inspect(id), exportEncryptedSnapshot(id) adalah operasi vault
```

Mulai harus dipanggil dari Activity terlihat. Permission/type microphone di library manifest di-merge ke host.
Host wajib menonaktifkan backup/transfer untuk seluruh data core. Jangan menaruh key/share pada Bundle,
SavedStateHandle, state UI tersimpan, logcat, crash report atau analitik. State publik hanya kode/status/angka non-sensitif.

`RecorderState` memiliki ID, capture, frame tersimpan, segmen, byte terenkripsi, sampleRate aktual dan errorCode.
ID dikembalikan saat start dijadwalkan; **bukan** jaminan mikrofon telah aktif. UI hanya menampilkan Merekam
sesudah state RECORDING. `stop()` menunggu state terminal. Start kedua saat busy ditolak.

`RecordingSummary` memisahkan capture/sync/recovery/integrity, tanpa judul/kronologi bebas.
`prepare(id)` memverifikasi seluruh paket lokal sebelum player siap; audio tiap segmen diautentikasi kembali
sebelum ditulis ke AudioTrack. `release()` membatalkan job dan membebaskan resource.
Host memanggil `core.onHostBackgrounded()` pada Activity `onStop` agar playback melepas buffer/resource;
operasi ini tidak menghentikan service perekaman. Demo sudah memasang hook ini.

`inspect` sukses tetap VERIFIED_PARTIAL: hash/chain/format/tag/frame dibanding indeks lokal;
tidak tersedia final manifest bertanda tangan. Salah kunci dan rusaknya paket dilaporkan tanpa menuduh audio asli diubah.
`demonstrateRecovery` hanya mengembalikan jumlah pasangan dan lulus/gagal; bytes key/share tidak diberikan ke layar.

Snapshot hanya untuk sesi terminal yang lolos pemeriksaan; referensi memuat file ciphertext internal immutable,
ID/index/hash/previousHash/ukuran/sampleCount. Jangan menulis atau menghapus berkas melalui referensi ini.
M1 snapshot policy `demo_2of3`, unsigned manifest, **tidak uploadable** ke backend integrated.

Receipt M2 mengikat recordingId, index, objectHash, committedAtServer (epoch ms).
`acknowledgeUpload` memvalidasi receipt terhadap indeks lokal, mencatat outbox COMMITTED
dan mengubah sync menjadi PARTIAL/SYNCED. Demo tetap ditolak. Receipt tidak menghapus file
atau DEK dan tidak mengubah recovery DEGRADED menjadi siap.

M2 menambahkan `CaptureConfig(cloudPolicy=...)`, `CloudCapturePolicy` dan
`CloudMember`. Source device dan fingerprint owner harus sama dengan `core.identity`.
Policy dibekukan dan ditandatangani saat create sebelum frame disimpan. Tanpa policy,
rekaman selalu `demo_2of3`; tidak ada migrasi fallback ke cloud.

Snapshot integrated hanya diekspor dari SEALED/INTERRUPTED dengan segmen terverifikasi;
`cloudRegistrationJson` berisi metadata final, bytes snapshot dan signature yang sama
pada setiap retry; `cloudOwnerUserId` mencegah antrean dipakai akun lain. Tidak ada
private key/DEK/share pada metadata. App mengirim file ciphertext apa adanya.
`markSyncFailure(id,code)` menerima AUTH_REQUIRED/NETWORK/CONFLICT/REMOTE saja;
token expired menghasilkan NEEDS_AUTH. WorkManager menyimpan recordingId saja.
Room v2 memakai migrasi aditif 1→2 untuk registration dan outbox.

Encoding policy **SWP1**, big-endian: magic ASCII 4 byte, recording UUID 16,
owner UUID 16, source device UUID 16, policy code 1 (1=owner_required_2of2,
2=recovery_2of3), count 1. Setiap anggota 97 byte: shareIndex 1, user UUID 16,
device UUID 16, HPKE fingerprint 32, signing fingerprint 32. Urutan index wajib
1..n, owner index 1, user berbeda. Panjang total 54+97*n. Signature P-256 SHA-256
DER atas bytes ini, tanpa serialisasi JSON ambigu. Kotlin dan backend memvalidasi
binding recording/source/owner/policy sebelum memakai snapshot.

Identitas device memakai signing P-256 Android Keystore dan Tink HPKE X25519/
HKDF-SHA256/AES256GCM. Private HPKE keyset hanya disimpan Keystore-wrapped.
`core.identity` memberi public keyset/SPKI/fingerprint dan operasi tanda tangan;
tidak mengekspos kunci privat. Distribusi envelope dan pemulihan threshold lintas
perangkat tetap pekerjaan M3. Memori internal library dapat menyalin byte kunci;
zeroization buffer milik aplikasi tidak menjamin seluruh salinan JVM terhapus.

Fixture handoff [fixtures/synthetic-segments-v1.json](fixtures/synthetic-segments-v1.json) berisi dua objek
SWL1 dari PCM nol sintetis (11 frame total), hash, previousHash, ukuran dan base64 bytes.
DEK dibuang sesudah pembuatan; tidak ada key/share di fixture. Header/hash/chain diperiksa lintas Kotlin–Node.
Fixture ini untuk parser/validasi objek backend, **bukan rekaman yang boleh didaftarkan pada cloud**:
`cloudUploadAllowed=false`, policy demo, tanpa manifest/signature/member snapshot.
Ia tidak membuktikan otorisasi API, upload nyata, atau verifikasi GCM oleh server.

Error recorder minimum: MIC_PERMISSION, SERVICE_START_FAILED, FOREGROUND_PERMISSION,
STORAGE_WRITE_FAILED, CAPTURE_FAILED, SERVICE_INTERRUPTED. Kegagalan sensitif tidak diteruskan sebagai stacktrace.
LOCAL_STORAGE_UNAVAILABLE menandakan inisialisasi/recovery lokal gagal; NO_AUDIO_CAPTURED menandai stop tanpa frame aman.
Diagnostik latency, haptic preferences, variasi perangkat, pengukuran baterai, dan gap audio masih perlu validasi lanjut.
