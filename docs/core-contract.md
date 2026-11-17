# Kontrak core — M1 / format v1

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

Receipt M2 harus mengikat recordingId, index, objectHash, committedAtServer.
`acknowledgeUpload` M1 menolak demo dan belum mengubah sync state. Tidak ada HTTP 200 palsu.
Implementasi M2 wajib menambah snapshot policy/perangkat/anggota sah dan validasi receipt terhadap indeks core,
lalu menambah outbox dengan migration Room teruji. Receipt tidak boleh menghapus file atau DEK.

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
