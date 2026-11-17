# SwaraLara — Brief Implementasi Dua Orang

Versi 1.0 · 17 November 2026

**Pemilik brief ini berperan sebagai Orang 2: pengembang inti perekaman dan kriptografi.**

Dokumen ini melengkapi `prd.md`. Berikan kedua file kepada Codex. PRD menetapkan kebutuhan produk, format kriptografi, database, dan API; brief ini menetapkan pembagian kerja, batas modul, prioritas, serta cara mengintegrasikan hasil dua pengembang.

Jika ada perbedaan pembagian tugas dengan percakapan atau rancangan sebelumnya, gunakan pembagian di brief ini. Format kriptografi dan aturan keamanan tetap mengikuti PRD. Penambahan modul Android di bawah adalah penyesuaian struktur agar Orang 2 dapat menguji alur inti tanpa menunggu aplikasi utama atau backend.

## 1. Tujuan dan hasil akhir

Bangun prototipe Android SwaraLara untuk memulai perekaman melalui gestur tekan lama, mengenkripsi audio secara bertahap, menyimpannya secara lokal, dan memulihkannya menggunakan AES-GCM serta Shamir Secret Sharing.

Pekerjaan dibagi menjadi dua jalur:

- **Orang 1:** aplikasi utama, layar pendukung, autentikasi, backend, database, Storage, API, dan sinkronisasi.
- **Orang 2 — saya:** seluruh alur inti lokal, mulai dari gestur, mikrofon, segmentasi, kriptografi, penyimpanan, pemulihan, pemeriksaan, hingga pemutaran.

Prioritas pertama adalah satu demonstrasi lokal yang benar-benar bekerja. Integrasi cloud dan beberapa perangkat menyusul sesuai milestone. Satu malam tidak dianggap cukup untuk menyelesaikan seluruh sistem secara aman dan teruji.

## 2. Matriks pembagian tugas

| Bagian | Orang 1 | Orang 2 — saya |
|---|---|---|
| Fondasi repositori | Menyiapkan konfigurasi Supabase dan struktur aplikasi utama setelah fondasi Android tersedia | Menyiapkan fondasi Gradle Android dan modul inti/demo; menyerahkan scaffold minimal aplikasi utama |
| Navigasi dan gaya | Tema global, navigasi, onboarding, login, layout aplikasi utama | Gaya minimum halaman demo serta komponen inti agar dapat diuji mandiri |
| Tombol tekan lama | Menempatkan komponen yang disediakan Orang 2 di beranda | Implementasi sentuhan, ambang tekan, pencegahan aktivasi ganda, dan umpan balik |
| Mikrofon | Menampilkan status kesiapan dari modul inti | Izin, AudioRecord, foreground service, lifecycle, interupsi, dan cleanup |
| Audio | Menggunakan metadata hasil rekaman | Buffer PCM, segmentasi, tail buffer, konfigurasi audio, dan frame count |
| Enkripsi | Menyimpan/mengirim ciphertext tanpa membuka isinya | AES-GCM, nonce/AAD, codec segmen, pengelolaan DEK dan Keystore |
| Secret sharing | UI pemegang/penerima dan transport envelope | Shamir, codec bagian, HPKE envelope, rekonstruksi, dan validasi binding |
| Penyimpanan lokal | Data akun/pengaturan non-rekaman milik aplikasi utama | File rekaman terenkripsi, Room rekaman, indeks, outbox inti, dan crash recovery |
| Brankas | Layar daftar/detail dan tampilan kronologi | Query domain, penyimpanan kronologi terenkripsi, serta operasi baca/tulis aman |
| Player | Menempatkan kontrol playback pada halaman detail | Verifikasi, dekripsi per segmen, dan AudioTrack |
| Database server | Seluruh migration, constraint, index, transaksi, dan kontrol akses | Memberikan kontrak paket dan memeriksa apakah schema mendukung algoritma |
| API dan Storage | Auth, Edge API, private bucket, otorisasi, signed URL, retry, audit | Penyedia paket terenkripsi dan hasil pemeriksaan lokal |
| Persetujuan akses | Halaman inbox/persetujuan dan state di backend | Pembuatan payload bertanda tangan, pelepasan bagian, dan pemulihan lokal |
| Pengujian | Layar pendukung, API, isolasi user, upload/retry, integrasi cloud | Gestur, recorder, crypto, Keystore, storage lokal, recovery, dan playback |

**Tidak ada endpoint server untuk menggabungkan bagian kunci atau mendekripsi audio.** Walaupun implementasi backend milik Orang 1, seluruh operasi yang membuka isi sensitif tetap berada pada modul perangkat milik Orang 2.

## 3. Batas folder dan kepemilikan perubahan

Struktur target:

```text
swaralara/
  android/
    app/                         # Orang 1: aplikasi utama
    core-crypto/                 # Orang 2: library Kotlin/JVM
    recording-core/              # Orang 2: Android library, service, Room, komponen inti
    core-demo/                   # Orang 2: aplikasi demo Android mandiri
    gradle/libs.versions.toml     # Orang 2: pemilik awal konfigurasi bersama
    settings.gradle.kts          # Orang 2: pemilik konfigurasi bersama
    build.gradle.kts             # Orang 2: pemilik konfigurasi bersama
    gradle/wrapper/               # Orang 2: pemilik konfigurasi bersama
  supabase/                      # Orang 1
  docs/
    core-contract.md             # Orang 2; disepakati kedua pihak
    crypto-format.md             # Orang 2
    core-testing.md              # Orang 2
    backend-api.md               # Orang 1
    backend-testing.md           # Orang 1
    integration-checklist.md      # Bersama
    decisions.md                 # Bersama
  prd.md
  brief_pembagian_tugas_swaralara.md
```

Aturan:

1. Gunakan satu repositori dengan branch `feat/app-backend` untuk Orang 1 dan `feat/recording-crypto` untuk Orang 2.
2. Orang 2 membuat fondasi build dan scaffold minimum lebih dulu sebagai commit bersama. Setelah itu `app/` menjadi milik Orang 1; jangan terus menulis layar produk di `app/` dari branch Orang 2.
3. Orang 1 tidak mengubah internal recorder, algoritma, format segmen, atau database Room rekaman langsung. Gunakan facade publik.
4. Orang 2 tidak mengubah schema server/API secara sepihak. Jika algoritma membutuhkan field tambahan, catat pada kontrak dan sinkronkan dengan Orang 1.
5. Perubahan root Gradle/version catalog dikoordinasikan melalui pemilik awal Orang 2. Perubahan di branch lain harus disampaikan sebelum integrasi.
6. Jangan mengirim folder build, SDK, token, file rekaman nyata, private key, atau bagian Shamir melalui Git.
7. Tidak perlu membuat banyak modul per layar. Empat modul di atas cukup sebagai batas implementasi awal.
8. Jika repo sudah ada, adaptasikan struktur tanpa merombak pekerjaan yang sudah berfungsi. Tulis pemetaan folder aktual di `docs/decisions.md`.

## 4. Tugas detail Orang 2 — instruksi utama untuk Codex saya

### 4.1 Fondasi dan aplikasi pengujian mandiri

Buat `core-demo` sebagai aplikasi debug/test terpisah dengan application ID `id.swaralara.coredemo`. Aplikasi utama memakai `id.swaralara.app`.

`core-demo` harus:

- Dapat dibangun dan digunakan tanpa akun, backend, Supabase key, atau internet.
- Menggunakan library dan pipeline recorder yang sama dengan aplikasi utama; jangan membuat implementasi recorder/crypto kedua khusus demo.
- Memiliki halaman uji perekaman, daftar lokal, pemulihan Shamir, pemeriksaan keutuhan, dan playback.
- Menampilkan label **Demo lokal — data simulasi** dan **Pembagian kunci pada satu perangkat** bila belum ada distribusi lintas perangkat.
- Menyediakan ringkasan diagnostik non-sensitif: status recorder, nomor segmen, durasi, jumlah byte terenkripsi, dan hasil verifikasi.
- Tidak menampilkan DEK/private key/share plaintext secara default. Uji secret sharing membandingkan byte di test dan menampilkan lulus/gagal.
- Menyediakan tombol uji korupsi yang bekerja pada salinan ciphertext, bukan merusak rekaman asli.
- Memisahkan data aplikasi demo dari aplikasi utama. Jangan menjanjikan migrasi data otomatis hanya karena kode library sama.

Fondasi dibangun dengan Kotlin, Compose, Coroutines/Flow, AudioRecord, Room, JCA, Bouncy Castle, Android Keystore, dan Tink sesuai PRD. Verifikasi versi dependency dan kompatibilitas sebelum dipin. Gunakan `minSdk` usulan 26 kecuali ada alasan kompatibilitas yang dicatat.

### 4.2 Gestur dan kontrol perekaman

- Orang 2 memiliki komponen Compose `RecorderPanel` atau nama setara, termasuk gestur tekan lama dan pengelolaan izin mikrofon.
- Ambang awal 1.500 ms adalah parameter pengujian. Lepas sebelum ambang membatalkan; setelah aktif, melepas jari tidak menghentikan perekaman.
- Pastikan tepat satu aktivasi pada satu interaksi. Rapid tap, long press berulang, dan rotasi layar tidak membuat recorder kedua.
- Mulai perekaman dari Activity yang terlihat dengan foreground service bertipe microphone serta deklarasi permission yang sesuai OS.
- Status **Merekam** hanya muncul setelah recorder benar-benar aktif. Kegagalan harus menjadi state yang dapat ditangani UI, bukan hanya log.
- Hentikan melalui aksi terpisah. Getaran dapat disetel dan tidak menggantikan state yang dapat diamati aplikasi.
- Recorder dimiliki service; perpindahan halaman tidak otomatis mematikan rekaman.
- Jangan menghilangkan notifikasi/indikator mikrofon Android atau menambahkan aksesibilitas/overlay untuk melewati pembatasan platform.

### 4.3 Segmentasi dan enkripsi

Target audio awal: PCM signed 16-bit little-endian, mono, 16.000 Hz; segmentasi target 2 detik. Periksa kemampuan perangkat, simpan format aktual, dan tangani partial read/tail buffer dengan benar.

Pipeline:

```text
Mikrofon -> buffer memori -> segmen PCM -> AES-GCM
         -> file sementara terenkripsi -> rename atomik
         -> indeks Room -> tersedia untuk daftar/unggah
```

AES-GCM:

- DEK acak 32 byte baru per sesi; `AES/GCM/NoPadding`, tag 16 byte.
- Nonce 12 byte = prefix acak 8 byte per sesi + index segmen UInt32 big-endian 4 byte.
- Indeks monoton mulai 0; tolak overflow; retry tidak mengenkripsi ulang dengan pasangan key/nonce yang sama.
- AAD adalah header `.swseg` versi 1 dari PRD. Header total 82 byte; jangan menciptakan format alternatif di branch lain.
- Field header: magic `SWL1`, UUID raw, index, sampleRate, channels, pcmEncoding, sampleCount, nonce, previousObjectHash, ciphertextLength.
- `objectHash = SHA256(seluruh byte .swseg)`; hash segmen sebelumnya dimasukkan ke header berikutnya.
- Validasi magic, ukuran, ID, indeks, format, chain, dan tag sebelum plaintext diberikan kepada player.
- Tidak ada file audio terbuka di internal/external storage, cache, logcat, Room, atau crash report.

Rincian byte order dan ukuran setiap field mengikuti bagian 8.2 `prd.md`; dokumentasikan implementasi aktual dan buat vektor uji codec.

### 4.4 Pengelolaan kunci dan Shamir

- DEK dibuat di memori agar dapat dibagi; simpan hanya envelope DEK yang dibungkus kunci Keystore ketika persistence lokal diperlukan.
- Jangan membuat DEK non-exportable di Keystore lalu mencoba mengekspornya untuk Shamir.
- Buat adapter Bouncy Castle untuk split/recover DEK 32 byte. Pin format/basis GF(256) dan simpan koordinat bagian, bukan sekadar byte y.
- M1 memakai demonstrasi `demo_2of3`. Semua pasangan (1,2), (1,3), dan (2,3) harus memulihkan DEK identik.
- Tolak duplicate shareIndex, kurang bagian, format/ID sesi tidak sesuai, atau panjang bagian salah.
- Integrated mode mengikuti pilihan `owner_required_2of2` atau `recovery_2of3` dari PRD. Jangan diam-diam menganggap dua kebijakan tersebut sama.
- Dekripsi sukses hanya setelah key recovery dan autentikasi GCM sukses. Share salah dapat menyebabkan kegagalan pemulihan; jangan langsung menuduh audio asli diubah.
- Jangan menyimpan key/share plaintext di Compose saved state, Bundle, public DTO, atau log. Pembersihan memori bersifat best effort.
- Implementasikan siklus hidup DEK lokal sesuai PRD. Menghapus full-key envelope dilakukan oleh core setelah persyaratan valid terpenuhi, bukan oleh layar/worker karena HTTP upload sukses.

### 4.5 Penyimpanan dan pemulihan lokal

Orang 2 memiliki Room entities `LocalRecording`, `LocalSegment`, `LocalKeyEnvelope`, `LocalOutbox`, `LocalTrustedDevice`, dan `LocalSensitiveNote` sebagaimana dibutuhkan PRD.

- Isi sensitif seperti judul bebas, kronologi, lokasi opsional harus dienkripsi; Room sendiri tidak dianggap terenkripsi.
- File berada di internal storage dengan ID rekaman/index deterministik. Simpan segmen final sebelum memperbarui indeks.
- Rekonsiliasi file final yang belum masuk Room setelah crash. Isolasi/buang hanya `.tmp` yang belum lengkap, bukan segmen final yang valid.
- Jangan melanjutkan sesi setelah proses mati menggunakan DEK/counter lama. Mulai ID dan DEK baru; sesi sebelumnya ditandai interrupted.
- Core menyediakan data/domain model untuk brankas; Orang 1 tidak membaca file atau tabel Room secara langsung.
- State capture, sync, recovery, dan integrity harus terpisah. Cloud acknowledgment tidak otomatis berarti kemampuan pemulihan sudah lengkap.
- Di mode demo/local, playback dapat memakai local wrapped DEK. Di integrated mode setelah transisi penghapusan envelope penuh, playback mengikuti threshold; jangan meninggalkan bypass tersembunyi.

### 4.6 Playback dan pemeriksaan

- Implementasikan playback menggunakan AudioTrack atau mekanisme setara yang menerima PCM setelah autentikasi per segmen berhasil.
- Jangan membuat WAV/PCM terbuka sementara untuk memudahkan player.
- Sediakan state preparing, playing, paused, completed, failed dan operasi cleanup.
- Gunakan total sample frame untuk durasi; jangan hanya menghitung jumlah file dikali durasi target.
- Verifikasi final manifest, signature, urutan/jumlah/hash, serta tag GCM sesuai milestone. Untuk sesi terputus, jelaskan batas kelengkapan.
- M1 harus sudah punya urutan/frame count dan pemeriksaan segmen; signing/checkpoint lengkap dapat menyusul M4. UI tidak menampilkan **Paket bertanda tangan terverifikasi** sebelum implementasi itu tersedia.

### 4.7 Pengembangan lanjutan setelah demo stabil

- HPKE envelope menggunakan Tink untuk public keyset perangkat pemegang dan request-specific keyset.
- Pinned fingerprint, policy snapshot, device signing P-256, dan binding request/recording/recipient/shareIndex.
- Share release dienkripsi ulang pada perangkat; server tidak menerima share terbuka.
- Signature Android JCA DER dan verifier Deno harus diuji formatnya; koordinasikan codec dengan Orang 1.
- Kronologi memakai kunci turunan HKDF dengan domain terpisah sebagaimana PRD.
- Signed manifest/checkpoint serta siklus acknowledgment pemegang diterapkan sesuai PRD.
- Primitive/langkah yang belum tersedia tidak boleh digantikan mock tanpa label.

## 5. Tugas detail Orang 1 — brief yang dibagikan ke rekan

Orang 1 membaca PRD lalu mengerjakan hal berikut di luar internal modul Orang 2:

1. Aplikasi utama Compose: onboarding, login, beranda sebagai host `RecorderPanel`, brankas, detail, kronologi, pihak tepercaya, permintaan akses, dan pengaturan.
2. Supabase Auth serta penyimpanan sesi pada perangkat secara aman. Perekaman lokal tidak bergantung pada login atau jaringan.
3. Migration 14 tabel sesuai PRD: `profiles`, `devices`, `trust_invitations`, `trusted_links`, `recordings`, `recording_members`, `recording_segments`, `recording_manifests`, `encrypted_notes`, `share_envelopes`, `access_requests`, `access_decisions`, `share_releases`, `audit_events`.
4. Constraint, index, immutable snapshot, API-gated access, RLS deny-by-default, serta transaksi keputusan+release yang atomik.
5. Edge API TypeScript/Deno sesuai kontrak PRD. Actor dari JWT tervalidasi, bukan userId dari body. Periksa ownership/membership/device/resource pada setiap endpoint.
6. Private Storage dan penerbitan URL terbatas. Backend memverifikasi object/hash/header sebelum commit metadata.
7. Kotlin API client dan worker sinkronisasi yang mengambil objek terenkripsi melalui facade Orang 2. Retry idempotent tanpa mengubah ciphertext, indeks, atau nonce.
8. Pengelolaan undangan, pemasangan perangkat, public key transport, inbox, expiry/cancellation, dan audit. Identitas/fingerprint yang ditampilkan harus berasal dari kontrak yang diverifikasi bersama core.
9. Integrasi UI: membuka rekaman dan memproses persetujuan melalui fungsi core, bukan mengimplementasikan AES/Shamir lagi di aplikasi utama.
10. Dokumentasi setup backend, konfigurasi contoh tanpa secrets, seed data simulasi, dan tes isolasi antaruser.

Backend tidak menyimpan DEK/private key/share terbuka. Service secret tidak masuk APK. Field `ready` hanya menyatakan envelope persetujuan sah cukup secara workflow; keberhasilan key recovery dibuktikan di perangkat.

Untuk malam pertama, dahulukan shell UI dengan fake repository yang diberi label demo, migration, dan kerangka API. Jangan memperluas fitur menjadi SOS, AI, dashboard web, atau integrasi lembaga.

## 6. Kontrak integrasi yang harus disepakati lebih dulu

Orang 2 membuat draft `docs/core-contract.md` dan implementasi interface minimum. Orang 1 dapat memulai layar pendukung memakai fake implementation tanpa memalsukan keberhasilan integrasi.

### 6.1 Model data publik

| Model | Data yang boleh keluar dari core |
|---|---|
| `RecordingSummary` | ID, kind, waktu perangkat, durasi, jumlah segmen, state capture/sync/recovery/integrity; tanpa kronologi sensitif terbuka |
| `RecorderState` | Status recorder, ID sesi, durasi/frame count, segmen tersimpan, serta kode error non-sensitif |
| `EncryptedSegmentRef` | ID rekaman, index, referensi berkas terenkripsi, hash, previous hash, ukuran, sample count |
| `EncryptedRecordingSnapshot` | Daftar segmen final yang konsisten, manifest jika tersedia, format version, dan metadata publik yang diperlukan upload |
| `UploadReceipt` | Resource/index/hash yang diterima server, waktu server, dan status commit; bukan sekadar HTTP 200 |
| `RecoveryProgress` | Jumlah bagian berbeda yang valid, ambang, status pemulihan, serta error; tidak mengekspos share bytes |
| `PlaybackState` | Status player, posisi/durasi, dan hasil verifikasi yang sudah dilakukan |

Public metadata tidak memuat raw key, private keyset, bagian terbuka, PCM buffer, atau token. Tampilan kronologi melalui operasi baca khusus dan hanya setelah akses lokal yang sesuai; jangan memasukkannya ke daftar metadata upload.

### 6.2 Interface yang dituju

Berikut kontrak domain usulan; sesuaikan tipe Kotlin aktual dan dokumentasikan perubahan sebelum kedua branch mengimplementasikan versi berbeda:

```kotlin
interface RecorderController {
    val state: StateFlow<RecorderState>
    suspend fun start(config: CaptureConfig): RecordingId
    suspend fun stop(): StopResult
}

interface SecureVault {
    fun observeRecordings(): Flow<List<RecordingSummary>>
    suspend fun inspect(recordingId: RecordingId): IntegrityReport
    suspend fun exportEncryptedSnapshot(recordingId: RecordingId): EncryptedRecordingSnapshot
    suspend fun acknowledgeUpload(receipt: UploadReceipt)
}

interface SecurePlaybackController {
    val state: StateFlow<PlaybackState>
    suspend fun prepare(recordingId: RecordingId): PreparePlaybackResult
    suspend fun play()
    suspend fun pause()
    suspend fun release()
}
```

`CaptureConfig` berisi jenis rekaman serta opsi policy/context yang didukung; jangan mensyaratkan backend agar mode lokal mulai. `prepare` boleh menghasilkan status **Perlu pemulihan kunci**, bukan memaksa key bypass atau meminta bagian plaintext kepada layar.

Komponen UI publik minimum: `RecorderPanel(controller, modifier)` dan `SecurePlaybackPanel(controller, modifier)`, atau signature setara yang tercatat. Permission launcher/gesture milik komponen Orang 2; jangan diduplikasi dalam beranda Orang 1.

### 6.3 Alur unggah

1. Orang 1 meminta snapshot terenkripsi yang konsisten dari core.
2. Untuk M2 awal, snapshot dapat dibatasi pada sesi yang sudah berhenti/terputus. Streaming upload saat recorder aktif adalah perluasan berikutnya dengan snapshot prefix yang eksplisit.
3. Worker mendaftarkan rekaman, meminta signed URL, mengunggah bytes yang tersedia, lalu memanggil commit.
4. Backend mengembalikan receipt yang mengikat ID/index/hash.
5. Worker meneruskan receipt ke core. Core memvalidasi kecocokan dengan snapshot sebelum mengubah status lokal.
6. Snapshot tidak memberi izin menghapus segmen/DEK; core mengelola retention dan transisi kunci.
7. App tidak membuka tabel Room internal, merekonstruksi DEK untuk upload, atau membuat ulang ciphertext saat retry.

### 6.4 Batas teknis lain

- Bentuk timestamp transport: ISO 8601 UTC; waktu perangkat dan server tetap berbeda field.
- Hash: SHA-256 hex lowercase; data biner API: base64 dengan varian/padding yang dipin dalam kontrak.
- ID rekaman dibuat core dan tidak diubah server.
- Semua format diberi version. Error ditranslasikan ke pesan produk tanpa membeberkan secrets.
- DTO jaringan dibuat Orang 1; codec paket kriptografi dibuat Orang 2. DTO tidak boleh mengubah bytes yang telah ditandatangani.
- API yang belum tersedia ditandai unsupported/pending. Tidak ada shared DB palsu atau acknowledgment buatan untuk melewati milestone.

## 7. Urutan kerja dan checkpoint bersama

### Tahap A — fondasi

Orang 2 menyiapkan empat modul dan facade minimum, pin dependencies, lalu membagikan commit fondasi. Orang 1 menyiapkan Supabase secara paralel. Setelah kontrak tersedia, Orang 1 membangun layar menggunakan fake facade yang jelas berlabel.

### Tahap B — pekerjaan paralel

- Orang 2: crypto/codec tests -> recorder -> atomic local storage -> playback -> demonstrasi Shamir.
- Orang 1: shell UI -> database/otorisasi -> API/upload -> client/worker.
- Jangan menunggu semua layar selesai sebelum mencoba integrasi komponen recorder.

### Tahap C — integrasi pertama

Target integrasi pertama hanya beranda aplikasi utama yang menampilkan komponen recorder asli, satu rekaman terenkripsi muncul di brankas, dan playback melalui core berhasil. Backend belum menjadi syarat tahap ini.

### Tahap D — integrasi cloud

Target: paket terenkripsi yang sama berhasil diunggah, retry tidak menggandakan/mengubah data, dan status UI berasal dari receipt nyata. Rekaman demo Shamir lokal tidak otomatis dianggap rekaman integrated; patuhi snapshot/pairing PRD.

### Tahap E — beberapa perangkat

Orang 1 mengerjakan UI/API pairing dan permintaan akses. Orang 2 mengerjakan envelope/signature/recovery. Uji pada perangkat/akun berbeda sebelum mengklaim pembukaan bersama selesai.

Estimasi satu malam hanya dipakai untuk menargetkan demo lokal. Dua orang tidak menghilangkan kebutuhan waktu integrasi, pengujian perangkat, dan penanganan kegagalan.

## 8. Acceptance criteria Orang 2

- `core-demo` dapat dibangun dan berfungsi tanpa backend, akun, atau kredensial.
- Tap singkat tidak merekam; long press memulai tepat satu sesi; lepas jari tidak menghentikan.
- Izin ditolak/dicabut dan kegagalan mikrofon menghasilkan state yang benar.
- Rekaman asli disimpan sebagai segmen terenkripsi, termasuk tail buffer pada stop normal.
- Enkripsi/dekripsi mengembalikan PCM byte-identik; perubahan header/tag/ciphertext ditolak.
- Tidak ada nonce ganda per DEK; restart membuat sesi/kunci baru; retry memakai ciphertext sama.
- Shamir semua pasangan 2-of-3 menghasilkan DEK identik; kurang bagian/duplicate index ditolak.
- Playback hanya menerima PCM segmen setelah autentikasi; tidak membuat audio terbuka di file cache.
- Crash/force-stop menghasilkan rekaman parsial yang terlihat; segmen final tidak hilang hanya karena indeks belum sempat commit.
- Core menghasilkan snapshot upload stabil dan tidak bergantung API server untuk perekaman lokal.
- Main app dapat memakai komponen/facade tanpa mengakses private database atau key internals.
- Tes signature/HPKE dan manifest dilaporkan sesuai milestone; jangan mencentang fitur yang belum dikerjakan.

## 9. Acceptance criteria Orang 1

- Layar pendukung berjalan memakai kontrak yang sama dengan core, dan mode fake teridentifikasi.
- Aplikasi utama memakai recorder/player asli dari Orang 2, tanpa implementation copy.
- Akun A tidak dapat mengakses rekaman B dengan mengganti ID/path.
- Seluruh tabel produk menerapkan akses langsung deny-by-default sesuai PRD; API privileged memeriksa otorisasi tiap operasi.
- Server tidak memiliki key/share terbuka dan tidak melakukan dekripsi.
- Upload idempotent, commit memverifikasi file, dan retry tidak mengubah ciphertext.
- Signed URL serta token tidak tercetak dalam log; secrets server tidak berada dalam aplikasi.
- State tersimpan lokal, tersalin server, envelope terunggah, dan acknowledgment pemegang tidak disamakan.
- Keputusan+release dipersistenkan atomik dan request expired/cancelled menolak tindakan berikutnya.
- Dokumen setup dan hasil tes menyebutkan yang benar-benar dijalankan serta yang belum dapat diuji.

## 10. Deliverables dan handoff

### Dari Orang 2 kepada Orang 1

1. Commit modul `core-crypto`, `recording-core`, dan `core-demo` yang build.
2. Kontrak facade, model, error, state, dan contoh pemanggilan Compose.
3. Codec `.swseg`, manifest, share envelope, dan signature sesuai milestone.
4. Snapshot paket terenkripsi dari data simulasi untuk pengujian parser/upload; jangan menyertakan key/share plaintext dalam Git.
5. Panduan permission/service/manifest merging dan dependency yang diperlukan aplikasi utama.
6. Hasil tes, langkah menjalankan demo, batas fitur, dan daftar pekerjaan lanjutan.

### Dari Orang 1 kepada Orang 2

1. Migration dan API specification dengan payload contoh non-sensitif.
2. Konfigurasi local backend/example environment tanpa secrets.
3. API client atau metode integrasi, format receipt, dan kode error.
4. Langkah akun/perangkat uji, pairing, upload, dan approval.
5. Hasil uji otorisasi serta daftar perubahan kontrak yang diperlukan.

Tidak ada milestone yang dianggap selesai hanya berdasarkan screenshot atau mock. Sertakan langkah reproduksi dan hasil build/test aktual. Bila SDK/perangkat/dependency tidak tersedia, tulis hambatan spesifik dan jangan mengklaim tes lulus.

## 11. Prompt siap pakai untuk Codex saya — Orang 2

Salin prompt ini dan lampirkan `prd.md` beserta brief ini:

```text
Saya berperan sebagai ORANG KEDUA dalam proyek SwaraLara.

Baca prd.md dan brief_pembagian_tugas_swaralara.md. Tugasmu adalah mengimplementasikan seluruh inti lokal: gestur tekan lama, izin mikrofon, AudioRecord, foreground service, segmentasi audio, AES-GCM per segmen, Shamir Secret Sharing, Android Keystore, penyimpanan terenkripsi, crash recovery, verifikasi, dan playback.

Buat core-crypto sebagai library Kotlin/JVM, recording-core sebagai Android library, dan core-demo sebagai aplikasi Android mandiri. Core-demo harus benar-benar berjalan tanpa akun, backend, internet, atau Supabase key. Gunakan library yang sama untuk demo dan aplikasi utama; jangan menulis pipeline kedua khusus demo.

Mulai dengan membaca instruksi repo dan memeriksa toolchain. Jika repo kosong, siapkan fondasi Gradle serta scaffold app minimal yang nantinya menjadi milik Orang 1. Jika repo sudah ada, adaptasikan tanpa menimpa pekerjaan yang tersedia. Pin versi dependency yang telah diverifikasi kompatibel.

Prioritaskan M0 dan M1. Target pertama: tahan tombol -> rekam -> enkripsi bertahap -> simpan lokal -> demonstrasi pemulihan kunci -> verifikasi -> putar kembali. Implementasikan fungsi nyata, jangan mengganti crypto atau recorder dengan mock. Gunakan rekaman simulasi.

Gesture dan komponen status recorder adalah tanggung jawabmu. Sediakan komponen Compose RecorderPanel dan SecurePlaybackPanel, facade publik, serta model/state/error agar Orang 1 dapat memasangnya tanpa mengubah internal modul. Simpan kontraknya di docs/core-contract.md.

Ikuti persis format .swseg dan aturan nonce/AAD di PRD. Audio terbuka, private key, DEK, dan bagian Shamir tidak boleh disimpan ke log, file sementara, Room terbuka, atau Git. Berkas upload adalah ciphertext yang sudah tersedia, bukan hasil enkripsi ulang saat retry.

Jangan menunggu backend agar demo lokal bekerja. Jangan mengimplementasikan Supabase/server decrypt atau memperluas scope ke AI/SOS/web. Siapkan interface snapshot/receipt untuk integrasi, dan kerjakan HPKE serta pembukaan beberapa perangkat setelah demo lokal lulus.

Jalankan pengujian yang relevan serta build jika lingkungan mendukung. Di akhir, laporkan file/modul yang dibuat, perintah yang benar-benar dijalankan, fitur selesai/belum selesai, langkah menjalankan core-demo, dan kebutuhan integrasi untuk Orang 1. Jika ada hambatan lingkungan, jelaskan secara spesifik tanpa mengklaim hasil pengujian yang belum dilakukan.
```

## 12. Prompt siap pakai untuk Codex rekan — Orang 1

```text
Saya berperan sebagai ORANG PERTAMA dalam proyek SwaraLara.

Baca prd.md dan brief_pembagian_tugas_swaralara.md. Tugasmu adalah aplikasi utama Android beserta layar pendukung, autentikasi, Supabase backend, database, Edge API, private Storage, API client, sinkronisasi, dan UI permintaan/persetujuan akses.

Inti gestur, recorder, kriptografi, Keystore, Room rekaman, pemulihan, dan player menjadi tanggung jawab Orang 2. Jangan menulis implementasi paralel untuk bagian tersebut. Gunakan facade dan komponen dari docs/core-contract.md; bila belum tersedia, gunakan fake repository berlabel demo dan catat kebutuhan integrasinya.

Kerjakan app/ dan supabase/. Jangan mengubah internal core-crypto, recording-core, atau core-demo. Koordinasikan perubahan root Gradle/version catalog dengan Orang 2. Gunakan fondasi repo yang sama, bukan membuat proyek kedua yang tidak kompatibel.

Implementasikan migration 14 tabel, constraint/index, kontrol akses API-gated dan RLS deny-by-default, serta Edge API dengan JWT dan otorisasi per-resource. Server tidak menerima audio terbuka, DEK/private key, atau bagian Shamir terbuka; tidak ada endpoint decrypt/combine-shares.

Implementasikan worker yang mengunggah ciphertext dari snapshot core. Retry harus idempotent dan tidak mengubah ciphertext/nonce. Commit server memverifikasi objek/hash/header dan menghasilkan receipt yang diteruskan ke core. Jangan menghapus file atau DEK dengan mengakses internal Room/core secara langsung.

Prioritaskan shell UI, migration, endpoint dasar, pengujian isolasi user, lalu integrasi recorder/vault/playback asli. Lanjutkan pairing dan approval beberapa perangkat setelah alur dasar berjalan. Jangan mengklaim UI mock sebagai fitur integrated.

Jalankan tes/build yang relevan dan dokumentasikan setup lokal, konfigurasi contoh tanpa secrets, payload API, hasil tes aktual, fitur yang belum selesai, dan kebutuhan handoff ke Orang 2. Jangan deploy atau reset database produksi tanpa instruksi eksplisit.
```

## 13. Checklist sebelum mulai bekerja paralel

- [ ] Kedua orang menggunakan PRD dan brief versi yang sama.
- [ ] Repo/branch dan pemilik folder sudah jelas.
- [ ] Fondasi build serta versi dependency disepakati melalui commit bersama.
- [ ] Orang 2 dapat menjalankan core-demo tanpa backend.
- [ ] Orang 1 memahami bahwa recorder/crypto/player berasal dari core Orang 2.
- [ ] Kontrak state, ID, snapshot, receipt, error, serta format bytes tersedia.
- [ ] Jadwal integrasi pertama ditetapkan sebelum fitur lanjutan dikerjakan.
- [ ] Data uji adalah simulasi; tidak ada secrets atau rekaman nyata di Git.
