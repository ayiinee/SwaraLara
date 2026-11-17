# SwaraLara — Product Requirements & Implementation Brief

Versi: 1.0 · Tanggal: 17 November 2026 · Bahasa produk: Indonesia

> Instruksi untuk Codex: gunakan dokumen ini sebagai spesifikasi implementasi. Mulai dari milestone M0 dan M1. Selesaikan satu alur nyata sebelum menambah layar atau fitur. Jangan mengklaim fitur selesai jika masih berupa mock, dan jangan menyatakan sistem siap untuk pengaduan nyata berdasarkan demo. Bila repositori sudah ada, baca instruksi proyek dan pertahankan pekerjaan pengguna.

## 1. Identitas dan tujuan

**Judul akademik:** SwaraLara: Sistem Preservasi Rekaman Pengaduan Kekerasan Seksual Berbasis Enkripsi AES-GCM dan Shamir Secret Sharing dengan On-Demand Recording Berbasis Gestur.

SwaraLara membantu pengguna memulai perekaman audio saat menghadapi ancaman, pemaksaan, atau pelecehan verbal yang sedang berlangsung. Audio diamankan pada perangkat, disimpan bertahap, dan pada tahap integrasi dapat dipulihkan melalui bagian kunci yang dipegang pihak tepercaya. Pengguna juga dapat merekam penuturan setelah kejadian dan menambahkan kronologi.

Rekaman kejadian dan rekaman penuturan pengguna harus dibedakan melalui label. Pemeriksaan keutuhan file tidak membuktikan kebenaran isi, identitas pembicara, atau waktu kejadian secara independen. Produk tidak menentukan bahwa suatu ucapan merupakan tindak pidana. Ketiadaan rekaman tidak boleh ditampilkan sebagai alasan seseorang tidak dapat mencari bantuan atau menyampaikan pengalaman.

### Hasil yang dituju

1. Aktivasi perekaman melalui tekan lama dengan status berhasil/gagal yang jelas.
2. Segmen audio dienkripsi sebelum ditulis ke penyimpanan persisten.
3. Rekaman yang telah diamankan tetap dapat dibaca kembali melalui alur pemulihan yang sah.
4. Pengunggahan dapat dilanjutkan setelah gangguan jaringan.
5. Server tidak menerima audio terbuka, kunci AES utuh, atau bagian Shamir terbuka.
6. Perubahan segmen, ketidaklengkapan terhadap manifest, dan kegagalan autentikasi ditampilkan secara jelas.

## 2. Batas implementasi dan prioritas

**Satu malam adalah target prototipe lokal, bukan seluruh sistem.** Jangan memaksakan semua milestone ke satu sesi. Build tanpa backend harus dapat dijalankan.

| Milestone | Lingkup | Definisi selesai |
|---|---|---|
| M0 — fondasi | Android project, dependency lock/version catalog, navigasi, fake repository | Build debug dan pengujian modul crypto dapat dijalankan |
| M1 — demo lokal | Tekan lama, AudioRecord, AES-GCM per segmen, Room, brankas, pemutaran lokal, demo Shamir | Satu rekaman simulasi dapat direkam, diamankan, dipulihkan, dan diputar; perubahan ciphertext ditolak |
| M2 — cloud | Auth, migrations, Edge API, private Storage, antrean sinkronisasi | Unggah idempotent dan isolasi antaruser terbukti |
| M3 — beberapa perangkat | Pemasangan pihak tepercaya, envelope bagian kunci, permintaan akses, pelepasan bagian | Dua/lebih perangkat berbeda menjalankan kebijakan ambang tanpa bagian terbuka melewati server |
| M4 — penguatan | Segmen bertanda tangan, manifest, audit, pengujian crash/perangkat, penanganan pergantian perangkat | Kriteria integritas dan ketahanan yang tercantum di dokumen ini diuji |

M1 memakai data simulasi. Demo Shamir di satu perangkat harus diberi label **Demo algoritma lokal** dan tidak disebut distribusi ke pendamping. UI fitur M2–M4 yang belum tersedia harus dinonaktifkan dengan keterangan tahap, bukan menampilkan keberhasilan palsu.

M2 dapat diuji memakai akun/perangkat uji yang public key-nya benar-benar didaftarkan dan hubungan kepercayaannya dibentuk melalui API; UI pemasangan baru diselesaikan pada M3. Jangan seed key privat/share. Rekaman fallback yang dibuat sebelum snapshot kelompok tersedia tetap lokal pada v1; jangan mengunggahnya dengan snapshot/acknowledgment buatan. Migrasi rekaman fallback ke kebijakan bersama merupakan pekerjaan lanjutan yang eksplisit.

### Di luar versi awal

- Pengiriman SOS, lokasi, atau pesan kepada orang lain secara otomatis.
- Integrasi pengaduan resmi dengan lembaga/polisi.
- Perekaman sebelum aktivasi, perekaman panggilan telepon, atau perekaman mikrofon tanpa batasan sistem operasi.
- Penghilangan indikator mikrofon/notifikasi Android, penyamaran aplikasi, atau penyalahgunaan Accessibility Service.
- AI untuk klasifikasi pelecehan, transkripsi otomatis, identifikasi pembicara, dan deteksi deepfake.
- Publikasi rekaman, unggahan konten intim, blockchain, dan pelepasan rekaman karena check-in terlewat.
- Dashboard web dan iOS. Dahulukan aplikasi Android dengan peran yang berbeda.
- Jaminan anti-penghapusan oleh administrator server atau pencabutan file yang sudah diunduh penerima.

## 3. Stack dan keputusan teknis

| Lapisan | Pilihan | Catatan implementasi |
|---|---|---|
| Mobile | Kotlin, Jetpack Compose, Material 3, Navigation Compose | Satu aplikasi untuk pemilik, pemegang bagian, dan penerima |
| Arsitektur | MVVM, repository, Kotlin Coroutines/Flow | Manual dependency injection cukup; hindari framework tambahan tanpa kebutuhan |
| Audio | AudioRecord, PCM 16-bit mono | Konfigurasi awal 16 kHz, periksa dukungan dan simpan konfigurasi aktual |
| Layanan | Foreground Service tipe microphone | Aktivasi awal dari Activity yang terlihat |
| Crypto audio | JCA Cipher AES/GCM/NoPadding, SecureRandom | AES-256, nonce 12 byte, tag 16 byte |
| Secret sharing | Bouncy Castle lightweight threshold API | Shamir GF(256), rahasia 32 byte; jangan mengganti provider crypto Android secara global |
| Envelope bagian | Google Tink Hybrid Encryption, HPKE | DHKEM X25519 + HKDF-SHA256 + AES-256-GCM; cek template/API yang tersedia pada versi terpilih |
| Kunci lokal | Android Keystore + keyset Tink yang dienkripsi | Private HPKE keyset terbungkus lokal; bukan klaim X25519 disimpan langsung sebagai kunci hardware |
| Tanda tangan | JCA SHA256withECDSA, P-256 | Kunci signing terpisah dari HPKE dan DEK |
| Lokal | Room + internal files + DataStore | Room bukan database terenkripsi secara otomatis; isi sensitif harus dienkripsi terpisah |
| Sinkronisasi | WorkManager + coroutine saat sesi aktif | Worker untuk retry, bukan jaminan upload langsung pada setiap kondisi |
| Backend | Supabase Auth, PostgreSQL, Storage | Private bucket; akses rekaman melalui Edge API |
| Server API | Deno/TypeScript Supabase Edge Functions | Satu router api dengan service layer, validator, dan repository |
| Kotlin client | supabase-kt + Ktor Android/OkHttp engine | Ikuti dokumentasi Supabase Kotlin yang sesuai dengan versi dipin |
| Serialization | kotlinx.serialization, JSON | Untuk objek biasa; format crypto biner ditetapkan pada bagian 8 |
| Pengujian | JUnit, Android instrumented tests, Deno tests, pgTAP/SQL integration | Uji perilaku, otorisasi, dan kegagalan penting |

### Versi dan kompatibilitas

- `applicationId`: `id.swaralara.app`; namespace sama.
- Usulan `minSdk = 26`; compile/target SDK mengikuti versi stabil dan persyaratan distribusi saat implementasi.
- Gunakan Android Studio stabil dan Gradle JDK yang kompatibel dengan AGP yang dipilih. Jangan menebak kombinasi versi AGP/Gradle/Kotlin/Compose.
- Pin versi yang sudah diverifikasi dalam `gradle/libs.versions.toml`, Gradle wrapper, dan import map/lock Deno. Jangan memakai `latest`, `+`, atau SNAPSHOT.
- Lakukan compatibility spike kecil: AES-GCM, Bouncy Castle split/recover, dan Tink hybrid round-trip pada emulator/perangkat sebelum mengerjakan M3.
- Jika HPKE template tidak tersedia pada dependency yang dipilih, laporkan hasil verifikasi dan pilih versi resmi yang mendukungnya. Jangan membuat implementasi HPKE sendiri atau diam-diam beralih algoritma.
- HPKE menggantikan usulan RSA-OAEP sebelumnya untuk envelope bagian kunci. Algoritma utama audio dan secret sharing tetap AES-GCM dan Shamir. Ini adalah keputusan rancangan v1 agar format envelope ditangani pustaka.

## 4. Setup dari repositori kosong

### 4.1 Struktur repositori yang dituju

```text
swaralara/
  android/
    app/src/main/java/id/swaralara/app/
      MainActivity.kt
      SwaraLaraApplication.kt
      core/{di,model,security,util}/
      data/{local,remote,repository}/
      domain/{model,repository,usecase}/
      feature/{onboarding,auth,home,recorder,vault,detail,trusted,requests,settings}/
      service/RecordingService.kt
      worker/UploadRecordingWorker.kt
    core-crypto/src/main/kotlin/id/swaralara/crypto/
    core-crypto/src/test/
    app/src/test/
    app/src/androidTest/
    gradle/libs.versions.toml
    local.properties.example
  supabase/
    config.toml
    migrations/
    functions/api/{index.ts,router.ts,auth.ts,validation.ts}/
    functions/api/services/
    functions/api/repositories/
    tests/
    seed.sql
  docs/{architecture.md,crypto-format.md,api.md,testing.md,decisions.md}
  README.md
  prd.md
  .gitignore
```

Keterangan: direktori `{a,b}` di atas adalah notasi ringkas; buat direktori terpisah. Jangan menambah modul Gradle per layar. Modul JVM `core-crypto` menangani primitive/format yang tidak bergantung Android; adapter Keystore berada di aplikasi Android.

### 4.2 Urutan setup

1. Periksa toolchain lokal, Android SDK, Java, Gradle, Supabase CLI, dan Docker. Catat yang tersedia; jangan mengaku menjalankan build Android jika SDK tidak ada.
2. Buat proyek Empty Activity Compose di `android/`, Gradle Kotlin DSL, version catalog, dan wrapper. Jangan menimpa proyek yang sudah ada.
3. Buat mode `localDemo` yang berjalan tanpa kredensial server dan mode `connected` untuk backend. `localDemo` tidak boleh memakai data autentikasi palsu untuk memanggil cloud.
4. Implementasikan interface repository agar mode demo dan connected memakai kontrak domain yang sama.
5. Implementasikan M1 terlebih dahulu, kemudian jalankan unit test dan build debug.
6. Untuk M2, inisialisasi Supabase dari root repositori dan jalankan lingkungan lokal. Jangan melakukan `init` jika folder sudah ada.

```bash
supabase init
supabase start
supabase db reset
supabase functions serve api --env-file supabase/.env.local
```

`db reset` hanya untuk database lokal disposable. Jangan menjalankan perintah reset terhadap proyek hosted. Jika CLI tidak tersedia, siapkan migration dan petunjuk eksekusi tanpa membuat hasil palsu.

7. Masukkan konfigurasi Android melalui `local.properties` yang diabaikan Git. Buat file contoh dengan nilai placeholder.

```properties
SUPABASE_URL=<project-url-or-local-api-url>
SUPABASE_PUBLISHABLE_KEY=<publishable-key>
```

Untuk emulator Android, akses host lokal umumnya melalui `10.0.2.2`, bukan `localhost`. Verifikasi port hasil `supabase status`. Perangkat fisik memakai alamat yang benar-benar dapat dijangkau. HTTP lokal hanya di debug dengan network security config terbatas; connected release wajib HTTPS.

8. Backend membaca `SUPABASE_URL`, publishable key yang relevan, dan server-only service secret/service-role melalui environment resmi deployment. Ikuti nama variabel SDK/CLI versi terpilih. Token user divalidasi; jangan memakai API key publik sebagai bukti identitas user.
9. Seed hanya akun uji dan metadata simulasi. Jangan memasukkan kata sandi tetap produksi, kunci privat, DEK, atau bagian Shamir ke seed/repo/log.
10. Dokumentasikan cara membuat dua/tiga akun uji dan memasangkan dua/tiga perangkat. Keterbatasan email lokal dijelaskan melalui mail catcher lingkungan lokal.

Kunci publishable memang dapat berada pada aplikasi; service secret/service-role tidak boleh masuk APK. Jangan mencetak environment lengkap. Kredensial hosted yang belum tersedia tidak menghalangi implementasi mode demo atau migration lokal.

## 5. Aktor dan kebijakan kunci

| Aktor | Kewenangan |
|---|---|
| Pemilik/pengguna | Merekam, menambah kronologi, menentukan kelompok pemegang, meminta pembukaan, melihat metadata miliknya |
| Pemegang bagian | Memiliki satu bagian terenkripsi, menyetujui/menolak permintaan pelepasan bagi rekaman yang ditugaskan |
| Penerima | Mengajukan pembukaan, menerima bagian terenkripsi untuk perangkatnya, memulihkan dan memutar pada perangkat tersebut |
| Operator backend | Mengoperasikan layanan; tidak diberikan private key, DEK, atau bagian terbuka melalui rancangan aplikasi |

Role ini berbasis hubungan pada rekaman, bukan satu kolom `role` global pada profil. Satu user dapat menjalankan beberapa peran pada rekaman berbeda. Tidak ada admin yang dapat menyetujui pembukaan sendirian.

### Dua kebijakan yang didukung M3

| Policy code | Pemegang | Ambang | Konsekuensi yang harus disetujui saat setup |
|---|---|---|---|
| `owner_required_2of2` | Pemilik + satu pihak tepercaya | 2 dari 2 | Pemilik wajib menyumbang bagian; kehilangan salah satu bagian dapat menghalangi pemulihan |
| `recovery_2of3` | Pemilik + dua pihak tepercaya | 2 dari 3 | Dua pihak tepercaya dapat bekerja sama membuka tanpa bagian pemilik |

Default tampilan onboarding adalah `owner_required_2of2`, tetapi setup belum sah sebelum pengguna memilih/menyetujui konsekuensinya. M1 memakai `demo_2of3`, tidak dapat diunggah sebagai rekaman integrated. Jangan mengklaim Shamir 2-of-3 menjamin veto korban. Perubahan pihak tepercaya berlaku untuk rekaman baru; perubahan kebijakan rekaman lama memerlukan protokol rekey dan berada di luar v1.

## 6. Frontend: layar dan interaksi

### 6.1 Onboarding dan kesiapan

- Jelaskan fungsi, batas perekaman sejak aktivasi, serta perbedaan rekaman kejadian/penuturan.
- Minta izin mikrofon pada konteks yang tepat; sediakan uji mikrofon dengan rekaman simulasi.
- Tampilkan status: mikrofon siap, ruang penyimpanan cukup, konfigurasi pemegang tersedia, jaringan tersedia/tidak tersedia.
- Jika setup kepercayaan belum selesai, pengguna tetap bisa merekam dengan penyimpanan lokal. Beri label **Perlindungan lokal — belum memiliki pemulihan bersama**. Jangan menjanjikan pemulihan setelah perangkat hilang.
- Pemilihan kebijakan, pemasangan perangkat, dan login dilakukan sebelum situasi mendesak.

### 6.2 Beranda dan perekaman

- Tombol utama: **Tahan untuk merekam**. Ambang awal 1.500 ms, dapat diubah lewat konfigurasi pengujian.
- Lepas sebelum ambang: batalkan. Setelah ambang, mulai tepat satu sesi dan abaikan sentuhan ganda.
- Jangan menampilkan **Merekam** sebelum AudioRecord sukses masuk status recording. Getaran singkat mengikuti konfirmasi ini, dengan preferensi pengguna.
- Tampilkan durasi, status audio, jumlah segmen aman lokal, dan status sinkronisasi secara terpisah.
- Tombol **Hentikan** adalah aksi berbeda dari pelepasan jari. Setelah berhenti, tampilkan detail/status penyimpanan.
- Perekaman berlanjut ketika navigasi layar berubah; service, bukan ViewModel, memiliki recorder.
- Tidak ada dialog izin, login, atau pilihan penerima yang wajib diisi setelah tombol darurat ditekan jika kesiapan sudah selesai.
- Bila izin belum ada/dicabut atau mikrofon gagal, beri status gagal dan langkah pemulihan; jangan menampilkan keberhasilan palsu.
- Notifikasi foreground bersifat faktual dan memuat aksi berhenti. Jangan menjanjikan perekaman tidak terlihat.

### 6.3 Brankas dan detail

- Daftar: label netral, waktu perangkat, durasi, tipe rekaman, status capture/sync/recovery/integrity.
- Jangan menampilkan cuplikan kronologi sensitif di daftar/notifikasi default.
- Detail: pemutaran, kronologi terenkripsi, status pihak pemegang, status unggah, hasil pemeriksaan, dan riwayat.
- Status **Tersimpan lokal** berbeda dari **Tersalin ke server**, dan **Bagian pemulihan diterima** berbeda dari **Envelope baru diunggah**.
- Rekaman terputus tetap terlihat. Jangan otomatis menghapusnya atau menandainya lengkap.

### 6.4 Pihak tepercaya

- Undangan satu kali melalui QR/token acak. Tampilkan identitas perangkat dan fingerprint signing/HPKE.
- Kedua pihak mengonfirmasi pasangan yang sama. Tidak ada pencarian direktori semua user melalui email.
- Pemegang harus menerima undangan; pemilik tidak dapat mendaftarkan akun lain secara sepihak.
- Rekam fingerprint yang sudah diverifikasi secara lokal; penggantian kunci membutuhkan pemasangan ulang.

### 6.5 Permintaan akses

- Tampilkan rekaman yang diminta, pemohon, perangkat penerima, masa berlaku, dan kebijakan ambang.
- Pemegang memilih setuju/tolak. Persetujuan baru dianggap menyumbang bagian setelah envelope pelepasan yang valid tersedia.
- Setelah bagian cukup, lakukan rekonstruksi lokal dan pemeriksaan sebelum pemutaran.
- Pemilik melihat permintaan yang terkait rekamannya. Expiry/revocation menghentikan pelepasan/download berikutnya, bukan menghapus salinan yang sudah keluar.

### 6.6 Gaya dan aksesibilitas

- Bahasa Indonesia sederhana, nada tenang, latar terang, teks kontras, target sentuh minimal mengikuti panduan Android, dukungan font scaling/TalkBack.
- Usulan warna: plum `#6B3F69`, latar `#FAF7FA`, teks `#211C24`; merah hanya untuk kegagalan/tindakan berisiko.
- Jangan memunculkan pilihan yang menyalahkan korban atau mewajibkan kategori hukum.
- Tampilkan detail algoritma di halaman informasi, bukan mengganggu aktivasi darurat.

## 7. Perekaman, penyimpanan lokal, dan state machine

### 7.1 Parameter awal

- PCM signed 16-bit little-endian, satu kanal, target 16.000 Hz.
- Segmen target 2.000 ms; pada konfigurasi tersebut sekitar 64.000 byte audio per segmen.
- PCM 16 kHz mono 16-bit sekitar 1,92 MB per menit, sebelum envelope/metadata. Durasi segmen dan sample rate adalah parameter prototipe, bukan hasil validasi pengguna.
- Gunakan `AudioRecord.getMinBufferSize`; ukuran read buffer bukan harus sama dengan ukuran segmen. Akumulasi read positif sampai segmen siap; tangani partial read, error, audio silenced, dan buffer overrun.
- Tidak memakai speech recognition. Audio asli tidak diedit/ditingkatkan; turunan di masa depan harus terpisah.

### 7.2 Pipeline

```text
AudioRecord -> buffer PCM di memori -> segmentasi -> AES-GCM
            -> tulis .tmp terenkripsi -> flush/close -> rename atomik
            -> commit indeks Room -> antrean unggah
```

Tidak ada PCM terbuka di file sementara, external storage, log, database, crash report, atau backup aplikasi. Plaintext buffer harus berumur pendek; penghapusan byte array dilakukan best effort tanpa klaim jaminan pembersihan seluruh memori JVM.

Simpan pada `filesDir/recordings/<recordingId>/segments/<index>.swseg`. Keystore/keyset/token/berkas rekaman dikecualikan dari backup otomatis sesuai konfigurasi Android. Batasi file ke internal storage dan jangan gunakan folder galeri.

### 7.3 Status terpisah

- Capture: `idle -> arming -> starting -> recording -> stopping -> sealed`; jalur gagal: `failed` atau `interrupted`.
- Sync: `local_only | queued | uploading | partial | synced | failed`.
- Recovery: `local_only | envelopes_queued | envelopes_uploaded | holders_acknowledged | degraded`.
- Integrity: `unverified | verified_complete | verified_partial | failed`.
- Request: `pending | ready | denied | cancelled | expired | completed`.

Jangan memakai satu kolom status untuk seluruh dimensi. `synced` hanya berarti semua objek yang diwajibkan sudah dikonfirmasi backend, bukan semua pemegang pasti dapat memulihkan.

### 7.4 Room entities

| Entity | Kolom utama |
|---|---|
| `LocalRecording` | id, kind, captureState, syncState, recoveryState, integrityState, sampleRate, channels, startedAtDevice, durationSamples, segmentCount, policyCode, manifestPath |
| `LocalSegment` | recordingId+index, path, ciphertextSha256, previousSha256, byteLength, samples, uploadedAt, retryCount |
| `LocalKeyEnvelope` | recordingId, envelopeKind, wrappedPayload, holderDeviceId, uploadedAt, acknowledgedAt |
| `LocalOutbox` | id, recordingId, operation, objectKey, state, attempt, nextAttemptAt, lastErrorCode |
| `LocalTrustedDevice` | relationshipId, userId, deviceId, pinnedHpkeFingerprint, pinnedSigningFingerprint, verificationStatus |
| `LocalSensitiveNote` | recordingId, revision, ciphertextPath, nonce, updatedAtDevice |

Room menyimpan metadata minimum. Judul bebas, kronologi, lokasi, identitas tambahan, serta nama berkas asal adalah payload terenkripsi, bukan string terbuka di tabel.

### 7.5 Crash dan batas sistem

- Service berjalan foreground dengan deklarasi permission/type yang sesuai versi Android. Jangan mengaktifkan mikrofon otomatis dari boot receiver.
- WorkManager mengunggah ulang data yang sudah ada; tidak merekam ulang setelah reboot.
- Jika proses mati, file `.tmp` yang tidak lengkap dibuang/diisolasi; segmen final yang belum masuk Room direkonsiliasi melalui format dan hash/signature.
- Jangan melanjutkan sesi lama dengan DEK/counter yang mungkin sudah terpakai. Mulai sesi baru dengan DEK dan ID baru; hubungkan sebagai lanjutan hanya melalui metadata.
- Jika penghentian normal, enkripsi sisa buffer sebagai segmen terakhir lalu buat manifest.
- Jika force-stop/reboot/perangkat kehabisan daya, tandai sesi terputus ketika aplikasi dibuka kembali. Bagian buffer yang belum disimpan dapat hilang.
- Keberlanjutan layar terkunci, microphone contention, panggilan masuk, battery optimization, dan ruang penuh harus diuji, bukan diasumsikan.

## 8. Spesifikasi kriptografi dan format data

### 8.1 Hierarki kunci

| Kunci | Pembuatan/lokasi | Tujuan |
|---|---|---|
| `DEK` | SecureRandom 32 byte, baru per recording, di memori saat rekam | AES-GCM audio dan rahasia yang dibagi Shamir |
| `LocalKEK` | AES-256 dalam Android Keystore, non-exportable | Membungkus DEK/keyset privat lokal |
| `DeviceSigningKey` | ECDSA P-256 dalam Android Keystore | Tanda tangan manifest, envelope, dan pelepasan |
| `DeviceHPKEKeyset` | Tink; private keyset disimpan terenkripsi oleh Keystore-backed protector | Membuka envelope bagian pada perangkat pemegang |
| `RequestHPKEKeyset` | Tink, baru per permintaan, privat terbungkus lokal | Menerima bagian untuk satu permintaan pembukaan |
| `NoteKey` | HKDF-SHA256 dari DEK dengan info domain terpisah | Enkripsi kronologi, terpisah dari nonce/key audio |

DEK harus dapat diekspor sementara di memori agar dibagi. Karena itu jangan membuat DEK sebagai kunci Keystore non-exportable lalu berharap dapat dibaca untuk Shamir. Keystore menyimpan KEK dan signing key; DEK disimpan lokal hanya sebagai envelope terbungkus.

Kunci lokal untuk perekaman tidak boleh mensyaratkan prompt biometrik setiap segmen/aktivasi. App lock untuk membuka brankas dapat ditambahkan terpisah. Login ulang tidak boleh menghapus file atau keyset yang masih dibutuhkan. Kehilangan perangkat/keyset tidak dipulihkan hanya dengan reset password akun.

### 8.2 AES-GCM per segmen

```text
DEK = SecureRandom(32)
noncePrefix = SecureRandom(8)
segmentIndex = UInt32, mulai 0
nonce = noncePrefix || UInt32BE(segmentIndex)      # 12 byte
AAD = fixedBinaryHeader                          # seluruh header di bawah
ciphertextAndTag = AES256GCM(DEK, nonce, AAD, pcm)
```

Keunikan nonce dijamin oleh satu sesi dengan DEK baru dan indeks monoton, bukan oleh timestamp. Tolak overflow counter. Tidak pernah melakukan enkripsi ulang isi berbeda dengan DEK+indeks yang sama. Retry upload memakai byte terenkripsi yang sudah tersimpan. Sesi setelah crash selalu DEK baru.

Format `.swseg` versi 1, urutan persis, integer big-endian kecuali payload PCM:

| Field | Byte | Isi |
|---|---:|---|
| magic | 4 | ASCII `SWL1` |
| recordingId | 16 | UUID raw |
| index | 4 | UInt32BE |
| sampleRate | 4 | UInt32BE |
| channels | 1 | 1 |
| pcmEncoding | 1 | 1 = signed PCM16LE |
| sampleCount | 4 | UInt32BE, jumlah frame per kanal |
| nonce | 12 | Prefix 8 byte + index 4 byte |
| previousObjectHash | 32 | SHA-256 seluruh `.swseg` sebelumnya; nol untuk index 0 |
| ciphertextLength | 4 | Ukuran ciphertext+tag |
| ciphertextAndTag | variabel | PCM terenkripsi + GCM tag 16 byte |

`AAD` adalah seluruh header 82 byte sampai ciphertextLength, termasuk nonce. `ciphertextLength = sampleCount * channels * 2 + 16`; validasi ukuran dan limit sebelum alokasi. Parser menolak extra/truncated bytes, magic salah, indeks salah, atau konfigurasi tidak didukung. GCM hanya mengeluarkan plaintext ke player setelah tag segmen berhasil diverifikasi.

`objectHash = SHA256(seluruh byte .swseg)`. Chain mengikat urutan segmen. Chain tanpa manifest/checkpoint terpercaya tidak membuktikan bahwa bagian akhir tidak dihapus.

### 8.3 Shamir dan envelope awal

- Pakai Bouncy Castle threshold API, secret length 32, CSPRNG. API untuk membagi DEK yang sudah ada adalah operasi seperti `resplit(secret, threshold, count)`; verifikasi pada versi yang dipin.
- Skema GF(256) dan mode/basis dipin sebagai `shamir-bc-gf256-v1` di docs serta metadata. Jangan menganggap format share lintas pustaka kompatibel.
- Buat adapter codec yang menyimpan koordinat x/shareIndex bersama byte share. Jangan hanya menyimpan y tanpa indeks.
- M1 harus menguji semua pasangan dari tiga bagian dan memastikan pemulihan DEK identik. Satu bagian ditolak oleh API aplikasi; jangan membuat fungsi yang mencoba menebak DEK.
- Share plaintext berisi recordingId, policy snapshot hash, shareIndex, scheme version, holderDeviceId, dan share bytes. Serialize sesuai codec yang didokumentasikan.
- Bungkus setiap share dengan Tink `HybridEncrypt` untuk public keyset perangkat pemegang. Context info mengikat protocol/version, recordingId, shareIndex, dan holderDeviceId.
- Enkripsi HPKE sendiri bukan bukti identitas pengirim. Signing key pemilik menandatangani hash envelope beserta binding di atas; pemegang memverifikasi terhadap fingerprint yang telah dipasangkan.
- Backend hanya menerima envelope ciphertext, signature, public identifiers, dan hash; tidak menerima byte share terbuka.
- Public key pemegang yang sudah dipasangkan disimpan lokal agar perekaman dan pembuatan envelope dapat berjalan offline. Jika key belum ada/berubah, simpan lokal dan tampilkan recovery degraded; jangan diam-diam memakai kunci baru dari server.
- Pemegang mengirim acknowledgment setelah berhasil membuka envelope dan memvalidasi struktur, bukan hanya setelah menerima notifikasi.

### 8.4 Manifest dan checkpoint

Manifest JSON memiliki schema `swl-manifest-v1`: recordingId, deviceId, policySnapshotHash, actual audio format, totalSegments, totalSampleFrames, finalCaptureState (`sealed`/`interrupted`), device start/end timestamps, serta daftar `{index, objectSha256, sampleCount}`.

- Simpan `manifestBytes` UTF-8 yang ditandatangani persis sebagai bytes/base64. Verifier memverifikasi byte asli sebelum parsing; tidak menandatangani hasil reserialize yang mungkin berbeda.
- Parser wajib strict schema, menolak duplicate keys, batas ukuran berlebihan, nomor ganda, dan indeks lompat. Urutan array adalah urutan segmen.
- `manifestSignature = SHA256withECDSA(DeviceSigningKey, manifestBytes)`. Simpan signature DER dan signing key fingerprint.
- Verifier Edge harus menangani format signature secara eksplisit: JCA biasanya mengeluarkan ASN.1 DER, sedangkan WebCrypto dapat memerlukan format IEEE P1363 (`r || s`). Gunakan adapter/pustaka yang diuji dengan vektor lintas Android–Deno; jangan menganggap keduanya langsung kompatibel atau melewatkan pemeriksaan karena format berbeda.
- Verifikasi signature, ID/binding, jumlah/urutan/hash, lalu setiap tag GCM. Cocokkan jumlah frame/durasi.
- M4 menambahkan signed checkpoint setiap segmen: recordingId, index, objectHash, previousObjectHash. Backend memberi waktu penerimaan sendiri setelah verifikasi. Ini mendukung pemeriksaan prefix yang tersimpan ketika final manifest tidak sempat dibuat.
- Checkpoint terputus ditampilkan **Bagian tersimpan terverifikasi; kelengkapan akhir tidak diketahui**, bukan **Rekaman lengkap**.
- Signing key yang sama dengan perangkat bukan bukti bahwa isi audio benar. Server juga tidak boleh mengubah waktu perangkat menjadi klaim waktu kejadian terpercaya.

### 8.5 Kronologi terenkripsi

`NoteKey = HKDF-SHA256(DEK, salt=recordingIdBytes, info="swaralara/notes/v1", L=32)`. Gunakan AES-GCM dengan nonce acak 12 byte baru per revisi, simpan nonce bersama ciphertext, dan AAD recordingId+revision. Retry mengirim ciphertext revisi yang sama; revision baru memakai nonce baru. Judul, uraian, lokasi opsional, dan label tambahan berada di payload ini.

### 8.6 Pembukaan beberapa perangkat

1. Pemohon membuat RequestHPKE keyset dan mengirim public keyset + signature permintaan dari perangkat terdaftar.
2. Backend memvalidasi identitas, hubungan terhadap rekaman, perangkat, masa berlaku, dan policy snapshot. Pemohon v1 hanya boleh anggota snapshot rekaman; penerima eksternal ditunda.
3. UI pemegang menampilkan pemohon/perangkat serta requestId. Pemegang memverifikasi signature dan binding; lalu membuka envelope bagiannya secara lokal.
4. Jika setuju, pemegang membungkus ulang share ke request public keyset. Context info mengikat requestId, recordingId, requesterDeviceId, shareIndex, dan expiry. Pemegang menandatangani ciphertext+binding itu.
5. Backend memvalidasi signature dan identitas pemegang, menyimpan ciphertext, dan menghitung shareIndex berbeda yang valid. Threshold tidak boleh dipilih pemohon.
6. Pemohon mengambil envelope pelepasan, memverifikasi tanda tangan pemegang, membuka menggunakan RequestHPKE private key, memeriksa binding, lalu merekonstruksi DEK di perangkat.
7. Verifikasi paket rekaman dan dekripsi lokal; jangan membuat endpoint server `decrypt`/`combine-shares`.
8. Setelah sesi, hapus plaintext buffer dan DEK di memori best effort. Jangan cache audio terbuka ke file.

`ready` pada server berarti jumlah envelope pelepasan dengan signature/binding sah sudah memenuhi kebijakan. Server tidak dapat memeriksa kebenaran isi share terenkripsi. Pemulihan masih dapat gagal pada client jika holder menyampaikan share rusak; Shamir dasar bukan verifiable secret sharing. Tampilkan kegagalan pemulihan tanpa menyatakan file asli telah berubah, dan jangan mengaku dapat mengetahui pemegang yang salah dari GCM failure saja. Pembuktian share yang lebih kuat berada di luar v1.

Masa berlaku tidak menghapus share yang sudah dibuka. Pemegang ambang yang berkolusi tetap dapat berbagi rahasia di luar aplikasi. Jangan menyebut workflow persetujuan sebagai jaminan mutlak pencegahan kolusi. Perangkat pengguna saat merekam juga memegang DEK utuh; Shamir mengatur pemulihan/distribusi sesudahnya, bukan mencegah perangkat sumber membaca audio.

### 8.7 Siklus hidup kunci lokal

- Saat merekam, DEK ada di memori dan tersimpan lokal dalam envelope Keystore untuk crash recovery.
- M1 menggunakan envelope lokal untuk playback dan eksperimen Shamir, dengan label demo.
- M3 mempertahankan envelope penuh selama konfigurasi belum aman/acknowledgment belum lengkap. Status harus jujur bahwa recovery bersama belum penuh.
- Setelah paket tersinkron dan seluruh pemegang yang diwajibkan telah acknowledgment, hapus envelope DEK utuh lokal menurut kebijakan yang disetujui; pemilik mempertahankan bagian Shamir miliknya.
- Pada integrated mode setelah transisi itu, pemilik juga menggunakan alur threshold untuk pembukaan. Jangan meninggalkan cache DEK tersembunyi yang melewati kebijakan.
- Pergantian/perusakan Keystore, uninstall, atau kehilangan perangkat dapat menghilangkan akses lokal. Jangan menghapus salinan lokal terakhir hanya karena satu endpoint upload mengembalikan HTTP 200.

## 9. Database PostgreSQL

Ini kontrak schema target. Buat migration SQL nyata, constraint, index, RLS, serta fungsi transaksi dari spesifikasi ini. Kolom `bytea` dikirim API sebagai base64; jangan menyimpan private key atau share terbuka di database.

### 9.1 Konvensi umum

- Primary key UUID. UUID objek offline dibuat client; backend memvalidasi ownership, tidak menggantinya saat retry.
- `created_at`, `updated_at`, `received_at` adalah `timestamptz` server UTC; UI mengubah zona tampilan. Waktu perangkat punya nama `*_device`.
- Timestamp tidak dijadikan ID, nonce, atau faktor keamanan.
- Enum/check constraint untuk state; text bebas dibatasi panjangnya. Snapshot kebijakan immutable setelah recording terdaftar.
- Foreign key terkait rekaman memakai composite key bila diperlukan untuk mencegah hubungan lintas recording/request/user.
- Relasi terhadap `auth.users` tidak diekspos sebagai direktori publik. Penghapusan akun memerlukan flow cleanup eksplisit, bukan cascade yang menghapus bukti/permintaan tanpa penjelasan.

### 9.2 Tabel dan kolom

| Tabel | Kolom dan tipe utama | Constraint/index penting |
|---|---|---|
| `profiles` | `id uuid PK FK auth.users`, `display_name text`, `created_at timestamptz` | Nama pendek/non-sensitif; email tetap dikelola Auth |
| `devices` | `id uuid PK`, `user_id uuid FK profiles`, `label text`, `hpke_public_keyset bytea`, `hpke_fingerprint text`, `signing_public_spki bytea`, `signing_fingerprint text`, `state text`, `created_at`, `revoked_at` | State active/revoked; index user_id; public keys immutable, rotasi = device baru |
| `trust_invitations` | `id uuid PK`, `owner_user_id`, `owner_device_id`, `token_hash bytea`, `expires_at`, `accepted_by_user_id nullable`, `accepted_device_id nullable`, `consumed_at nullable` | Token minimal 128-bit acak, hash unik, sekali pakai, TTL 15 menit; raw token tidak disimpan |
| `trusted_links` | `id uuid PK`, `owner_user_id`, `holder_user_id`, `owner_device_id`, `holder_device_id`, `state text`, `verified_at`, `created_at`, `revoked_at` | Dua pihak konfirmasi; no self-link; unique active relationship per pasangan/perangkat; device sesuai user |
| `recordings` | `id uuid PK`, `owner_user_id`, `source_device_id`, `kind text`, `policy_code text`, `threshold smallint`, `share_count smallint`, `policy_snapshot_bytes bytea`, `policy_snapshot_hash text`, `policy_signature bytea`, `sample_rate integer`, `channels smallint`, `pcm_encoding text`, `started_at_device timestamptz`, `capture_state text`, `sync_state text`, `recovery_state text`, `total_segments integer nullable`, `total_samples bigint nullable`, `created_at`, `sealed_at nullable` | Kind live_event/retrospective; owner index; valid policy/threshold/count; source device milik owner; immutable source/policy/audio format; demo policy dilarang di cloud |
| `recording_members` | `recording_id uuid FK`, `user_id uuid FK`, `device_id uuid FK`, `share_index smallint`, `member_kind text`, `hpke_fingerprint text`, `signing_fingerprint text`, `acknowledged_at nullable` | PK(recording_id,share_index); unique(recording_id,user_id); device milik user; snapshot fingerprints; tepat satu owner dan jumlah anggota sesuai policy |
| `recording_segments` | `recording_id uuid`, `segment_index integer`, `storage_path text`, `object_sha256 text`, `previous_sha256 text`, `byte_length integer`, `sample_count integer`, `checkpoint_bytes bytea nullable`, `checkpoint_signature bytea nullable`, `received_at` | PK(recording_id,segment_index); path unik/deterministik; index >=0; hash hex64 lowercase; metadata immutable setelah commit |
| `recording_manifests` | `recording_id uuid PK FK`, `manifest_bytes bytea`, `signature_der bytea`, `signing_fingerprint text`, `manifest_sha256 text`, `received_at` | Satu final manifest, immutable; duplicate identik idempotent, isi berbeda 409 |
| `encrypted_notes` | `recording_id uuid`, `revision integer`, `nonce bytea`, `ciphertext bytea`, `ciphertext_sha256 text`, `author_device_id uuid`, `created_at` | PK(recording_id,revision); append-only, author owner; nonce 12 byte, tag included; revision positif |
| `share_envelopes` | `recording_id uuid`, `share_index smallint`, `holder_device_id uuid`, `scheme_version text`, `envelope_ciphertext bytea`, `context_bytes bytea`, `owner_signature bytea`, `ciphertext_sha256 text`, `received_at`, `acknowledged_at nullable`, `ack_signature bytea nullable` | PK(recording_id,share_index); FK ke recording_members; tujuan terikat snapshot; immutable envelope |
| `access_requests` | `id uuid PK`, `recording_id uuid FK`, `requester_user_id uuid`, `requester_device_id uuid`, `request_hpke_public_keyset bytea`, `request_bytes bytea`, `request_signature bytea`, `state text`, `expires_at`, `created_at`, `completed_at nullable` | Pemohon anggota snapshot dan device terdaftar; expiry server maksimum 24 jam; threshold dari recording; index recording_id/state dan requester_user_id |
| `access_decisions` | `request_id uuid`, `recording_id uuid`, `share_index smallint`, `holder_user_id uuid`, `holder_device_id uuid`, `decision text`, `signed_decision_bytes bytea`, `decision_signature bytea`, `created_at` | PK(request_id,share_index); request/recording/member harus konsisten; decision approve/deny; satu keputusan final per request/share |
| `share_releases` | `request_id uuid`, `recording_id uuid`, `share_index smallint`, `holder_device_id uuid`, `release_ciphertext bytea`, `context_bytes bytea`, `holder_signature bytea`, `ciphertext_sha256 text`, `created_at` | PK(request_id,share_index); hanya untuk decision approve pada request sama; re-encrypted ke request key |
| `audit_events` | `id uuid PK`, `recording_id uuid nullable`, `request_id uuid nullable`, `actor_user_id uuid`, `actor_device_id uuid nullable`, `event_type text`, `metadata jsonb`, `created_at` | Server-only append; metadata allowlist teknis; index recording_id/created_at dan request_id; jangan isi kronologi/token/URL bertanda tangan |

Kolom waktu yang tidak diberi tipe pada tabel di atas semuanya `timestamptz`. ID user/device mengacu ke `profiles`/`devices`. Buat constraint hash, byte length, dan hubungan composite yang eksplisit dalam migration. Snapshot policy mencakup ID recording, policy, threshold, anggota+shareIndex+fingerprint. Signature pemilik mengikat snapshot ini agar server tidak dapat mengganti daftar pemegang tanpa terdeteksi client.

### 9.3 Contoh migration dasar

```sql
create table public.profiles (
  id uuid primary key references auth.users(id) on delete restrict,
  display_name text not null check (char_length(display_name) between 1 and 80),
  created_at timestamptz not null default now()
);

create table public.devices (
  id uuid primary key,
  user_id uuid not null references public.profiles(id) on delete restrict,
  label text not null check (char_length(label) between 1 and 80),
  hpke_public_keyset bytea not null,
  hpke_fingerprint text not null check (hpke_fingerprint ~ '^[0-9a-f]{64}$'),
  signing_public_spki bytea not null,
  signing_fingerprint text not null check (signing_fingerprint ~ '^[0-9a-f]{64}$'),
  state text not null default 'active' check (state in ('active','revoked')),
  created_at timestamptz not null default now(),
  revoked_at timestamptz,
  unique (id, user_id)
);
create index devices_user_id_idx on public.devices(user_id);

alter table public.profiles enable row level security;
alter table public.devices enable row level security;
revoke all on public.profiles, public.devices from anon, authenticated;
```

Contoh ini bukan migration lengkap. Implementer wajib menghasilkan seluruh tabel di atas dalam file migration berurutan. Tambahkan profil melalui bootstrap API setelah Auth berhasil, bukan menerima arbitrary user_id dari aplikasi. Pin `search_path` untuk fungsi privileged; revoke execute dari public/anon/authenticated bila fungsi hanya dipanggil server.

### 9.4 Model akses database dan Storage

Untuk v1 pilih model **API-gated**: seluruh operasi data produk melalui Edge API berautentikasi, bukan akses PostgREST bebas dari aplikasi. Aktifkan RLS pada semua tabel, revoke akses langsung `anon`/`authenticated`, dan jangan menambahkan policy `using (true)` untuk memudahkan demo.

Edge API boleh menggunakan service client server-only setelah JWT user diverifikasi dan semua pemeriksaan hubungan dilakukan. Service role melewati RLS; karena itu RLS bukan pengganti otorisasi endpoint. Buat satu service authorization bersama dan pengujian negatif untuk setiap route. Jangan memasukkan user_id dari request body sebagai actor; ambil actor dari JWT.

Storage:

- Bucket `swl-recordings`, private, MIME `application/octet-stream` dan batas ukuran objek yang sesuai segmen/manifest.
- Path segmen: `<ownerUuid>/<recordingUuid>/segments/<index-10-digit>.swseg`.
- Manifest/kronologi/envelope cukup di PostgreSQL bila ukurannya kecil; jika manifest membesar, pindahkan ke private object dengan metadata hash di DB dalam migration baru.
- Tidak ada direct write/delete/list policy untuk anon/authenticated. API menerbitkan signed upload URL hanya untuk path segmen milik owner dengan `upsert=false` dan TTL pendek yang didukung SDK.
- Signed read URL hanya diterbitkan untuk owner atau requester anggota yang memiliki request aktif `ready`; TTL usulan 60 detik. URL adalah bearer credential, jangan log/share.
- Memiliki signed read URL ciphertext tidak memberikan kunci, tetapi metadata dan aksesnya tetap dibatasi.
- Object yang telah commit tidak boleh ditimpa. Jika retry menemui object existing, verifikasi hash; identik = success, berbeda = 409.
- Tidak ada update/delete metadata segmen yang telah seal dari client. Penghapusan rekaman adalah flow terpisah yang menjelaskan dampak salinan; ditunda ke milestone lanjutan.
- Storage upload dan transaksi database tidak atomik bersama. Gunakan upload -> server verify object/hash -> commit row; orphan cleanup hanya terhadap upload belum terdaftar setelah grace period, tidak pernah terhadap rekaman parsial terdaftar.

## 10. Kontrak backend API

Base path: `/functions/v1/api`. Semua route kecuali health memerlukan bearer JWT user yang valid. Gunakan SDK auth server yang memverifikasi token (misalnya `getUser`/verified claims sesuai versi), bukan hanya decode JWT. Validator menerima field allowlist dan memberi batas ukuran body. Jangan mematikan verifikasi tanpa menambahkan pemeriksaan token setara di handler.

Envelope respons:

```json
{"data":{},"requestId":"uuid"}
```

```json
{"error":{"code":"FORBIDDEN","message":"Akses tidak tersedia."},"requestId":"uuid"}
```

| Method dan route | Fungsi dan aturan |
|---|---|
| `GET /health` | Hanya status layanan/version; tanpa secrets atau daftar user |
| `POST /bootstrap` | Buat/ambil profil pemilik JWT; tidak menerima role atau userId arbitrer |
| `POST /devices` | Daftar public keyset dan signing SPKI, proof-of-possession signature, label; ownership dari JWT |
| `GET /devices/me` | Daftar perangkat sendiri; metadata yang aman |
| `POST /trust/invitations` | Owner membuat token acak satu kali; backend menyimpan hash; rate limit |
| `POST /trust/accept` | User lain menyampaikan token dan device sendiri; consume atomik; status menunggu konfirmasi |
| `POST /trust/:id/confirm` | Konfirmasi fingerprint oleh kedua pihak; active hanya setelah keduanya setuju |
| `GET /trust` | Hanya hubungan pihak yang login |
| `POST /recordings` | Daftar rekaman offline, snapshot, public parameters/signature; validasi source device, policy, anggota aktif; create idempotent |
| `GET /recordings` | Daftar milik sendiri atau yang dipegang sesuai view; pagination cursor, maksimum 50 |
| `GET /recordings/:id` | Metadata minimum untuk owner/member; member tidak otomatis mendapat seluruh envelope milik orang lain |
| `POST /recordings/:id/segments/upload-url` | Owner meminta URL untuk indeks/path pasti; batasi ukuran, validasi state dan recording ownership |
| `POST /recordings/:id/segments/commit` | Backend baca object, cek byte length/hash/header/binding/checkpoint jika ada, baru insert row; jangan percaya hash deklarasi client |
| `PUT /recordings/:id/manifest` | Owner, verifikasi signature dan daftar segmen yang telah commit, hash/frame lengkap; immutable |
| `POST /recordings/:id/notes` | Owner append revisi terenkripsi; validasi ukuran/nonce/hash tanpa membuka isi |
| `GET /recordings/:id/notes` | Owner atau requester ready; hanya ciphertext |
| `POST /recordings/:id/share-envelopes` | Owner, anggota+tujuan dari snapshot; signature valid, idempotent berdasarkan recordingId/shareIndex/hash |
| `GET /recordings/:id/my-share` | Hanya holder user+device yang ditugaskan; dapatkan envelope untuk device itu saja |
| `POST /recordings/:id/my-share/ack` | Holder mengirim signature acknowledgment binding envelope hash, recordingId, dan device |
| `POST /access-requests` | Anggota meminta akses ke device sendiri, request public keyset/signature; expiry dari batas server |
| `GET /access-requests` | Inbox owner, holder, atau requester yang relevan; pagination |
| `POST /access-requests/:id/decision` | Holder; body approve beserta release terenkripsi/signature atau deny; commit decision+release secara atomik |
| `GET /access-requests/:id/releases` | Hanya requester user+device; tidak memberikan share milik request lain |
| `POST /access-requests/:id/read-urls` | Requester ready, belum expired/cancelled; daftar segmen/manifest sesuai recording |
| `POST /access-requests/:id/complete` | Requester mengirim hasil pemeriksaan signed; log sebagai client-reported, bukan server menjamin playback |
| `POST /access-requests/:id/cancel` | Requester atau owner; blok pelepasan berikutnya, tidak menjanjikan penghapusan data penerima |
| `GET /recordings/:id/audit` | Owner melihat kejadian terkait; holder/requester hanya subset relevan |

Endpoint `my-share`, ack, decisions, dan releases menerima device-bound signed payload; session JWT saja tidak boleh mengubah identitas perangkat tujuan. Sertakan action, resourceId, deviceId, issuedAt, nonce/idempotencyId, dan request expiry dalam bytes yang ditandatangani. Tolak binding resource/perangkat yang tidak cocok. Jangan membangun signature dari string concatenation ambigu; definisikan encoder biner length-prefixed di docs.

### 10.1 Contoh request

```json
{
  "id":"<recording-uuid>",
  "sourceDeviceId":"<registered-device-uuid>",
  "kind":"live_event",
  "policyCode":"recovery_2of3",
  "sampleRate":16000,
  "channels":1,
  "pcmEncoding":"pcm16le",
  "startedAtDevice":"2026-11-17T14:00:00Z",
  "policySnapshotBase64":"<signed-snapshot-bytes>",
  "policySignatureBase64":"<signature>",
  "idempotencyKey":"<uuid>"
}
```

```json
{
  "decision":"approve",
  "holderDeviceId":"<device-uuid>",
  "shareIndex":2,
  "releaseCiphertextBase64":"<hpke-envelope>",
  "contextBase64":"<request-bound-context>",
  "signedDecisionBase64":"<bytes>",
  "decisionSignatureBase64":"<signature>",
  "idempotencyKey":"<uuid>"
}
```

### 10.2 Transaksi dan konkurensi

- `approve_request` memvalidasi requester/member/device, state, expiry server, shareIndex milik actor, dan signature; lock row request, lalu insert decision+release+audit dalam satu transaksi.
- Gunakan fungsi PostgreSQL khusus hanya dapat dieksekusi service role; validasi signature di Edge lalu ulangi pemeriksaan membership/state/expiry di transaksi DB. Jangan mengandalkan beberapa insert HTTP yang bisa terputus di tengah.
- Hitung distinct shareIndex approved dengan release valid; set `ready` hanya jika threshold terpenuhi dan kebijakan `owner_required_2of2` mencakup owner. Jangan menyamakan jumlah akun dengan jumlah bagian valid.
- Satu penolakan menutup request hanya jika jumlah bagian maksimum yang tersisa tidak dapat memenuhi policy; keputusan lain dapat tetap pending bila ambang masih mungkin dipenuhi.
- Cek expiry pada setiap read/write; cron hanya untuk merapikan state, bukan satu-satunya penegakan expiry.
- Duplicate payload identik = respons sama; duplicate ID dengan payload/hash berbeda = 409. Retry upload tidak mengubah nonce atau ciphertext.
- Auth: 401; resource tidak terlihat: 404 yang tidak membocorkan keberadaan; invalid payload: 400/422; conflict: 409; expired request: 410; rate limit: 429; internal failure: 500 tanpa stacktrace ke client.
- Rate limit undangan, permintaan akses, login sesuai mekanisme Auth, dan penerbitan URL. Batas awal dicatat sebagai konfigurasi, bukan angka permanen tanpa pengujian.

## 11. Interface kode inti

Kontrak berikut dapat disesuaikan idiom Kotlin tanpa mengubah batas keamanannya:

```kotlin
interface SegmentCrypto {
    fun encrypt(key: ByteArray, header: SegmentHeader, pcm: ByteArray): EncryptedSegment
    fun decryptVerified(key: ByteArray, segmentBytes: ByteArray): VerifiedPcm
}

interface SecretSharing {
    fun split(secret: ByteArray, threshold: Int, count: Int): List<EncodedShare>
    fun recover(shares: List<EncodedShare>, threshold: Int): ByteArray
}

interface ShareEnvelopeCrypto {
    fun seal(publicKeyset: ByteArray, context: ByteArray, share: ByteArray): ByteArray
    fun open(keysetAlias: String, context: ByteArray, ciphertext: ByteArray): ByteArray
}

interface RecordingRepository {
    fun observeRecordings(): Flow<List<RecordingSummary>>
    suspend fun persistSegment(segment: EncryptedSegment)
    suspend fun finalizeRecording(recordingId: UUID, manifest: SignedManifest)
    suspend fun enqueueSync(recordingId: UUID)
}
```

`RecordingService` memiliki pipeline audio, foreground notification, coroutine scope dan cleanup resource. ViewModel mengirim action serta mengamati state; tidak menyimpan DEK/share plaintext dalam `SavedStateHandle` atau state Compose yang dapat dipersistenkan. Player menunggu segmen lolos verifikasi sebelum menyerahkan PCM ke AudioTrack; jangan menyimpan WAV terbuka untuk mempermudah playback.

## 12. Pengujian dan acceptance criteria

### 12.1 M1 wajib

- Tap singkat tidak merekam; tekan melewati ambang memulai tepat satu sesi; lepas jari tidak menghentikan sesi.
- Izin ditolak/dicabut, recorder gagal init, dan storage penuh menghasilkan pesan serta state yang sesuai.
- Audio simulasi dapat dienkripsi/dekripsi byte-identik; tag GCM, header, ciphertext yang diubah ditolak.
- Setiap segmen pada satu DEK memiliki nonce berbeda; retry memakai bytes sama; sesi setelah restart menggunakan DEK baru.
- Untuk 2-of-3, pasangan (1,2), (1,3), (2,3) memulihkan DEK asli; duplicate index, kurang bagian, atau panjang share salah ditolak.
- Tidak ada audio terbuka/key/share plaintext pada Room, file sementara, logcat, atau backup yang diaktifkan.
- Stop normal menyimpan tail buffer, frame count dan urutan benar. Pemutaran durasi sesuai jumlah sample frame.
- Pembatalan/force-stop tidak menyebabkan daftar rekaman hilang; segmen lengkap dapat ditemukan lagi dan sesi ditandai parsial.
- Local demo benar-benar dapat berjalan tanpa server, akun, atau akses internet.

### 12.2 M2 wajib

- Akun A tidak dapat membaca/list/mengunggah/mengubah rekaman B dengan mengganti ID/path.
- Akses langsung REST/Storage dengan publishable key atau JWT user tidak melewati API gate.
- Object Storage yang belum tercatat tidak dianggap tersinkron; metadata palsu tidak lolos commit.
- Upload identik diulang tidak menambah row/objek; isi berbeda pada index sama menghasilkan conflict.
- Jaringan terputus sebelum upload, sesudah upload sebelum commit, dan setelah commit sebelum acknowledgment client tidak menghilangkan data atau menggandakan segmen.
- Token expired menghentikan sync dengan state perlu autentikasi, sementara perekaman lokal tetap tersedia.

### 12.3 M3–M4 wajib

- Token pairing expired/terpakai ditolak; hubungan aktif memerlukan dua konfirmasi.
- Key fingerprint berubah memblokir distribusi sampai pemasangan ulang.
- Envelope hanya terbuka pada holder device yang dituju; context atau binding yang salah ditolak.
- Share release tidak dapat dipindahkan ke request/recipient/recording lain.
- Approval dari non-holder, device berbeda, shareIndex ganda, request expired/cancelled ditolak.
- `owner_required_2of2` tidak ready tanpa bagian owner; `recovery_2of3` semua pasangan sah berhasil.
- Transaksi approve yang gagal tidak meninggalkan decision approve tanpa release.
- Manifest/signature palsu, satu segmen diganti, dihilangkan, disisipkan, atau diurutkan ulang ditolak terhadap final manifest.
- Server/database dump hanya berisi ciphertext/public metadata dan tidak cukup untuk memulihkan audio dalam model ancaman yang ditetapkan.
- Penghapusan DEK envelope lokal hanya setelah syarat sync+ack terpenuhi; pembukaan sesudahnya memakai threshold sesungguhnya.
- Reboot/uninstall tidak diklaim menjaga data yang belum keluar perangkat; skenario hilang perangkat hanya lulus bila ciphertext dan bagian pemulihan yang dibutuhkan sudah tersedia di luar perangkat.

### 12.4 Verifikasi perangkat dan laporan

Uji pada emulator dan setidaknya satu Android fisik bila tersedia, mencakup versi Android dengan pembatasan layanan mikrofon modern. Catat versi OS, model, kondisi layar, koneksi, serta hasil. Jika perangkat fisik tidak tersedia, tandai pengujian tersebut belum dilakukan.

Ukur waktu dari ambang gestur terpenuhi sampai AudioRecord aktif/segmen pertama aman, keberhasilan aktivasi, salah aktivasi pada simulasi, gap audio, overhead enkripsi, ukuran penyimpanan, dan pemakaian baterai. Jangan menyatakan target 1,5 detik atau segmen 2 detik sebagai hasil eksperimen.

Contoh perintah yang perlu disesuaikan dengan module/build variant nyata:

```bash
cd android
./gradlew :core-crypto:test :app:testLocalDemoDebugUnitTest :app:assembleLocalDemoDebug
./gradlew :app:lintLocalDemoDebug
./gradlew :app:connectedLocalDemoDebugAndroidTest
```

```bash
supabase db reset
supabase test db
deno test supabase/functions/api
```

Jangan menambahkan test dangkal yang hanya memeriksa getter atau teks layout. Prioritaskan kesalahan kriptografi, state recorder, crash recovery, idempotensi, dan otorisasi.

## 13. Model ancaman dan batas jaminan

Dilindungi dalam rancangan: pembaca database/storage tanpa kunci privat, pengintip koneksi dengan HTTPS, satu pemegang di bawah ambang, perubahan file sesudah pengamanan, gangguan jaringan, serta kehilangan satu sumber sesuai policy dan salinan yang tersedia.

Belum ditangani penuh: perangkat sumber yang sudah dikuasai malware/root, pihak yang mengetahui layar/PIN, pemegang ambang berkolusi, penerima merekam ulang audio, pengguna memasukkan audio palsu, server menghapus semua salinan, paksaan fisik, serta eksploitasi dependency. Enkripsi tidak menyembunyikan seluruh metadata: server masih dapat melihat akun, hubungan, waktu unggah, ukuran, dan jumlah segmen.

Private bucket bukan backup independen. M2 menyimpan satu salinan remote ditambah salinan lokal; klaim tahan kegagalan seluruh penyedia memerlukan replika ciphertext pada fault domain terpisah dan uji restore di milestone baru.

Audit backend hanya mencatat aktivitas yang melewati aplikasi dan dapat diubah operator privileged. Jangan menyebutnya audit yang mustahil dimanipulasi. Jangan menjanjikan pencabutan akses kriptografis terhadap plaintext atau bagian kunci yang sudah diperoleh penerima.

## 14. Deliverables yang harus dihasilkan Codex

1. Kode Android yang dapat dibangun, mode lokal dan connected yang terpisah.
2. Modul kriptografi beserta test penting dan dokumentasi codec/version.
3. Migration database lengkap, constraint/index, deny-by-default RLS/grants, bucket setup, dan SQL transaksi approve.
4. Edge API berautentikasi, validasi input, otorisasi per-resource, idempotensi, serta pengujian negatif.
5. Contoh konfigurasi tanpa secrets, README setup dari nol, dan langkah simulasi beberapa perangkat.
6. `docs/architecture.md`, `docs/crypto-format.md`, `docs/api.md`, `docs/testing.md`, `docs/decisions.md`.
7. Daftar fitur selesai/belum selesai per milestone dan hasil perintah verifikasi yang benar-benar dijalankan.
8. APK debug bila toolchain tersedia; bila tidak, kode dan instruksi build disertai hambatan yang spesifik.

Jangan deploy ke hosted project atau mengubah database produksi hanya karena kredensial tersedia. Implementasi lokal, migration, test, dan dokumentasi merupakan keluaran pertama. Tidak perlu meminta keputusan ulang untuk pilihan reversible yang sudah ditetapkan di PRD ini. Catat penyimpangan yang diperlukan beserta alasannya; jangan menyembunyikan scope yang dikurangi.

## 15. Urutan kerja yang disarankan untuk Codex

1. Baca repo/instruksi lokal, tulis rencana singkat berdasarkan M0–M1 dan periksa toolchain.
2. Spike crypto dan buat codec segmen beserta test kegagalan.
3. Buat recorder service, gesture, state, dan penyimpanan atomik.
4. Buat vault/detail serta playback terverifikasi.
5. Tambahkan demo Shamir dengan label yang jelas, jalankan build/test, dokumentasikan hasil M1.
6. Implementasikan migration dan API M2 beserta pengujian otorisasi sebelum menghubungkan UI cloud.
7. Implementasikan outbox/sync dan uji retry dengan jaringan putus.
8. Tambahkan pairing dan HPKE envelope M3; uji round-trip perangkat berbeda.
9. Tambahkan request/approval/threshold recovery, lalu manifest/checkpoint dan penguatan M4.
10. Laporkan hasil terhadap acceptance criteria dan risiko yang masih terbuka.

## 16. Rujukan teknis primer

Diperiksa untuk penyusunan brief pada 17 November 2026. API dan versi dependency harus diverifikasi kembali saat implementasi. Dokumen ini berisi keputusan rancangan; rujukan di bawah mendukung kemampuan platform/primitive, bukan bukti bahwa SwaraLara sudah aman atau efektif.

- Android AudioRecord: https://developer.android.com/reference/android/media/AudioRecord
- Foreground service types: https://developer.android.com/develop/background-work/services/fgs/service-types
- Background start restrictions: https://developer.android.com/develop/background-work/services/fgs/restrictions-bg-start
- Android cryptography: https://developer.android.com/privacy-and-security/cryptography
- Android Keystore: https://developer.android.com/privacy-and-security/keystore
- Android WorkManager: https://developer.android.com/develop/background-work/background-tasks/persistent
- Android Java/Gradle compatibility: https://developer.android.com/build/jdks
- NIST SP 800-38D, GCM: https://csrc.nist.gov/pubs/sp/800/38/d/final
- Bouncy Castle ShamirSecretSplitter: https://downloads.bouncycastle.org/java/docs/bcprov-jdk18on-javadoc/org/bouncycastle/crypto/threshold/ShamirSecretSplitter.html
- Google Tink Hybrid Encryption: https://developers.google.com/tink/hybrid
- Google Tink supported key types: https://developers.google.com/tink/supported-key-types
- Supabase Kotlin setup: https://supabase.com/docs/guides/getting-started/quickstarts/kotlin
- Supabase Kotlin dependencies: https://supabase.com/docs/reference/kotlin/installing
- Supabase Storage access control: https://supabase.com/docs/guides/storage/security/access-control
- Supabase private buckets: https://supabase.com/docs/guides/storage/buckets/fundamentals
- Supabase Edge authentication: https://supabase.com/docs/guides/functions/auth
