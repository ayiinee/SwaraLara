# Progres SwaraLara — 18 November 2026

Branch task saat ini: `feat/m3-hpke-recovery`, berangkat dari hasil M2 `81fd2a3` di `feat/app-backend`.
Checkpoint `9bc6609` sudah dipush ke GitHub atas permintaan pengguna; tidak ada deployment hosted.

## Status milestone

| Milestone | Implementasi | Gate penerimaan |
|---|---|---|
| M0 | Empat modul Android/JVM, version catalog, wrapper terverifikasi, scaffold host utama | APK debug demo dan app berhasil dihasilkan; 6 test Gradle crypto lulus |
| M1 | Crypto, recorder/service, panel gestur/izin, Room/Keystore, file atomik/recovery, brankas demo, Shamir lokal, verifikasi dan AudioTrack | **Alur utama lulus pada emulator Android 15**; 6 test vault + 1 test UI, force-stop dan cabut izin diperiksa. Perangkat fisik dan skenario lanjutan belum diuji |
| M2 | Migration/RLS, API Auth/device/trust/recording/upload/commit/audit, private bucket, signed policy, Room v2/outbox dan WorkManager terintegrasi | **Alur lokal Android→HTTP API→PostgreSQL lulus**, 12 tes backend + 10 Android. Supabase Auth/Storage/Edge Runtime asli belum diuji karena Docker/CLI belum tersedia; gate provider masih terbuka |
| M3 — core Orang 2 | Codec SWB1, HPKE envelope+signature, pin/offline cache, ack, request-specific HPKE/release, threshold recovery dan lifecycle v2 tersedia melalui facade | 15 tes JVM + 6 vektor signature Node/Deno lulus. Suite Android disiapkan/di-build, belum dijalankan karena commit memory emulator kurang; pengguna memilih lanjut tanpa emulator. UI/API/transport M3 Orang 1 dan beberapa perangkat tetap terbuka |
| M4 | Belum diimplementasikan | Signed final manifest/checkpoint, kronologi terenkripsi dan penguatan perangkat masih terbuka |

## Fitur yang telah ditulis

- AES-256-GCM per segmen, header SWL1 82 byte persis PRD, nonce prefix+UInt32, SHA-256 chain,
  parsing berbatas ukuran, ID/indeks/format/tag diverifikasi sebelum PCM keluar ke player.
- Segmenter partial read dan tail; satu sesi tidak dapat menggunakan ulang counter setelah ditutup.
- Shamir BC 1.83 GF(256) AES basis; semua pasangan 2 dari 3 diuji. Koordinat+ID terikat pada codec demo,
  duplicate index/kurang bagian/panjang salah ditolak. Perilaku array null BC 1.83 ditangani adapter.
- AudioRecord mono 16 kHz (fallback format terdokumentasi), foreground service microphone,
  status aktif setelah recorder benar-benar recording, stop terpisah serta aksi notifikasi.
- RecorderPanel menangani izin dan tahan 1500 ms; pelepasan tidak memanggil stop; start busy ditolak.
- File ciphertext internal immutable, fsync+rename sebelum transaksi indeks; rekonsiliasi orphan final
  tanpa mengesahkan perubahan hash, penghapusan tmp, sesi aktif lama menjadi interrupted.
- DEK lokal dibungkus AES-GCM Android Keystore, AAD ID rekaman. Backup/transfer data dikecualikan.
- Brankas dan diagnostik non-sensitif; demo recovery membandingkan kunci dan mengautentikasi audio,
  korupsi diuji pada salinan memori, playback PCM langsung ke AudioTrack dengan pause/release.
- Satu implementasi core untuk demo dan scaffold app utama, sandbox terpisah; aplikasi demo tanpa internet/account.

**Ditulis tidak berarti seluruh perilaku Android telah diuji.** Tidak ada klaim final manifest bertanda tangan,
distribusi lintas perangkat, pemulihan saat kehilangan perangkat, atau kesiapan pengaduan nyata.

## Pengujian M0–M1 yang benar-benar dijalankan

| Pemeriksaan | Hasil |
|---|---|
| Git repo/toolchain/`adb devices -l` | Repo awal kosong; tidak ada perangkat Android terhubung |
| Wrapper JAR SHA-256 | Cocok `2db75c40782f5e8ba1fc278a5574bab070adccb2d21ca5a6e5ed840888448046` |
| Distribusi Gradle 8.11.1 SHA-256 | Cocok `f397b287023acdba1e9f6fc5ea72d22dd63669d59ed4a289a29b1a76eee151c6` |
| `android/gradlew.bat --version` dengan JDK 17.0.17 | Berhasil: Gradle 8.11.1 / BellSoft JDK 17.0.17 |
| Compile + JUnitCore `CryptoTest`, Kotlin 2.1.20 / BC 1.83 / JDK 17 | **Lulus 6 test**; meliputi semua byte tamper, truncation, wrong key, nonce/chain, 24 pemulihan pasangan dan segmenter |
| `gradlew :core-crypto:test --write-locks` dengan TLS 1.2 | **BUILD SUCCESSFUL**, 6 test, 0 failure/error/skipped; dependency lock crypto dihasilkan |
| Compile Kotlin sumber utama Android terhadap AAR cache | Berhasil, termasuk Compose compiler; pemeriksaan API/sintaks alternatif |
| Compile Kotlin sumber instrumented test terhadap AAR cache | Berhasil sesudah dependency rules 1.6.1 tersedia; bukan eksekusi Android |
| Parse empat XML dan script PowerShell verifikasi | Berhasil; 0 error parser script |
| `git diff --check` | Lulus pada perubahan yang diperiksa |
| `:core-demo:assembleDebug` / `:app:assembleDebug` | APK debug berhasil dihasilkan; pengecualian metadata OSGi memperbaiki benturan packaging |
| KSP Room | Schema v1 dan implementasi DAO/database dihasilkan tool build |
| `:core-demo:assembleDebugAndroidTest` / `:recording-core:assembleDebugAndroidTest` | Berhasil; seluruh build packaging **BUILD SUCCESSFUL**, 148 task (33 dieksekusi, 115 up-to-date) |
| `:recording-core:lintDebug` / `:core-demo:lintDebug` | **BUILD SUCCESSFUL**, 0 error; 1 peringatan application-context singleton pada core, 2 peringatan ikon/target SDK pada demo |
| `:recording-core:testDebugUnitTest` | NO-SOURCE; pengujian Room/Keystore berada pada instrumented tests, tidak dihitung sebagai test JVM lulus |
| `LocalVaultTest` via AndroidJUnitRunner pada emulator API 35 | **OK (6 tests)**, Keystore/Room/GCM/recovery/file immutable dan sesi baru |
| `LocalFlowTest` via AndroidJUnitRunner pada emulator API 35 | **OK (1 test)**, hold satu sesi → AudioRecord → stop → Shamir/GCM → AudioTrack completed |
| Force-stop dan cabut izin mikrofon | Lulus pada emulator: final 1 segmen/2 detik tetap terlihat interrupted; tanpa izin hold tidak mengaktifkan service |
| Manifest APK demo | Tidak ada permission INTERNET; foreground microphone, backup/transfer nonaktif dan service non-exported diperiksa |
| Fixture ciphertext Kotlin → Node | 2 objek: header UUID/index/format/nonce/ukuran/hash/chain/frame sesuai, policy demo tetap tidak uploadable |
| Perangkat fisik, storage penuh, rotasi, layar terkunci, panggilan/interupsi, baterai/gap audio | **Belum dijalankan** |

Spike awal memakai Kotlin compiler cache 2.2.10 dengan language/API 2.1. Verifikasi berikutnya memakai
**compiler dan stdlib 2.1.20 yang dipin**, BC 1.83, JUnit 4.13.2 serta JDK 17 lengkap; keenam test lulus.
JAR compiler dicocokkan dengan checksum Maven resmi. Hasil langsung ini belum menggantikan build APK/lint Gradle.

## Catatan hambatan M0–M1 (historis)

1. JDK awal yang dirujuk environment sudah hilang. JDK 17 lengkap dan Gradle 8.11.1 kini tersedia di `.tools/`
   yang diabaikan Git; tidak mengubah instalasi Java sistem. Script `scripts/verify.ps1` dapat menemukannya.
2. Unduhan dependency beberapa kali timeout/terputus. Distribusi Gradle hanya dipakai setelah checksum cocok;
   tidak ada hasil unduhan tidak lengkap yang dinyatakan lolos build.
   Percobaan Gradle menemukan handshake terputus pada `kotlin-scripting-jvm:2.1.20`;
   setelah artefak ber-checksum tersedia dan transport dibatasi TLS 1.2, tes Gradle crypto berhasil.
   Gunakan `scripts/verify.ps1 -Tls12` bila lingkungan mengalami masalah negosiasi yang sama.
3. Awalnya tidak ada AVD siap pakai atau perangkat fisik terhubung. Binary emulator 36.5.11 dan WHPX tersedia.
   Image AOSP API 35 kini selesai diunduh, checksum resmi cocok, dan diekstrak di `.tools/`.
   AVD berhasil boot dengan Vulkan nonaktif, 2 GB RAM dan satu core, memakai mikrofon sintetis bawaan emulator.
   Total **13 test** lulus (6 JVM + 6 vault Android + 1 UI Android). Ini tidak memvalidasi mikrofon/baterai perangkat fisik.
   Startup membutuhkan partisi data minimum 6 GB. Arsip/chunk unduhan task yang sudah diekstrak dihapus dengan
   path eksplisit untuk menyediakan ruang; source, SDK sistem, image hasil ekstraksi dan APK dipertahankan.
   Pengguna mengonfirmasi pada 18 November bahwa perangkat uji belum tersedia.
4. Dependency lock transitif dan Room schema hanya dikomit jika benar-benar dihasilkan tool build, bukan ditebak.
   Lock seluruh modul serta schema Room v1 kini telah dihasilkan. Build Android pertama juga menemukan benturan metadata OSGi
   dan keterbatasan memori native; keduanya ditangani pada konfigurasi packaging/build, lalu APK berhasil dibangun.
5. Build, lint dan alur emulator selesai. APK demo tersedia di `android/core-demo/build/outputs/apk/debug/core-demo-debug.apk`.
   Log hasil tes aktual tersimpan di `docs/test-results/2026-11-18/`. Emulator dihentikan sesudah tes untuk melepas RAM.
   Lengkapi checklist perangkat fisik/rotasi/interupsi di `docs/core-testing.md`; ukur latency, gap/overrun dan baterai.
6. Tindak lanjut integrasi M2: gunakan `docs/core-contract.md` dan fixture `docs/fixtures/synthetic-segments-v1.json`
   bersama implementasi backend Orang 1. Tambah policy/member snapshot sah, outbox+Room migration dan uji
   receipt/retry/isolasi user sebelum M2 dinyatakan selesai. Fixture maupun rekaman `demo_2of3` tetap dilarang cloud.

## Commit task

- `39a0cdb` — M0: scaffold empat modul, build dependencies dan spesifikasi sumber.
- `2616254` — M1: codec/segmenter/AES-GCM/Shamir serta unit tests.
- `0c875c9` — M1: service, storage/Keystore, panel/demo dan player lokal.
- `118feca` — M1: lifecycle player, penyegaran izin mikrofon dan state penghentian awal.
- `061108e` — M1: packaging OSGi, batas memori build, izin notifikasi, dan penghentian service.
- Commit verifikasi/dokumentasi melengkapi skenario instrumented serta laporan ini.

## M2 — checkpoint 18 November 2026

Branch `feat/app-backend` menambahkan migrasi PostgreSQL/RLS, API Supabase dengan
verifikasi Auth, identitas perangkat dan policy bertanda tangan, undangan trust,
serta upload ciphertext dan commit terverifikasi. Android menambahkan identitas
Tink/Keystore, Room v2/outbox, login, trust dan worker sinkronisasi.

Pengujian backend terakhir: **10/10 lulus** (PostgreSQL PGlite dan fixture HTTP
provider; belum merupakan deployment Supabase penuh). Build core-demo berhasil.
Build app terakhir tertahan resolusi dependency WorkManager karena DNS Maven;
APK app M2 dan tes integrasi Android belum dinyatakan lulus. Migrasi Room dan
regresi emulator masih perlu diuji. Docker/Supabase lokal penuh dan perangkat
fisik belum tersedia. M3 distribusi share/approval/recovery belum diimplementasikan;
status recovery cloud tetap degraded dan DEK lokal dipertahankan.

Checkpoint source ini dikomit dan dipush atas permintaan pengguna, lalu pekerjaan
verifikasi dan dokumentasi M2 dilanjutkan. Konfigurasi lokal, credential, cache,
artefak build dan data rekaman tetap diabaikan Git.

## M2 — hasil setelah checkpoint

Implementasi backend dan Android sudah terhubung pada lingkungan uji lokal.
Catatan checkpoint di atas adalah kondisi historis; masalah DNS dependency dan
build app sudah teratasi. M2 belum dinyatakan lulus deployment provider penuh.

Fitur yang selesai pada task ini:

- Dua migration membentuk 14 tabel target PRD + rate limits, constraints, RLS,
  private bucket, RPC service-only, transaksi registrasi/commit dan audit.
- JWT diverifikasi melalui Auth sebelum service role dipakai; actor tidak diambil
  dari body. Kepemilikan dicek di route dan transaksi. Akses antaruser ditolak.
- Public device proof SWD2, trust invitation satu kali/expired, dua konfirmasi
  SWT1 dan snapshot SWP1 bertanda tangan dengan fingerprint anggota immutable.
- Signed upload tanpa upsert, commit membaca SWL1 dan SHA-256 aktual, memeriksa
  index/chain/nonce/format/frame, receipt idempotent dan signed read URL owner.
- Android login/signup/refresh, session Keystore-wrapped, identitas Tink/JCA,
  layar trust/fingerprint, pilihan policy sebelum capture, Room v2/outbox dan
  WorkManager network/backoff. Refresh tidak menimpa session yang sudah dihapus.
- Retry memakai ciphertext dan metadata registrasi yang sama. Expired refresh
  mengubah state menjadi NEEDS_AUTH; rekaman lokal tetap berjalan. Demo/fallback
  tidak dipromosikan ke cloud; recovery tetap DEGRADED, file dan DEK lokal utuh.

| Pengujian aktual | Hasil |
|---|---|
| `node --test --test-concurrency=1 supabase/tests/*.test.ts` | **12/12 lulus**; migrations/RLS/RPC PostgreSQL PGlite, isolation, policy/proof, token, body/rate bounds, retry dan adapter HTTP Storage |
| Deno check / lint / fmt check | Lulus untuk function produksi; formatting function dan tests lulus. Lint mengizinkan explicit any pada batas JSON/RPC tervalidasi; regex penolak kontrol diberi pengecualian lokal |
| Build app/core-demo + kedua app-test APK + recording-core-test APK | **BUILD SUCCESSFUL**, 212 task (26 executed, 186 up-to-date) pada build terakhir |
| Android lint app / recording-core | **0 error**, masing-masing 43 dan 3 warning; saran versi dependency/AGP/target, ikon, UseKtx dan singleton application context |
| `LocalVaultTest` + `CloudVaultTest` | **OK (8 tests)**, 6 regresi M1 + migrasi Room v1→v2 mempertahankan recording/segment/wrapped key + receipt/cloud key lifecycle |
| `CloudIntegrationTest` | **OK (1 test)**, 15,811 detik; AudioRecord Android→API produksi→SDK Supabase→HTTP fixture→PostgreSQL; upload/commit terputus, lost receipt, retry, hash binding, worker success/failure, refresh valid/expired, isolation dan capture lokal setelah auth gagal |
| `LocalFlowTest` | **OK (1 test)**, 17,971 detik; gestur → rekam → Shamir lokal → verifikasi → playback tetap berjalan setelah perubahan M2 |
| `:core-crypto:test` | UP-TO-DATE; hasil 6 tes M1 masih valid, tidak dihitung sebagai eksekusi baru |

Log aktual: [test-results/2026-11-18/m2](test-results/2026-11-18/m2/).
Emulator AOSP API35 memakai mikrofon sintetis, satu core dan RAM 2 GB.
Public key Android benar-benar dihasilkan Tink/Android Keystore; holder ephemeral
didaftarkan dan mengonfirmasi melalui API. Tidak ada private key/share seed.

Hambatan tersisa dan tindak lanjut:

1. Docker engine dan Supabase CLI belum tersedia. PostgreSQL embedded menjalankan
   SQL nyata, sedangkan Auth/Storage provider diganti fixture protokol. Karena itu
   gateway Edge, RLS Storage provider, capability expiry dan refresh/signup pada
   Supabase asli masih harus diuji. Ikuti [backend-testing.md](backend-testing.md)
   saat stack lokal tersedia; belum ada hosted project yang diubah.
2. Perangkat fisik belum diuji. Rotasi, lock screen, panggilan, storage penuh,
   baterai/latency/gap audio tetap mengikuti checklist M1. ADB install/test task
   ini hanya menarget emulator-5556, tidak mengakses mikrofon perangkat fisik.
3. Distribusi HPKE share, ack pemegang, approval/access request, signed manifest,
   checkpoint dan pemulihan lintas perangkat adalah M3/M4. Endpoint belum tersedia
   tidak mengembalikan keberhasilan palsu. Status synced hanya salinan remote.
4. Resource mesin terbatas: Gradle dihentikan sebelum emulator untuk melepas RAM.
   Satu kesalahan lint konfigurasi domain debug diperbaiki dengan batas domain
   eksplisit; build/lint/tes terakhir sudah lulus. Beberapa API serialization Tink
   yang dipin masih memberi peringatan deprecation dan perlu migrasi API selanjutnya.

Panduan dan kontrak kini tersedia di [backend-api.md](backend-api.md),
[backend-testing.md](backend-testing.md), dan [core-contract.md](core-contract.md).

Commit M2 pada branch task yang sama:

- `9bc6609` — checkpoint backend/API + integrasi Android, dipush sebelum melanjutkan sesuai permintaan pengguna.
- `9cf158f` — verifikasi transport Storage, transaksi registrasi, validasi/rate limit, format/lint dan panduan backend.
- `51e02fb` — perbaikan worker/session, migrasi teruji, retry upload dan fallback lokal; dependency locks aktual.
- Commit dokumentasi berikutnya menyimpan laporan dan log hasil pengujian task ini.

Emulator dan server fixture dihentikan setelah tes untuk melepas resource. Data
tes terenkripsi tetap berada di sandbox emulator; credential fixture bersifat
ephemeral dan tidak masuk Git. Branch task dipush tanpa merge/force-push ke main.
