# Keputusan implementasi

Tanggal acuan: 17 November 2026.

1. Repositori awal kosong, branch `main` belum memiliki commit. Tidak ada AGENTS.md di root/ancestor proyek yang ditemukan.
2. Permintaan pengguna menjadi instruksi kerja. Dua lampiran menjadi spesifikasi produk/pembagian kepemilikan;
   blok prompt Orang 1/Orang 2 di lampiran tidak dianggap sebagai pesan pengguna baru. Peran mengikuti brief: Orang 2.
3. Struktur mengikuti revisi brief: `core-crypto`, `recording-core`, `core-demo`, dan scaffold `app` di `android/`.
   Tidak merombak pekerjaan rekan; belum ada implementasi backend yang dapat diintegrasikan.
4. Branch task inti memakai `feat/recording-crypto` sesuai brief. Tidak membuat branch rekan yang belum dikerjakan.
5. Pin AGP 8.9.2, Gradle 8.11.1, Kotlin/Compose compiler 2.1.20, KSP 2.1.20-2.0.1,
   Compose BOM 2025.04.01, Room 2.7.2, Bouncy Castle 1.83. `minSdk=26`, compile/target SDK 35.
   Kombinasi platform dipilih dari dokumentasi kompatibilitas resmi, bukan klaim versi terbaru.
   Dependency lock final hanya boleh dilaporkan tersedia setelah resolusi build berhasil.
6. M1 memakai aplikasi demo terpisah, bukan flavor palsu terhubung. Tidak ada permission INTERNET dalam manifest demo.
   `demo_2of3` tidak menjadi `owner_required_2of2`/`recovery_2of3`; receipt cloud untuk demo ditolak.
7. PCM mono 16-bit, 16 kHz diutamakan; fallback 48 kHz/44,1 kHz bila minimum buffer 16 kHz tidak didukung.
   Init/start masih dapat gagal; kegagalan menjadi state, bukan keberhasilan. Nilai sample rate aktual ikut setiap header.
8. File final immutable, ulang unggah membaca ciphertext yang sama. Error persist menghentikan sesi;
   enkripsi tidak mengulang pasangan key/nonce. Penulisan file dan transaksi Room tidak dianggap atomik bersama.
9. Signing/manifest/HPKE, kronologi, distribusi multi-perangkat dan state outbox ditunda ke milestone yang sesuai.
   Tidak ada mock yang menyatakan fitur itu berhasil. API demo share SWD1 eksplisit tidak kompatibel envelope integrated.
10. Tahap backend menunggu gate lokal yang diminta pengguna. Handoff pertama berupa facade/snapshot/kontrak,
    bukan perubahan sepihak schema/API milik Orang 1. Tidak ada hosted project yang diubah.
11. Spike menemukan BC 1.83 `resplit` mengalokasikan array sepanjang secret (32), mengisi hanya n elemen.
    Adapter mengambil tiga koordinat pertama secara eksplisit, menolak elemen null; tidak mengubah algoritma GF(256).
    Temuan dibuktikan oleh tes semua pasangan dan [source versi yang dipin](https://github.com/bcgit/bc-java/blob/r1rv83/core/src/main/java/org/bouncycastle/crypto/threshold/ShamirSecretSplitter.java).
12. Build APK mengecualikan hanya `META-INF/versions/9/OSGI-INF/MANIFEST.MF` yang berbenturan
    antara BC 1.83 dan jspecify. Metadata OSGi tidak digunakan Android; kelas kriptografi tetap ikut paket.
13. Mesin 8 GB mengalami kegagalan alokasi memori native saat Gradle memakai heap 3 GB dan beberapa compiler.
    Default kini heap 1536 MB, maksimal dua worker, build paralel nonaktif, compiler Kotlin in-process.
    Verifikasi pada mesin ini memakai satu worker. Pengaturan ini dapat dinaikkan pada mesin yang lebih besar.
14. AOSP API 35 x86_64 diunduh dari Google dan diperiksa SHA-1 paket resmi
    `2d857d170c0d1b827149565da34b3383e5306f7f`. Image dan AVD uji berada pada `.tools/`, diabaikan Git.
    Emulator menggunakan audio sintetis bawaan (host microphone tidak diaktifkan); tes ini tidak mengukur kualitas mikrofon fisik.

## Keputusan M2 — 18 November 2026

15. Pengguna secara eksplisit meminta implementasi backend/API yang belum tersedia
    dan integrasi Android, sehingga task meliputi app, supabase serta perubahan facade/
    Room yang diperlukan. Ini memperluas pekerjaan Orang 2 awal; instruksi lampiran
    tetap spesifikasi, bukan pesan pengguna baru. Branch `feat/app-backend` dibuat
    dari hasil M1. Pengguna juga meminta commit/push checkpoint lebih dulu, lalu lanjut.
16. API-gated PostgreSQL/RLS + satu RPC transaksi service-only. Seluruh JWT user
    diverifikasi melalui Supabase Auth getUser sebelum akses service. Tidak ada
    server decrypt/combine. Audit hanya public IDs/hash/index/waktu server.
17. Pin supabase-js 2.119.0, Deno 2.9.6 untuk dev check, PGlite 0.5.16 untuk tes,
    Tink Android 1.17.0 dan WorkManager 2.10.1. Registry/API diverifikasi dari paket
    versi terpilih. Upload URL Storage berlaku dua jam sesuai kemampuan SDK;
    read URL 60 detik. Public origin lokal dikonfigurasi lewat SWL_PUBLIC_SUPABASE_URL
    agar tidak memakai nama env SUPABASE_* yang dicadangkan runtime.
18. Android memakai REST Auth/API melalui HttpURLConnection, bukan supabase-kt
    dalam rancangan awal. Ini membatasi dependency transport, dengan validasi URL,
    TLS untuk release, no redirect, refresh token, batas response dan session
    Keystore-wrapped. SDK server tetap supabase-js. Perubahan transport tidak
    mengubah model otorisasi atau format kriptografi.
19. Policy SWP1 ditandatangani pada perangkat saat capture dibuat; registrasi
    metadata final dicache untuk retry identik. M1 tidak dikonversi menjadi cloud.
    Room v2 menambahkan registration/outbox secara aditif. Receipt tidak menghapus
    DEK dan tidak menyatakan pemegang sudah menerima bagian; recovery tetap DEGRADED.
20. Docker engine/CLI Supabase belum tersedia pada mesin kerja. Tes memakai migration
    nyata pada PostgreSQL embedded dan fixture protokol provider HTTP, termasuk
    adapter SDK produksi. Fixture diberi label test-only, bind loopback dan semua
    credential/key dihasilkan runtime. Ini bukan deployment Supabase; gate provider
    nyata tetap dicatat. Tidak ada private key/share/credential runtime dikomit.
21. M3/M4 di luar task M2: schema fondasi ada, tetapi API workflow yang belum tersedia
    tidak mengembalikan sukses palsu. UI menyatakan distribusi/pemulihan belum aktif.

Rujukan primer yang diperiksa:

- [AGP 8.9: Gradle 8.11.1, JDK minimal 17, API maksimal 35](https://developer.android.com/build/releases/agp-8-9-0-release-notes).
- [Compose compiler plugin mengikuti versi Kotlin](https://developer.android.com/develop/ui/compose/setup-compose-dependencies-and-compiler).
- [Room dan KSP](https://developer.android.com/jetpack/androidx/releases/room).
- [Foreground service microphone dan runtime permission](https://developer.android.com/develop/background-work/services/fgs/service-types#microphone).
- [BC 1.83 ShamirSplitSecret source](https://github.com/bcgit/bc-java/blob/r1rv83/core/src/main/java/org/bouncycastle/crypto/threshold/ShamirSplitSecret.java).
- [Gradle checksum](https://gradle.org/release-checksums/).
- [Supabase createSignedUploadUrl: URL berlaku dua jam](https://supabase.com/docs/reference/javascript/storage-from-createsigneduploadurl).
- [Supabase getUser memvalidasi token melalui Auth server](https://supabase.com/docs/reference/javascript/auth-getuser).
- [Environment bawaan dan nama secret yang dicadangkan Edge Functions](https://supabase.com/docs/guides/functions/secrets).
