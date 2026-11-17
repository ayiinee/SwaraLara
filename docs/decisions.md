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

Rujukan primer yang diperiksa:

- [AGP 8.9: Gradle 8.11.1, JDK minimal 17, API maksimal 35](https://developer.android.com/build/releases/agp-8-9-0-release-notes).
- [Compose compiler plugin mengikuti versi Kotlin](https://developer.android.com/develop/ui/compose/setup-compose-dependencies-and-compiler).
- [Room dan KSP](https://developer.android.com/jetpack/androidx/releases/room).
- [Foreground service microphone dan runtime permission](https://developer.android.com/develop/background-work/services/fgs/service-types#microphone).
- [BC 1.83 ShamirSplitSecret source](https://github.com/bcgit/bc-java/blob/r1rv83/core/src/main/java/org/bouncycastle/crypto/threshold/ShamirSplitSecret.java).
- [Gradle checksum](https://gradle.org/release-checksums/).
