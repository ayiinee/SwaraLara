# Pengujian core

Gunakan hanya rekaman simulasi. Hasil aktual dan hambatan dicatat di [progress.md](progress.md).
File test yang tersedia tidak otomatis berarti test tersebut telah dijalankan.

## Perintah standar (JDK 17 lengkap, SDK 35)

```powershell
cd android
.\gradlew.bat :core-crypto:test :recording-core:testDebugUnitTest :core-demo:assembleDebug :app:assembleDebug --write-locks
.\gradlew.bat :recording-core:lintDebug :core-demo:lintDebug
.\gradlew.bat :recording-core:connectedDebugAndroidTest :core-demo:connectedDebugAndroidTest
```

`--write-locks` dipakai saat resolusi pertama untuk merekam dependency transitif, kemudian jalankan lagi tanpa flag.
Commit lock yang benar-benar dihasilkan; jangan menulis lock perkiraan. Wrapper dan dependency langsung sudah dipin.

Laporan Gradle: `core-crypto/build/reports/tests/test/`, `recording-core/build/reports/androidTests/connected/`,
`core-demo/build/reports/androidTests/connected/`, dan `*/build/reports/lint-results-debug.html`.
APK debug: `core-demo/build/outputs/apk/debug/core-demo-debug.apk`.

## Cakupan otomatis

| Test | Perilaku yang diuji |
|---|---|
| `CryptoTest.headerVectorAndRoundTrip` | Header 82 byte persis, AES-256-GCM round-trip byte-identik |
| `tamperEveryByteTruncateAppendAndWrongKeyRejected` | Setiap byte header/ciphertext/tag diubah; seluruh truncation, appended byte dan key salah ditolak |
| `uniqueNonceChainAndBinding` | Nonce berbeda, chain, ID/index/previousHash salah, batas UInt32 |
| `allShamirPairsAndCodec` | 8 pengulangan seluruh pasangan 1–2/1–3/2–3; codec; duplicate/kurang/ID/panjang salah |
| `partialReadsTailAndIncompleteFrame` | Partial read ganjil, segment boundary, tail byte-identik, frame tidak lengkap ditolak |
| `closedSessionCannotReuseKeyNonce` | Sesi tertutup tidak dapat mengenkripsi ulang |
| `LocalVaultTest` (6 test, Android) | Keystore binding, snapshot, demo recovery+GCM, korupsi salinan, cloud demo ditolak, orphan final, tmp, missing tail, hash asli dipertahankan, final immutable, ID/DEK/prefix sesi baru setelah interupsi |
| `LocalFlowTest` (Android) | Short tap, long hold satu sesi, release tetap merekam, stop, recovery, korupsi, AudioTrack sampai completed |

`LocalFlowTest` membutuhkan Activity terlihat dan permission mikrofon. Jalankan di emulator yang mendukung mikrofon
dan perangkat fisik. Headless CI harus memberi window/focus yang benar. Jangan mengganti AudioRecord dengan mock
untuk mengklaim acceptance capture perangkat.

## Skenario perangkat wajib yang belum diwakili penuh oleh tes otomatis

Catat model/OS/build, emulator/fisik, kondisi layar, izin, dan jaringan untuk setiap run:

- Cabut/tolak izin mikrofon; status tidak menjadi Merekam. Ulangi setelah memberi izin.
- Tekan singkat/rapid taps, tekan lama berulang, gerakkan jari keluar, rotasi saat STARTING/RECORDING.
- Layar mati, pindah aplikasi, aksi stop notifikasi, microphone contention/panggilan masuk, audio silenced.
- Rekam >4 detik dan durasi bukan kelipatan dua detik; cocokkan frame/tail dan durasi playback.
- Force-stop ketika merekam: buka kembali; final tetap terlihat, capture interrupted, sesi baru ID/DEK baru.
- Putus setelah rename sebelum Room: tes LocalVault melakukan simulasi titik crash ini.
- Disk penuh, gagal fsync/rename/Room, process death saat stopping, reboot dan Keystore hilang.
- Buka kembali tanpa koneksi/login. Pastikan merged manifest demo tidak meminta internet dan backup/transfer dikecualikan.
- Periksa sandbox/logcat memakai data uji untuk memastikan tidak ada PCM, DEK/share atau token terbuka.

Latency, salah aktivasi, gap audio, overhead enkripsi, ukuran storage dan baterai harus diukur pada perangkat.
Target 1500 ms/2 detik adalah parameter konfigurasi, bukan hasil eksperimen.

## Spike alternatif saat toolchain penuh belum tersedia

Pada lingkungan awal JDK hilang. Runtime Java 21 lokal disalin ke `.tools/` (diabaikan Git),
konfigurasi yang hilang dipulihkan di salinan tersebut dari OpenJDK 21.0.4.
Kotlin compiler cache 2.2.10 dengan language/API 2.1, stub Java dari Android platform 35,
Bouncy Castle **1.83** (SHA-256 `82cf3a2af766c3bc874f6d36b9f20a8b99a8f09762dc776e8a227a45d8daaafb`),
JUnit 4.13.2 digunakan untuk compile/run keenam `CryptoTest` langsung.

Hasil spike tidak menggantikan `gradlew :core-crypto:test` pada dependency terpin, build APK,
atau instrumented test Keystore/AudioRecord/Room. Tidak ada file hasil unduhan/runtime yang dikomit.
Pemeriksaan compile Kotlin main Android terhadap AAR cache juga hanya pemeriksaan API/sintaks;
ia tidak menjalankan KSP, manifest merge, Android lint, resource packaging, atau perangkat.

Verifikasi lanjutan 18 November memakai JDK 17.0.17 lengkap, compiler **2.1.20**, stdlib **2.1.20**,
BC **1.83** dan JUnit **4.13.2**, menjalankan keenam test yang sama lewat JUnitCore: **OK (6 tests)**.
SHA-1 JAR compiler sesuai Maven resmi: `4ef56b3316798316bfac7a0ae443391c9e900ea1`.
Compiler fallback 2.2.10 tidak menjadi versi dependency proyek.

## Hasil Android 18 November

AVD `SwaraLara_API35`, AOSP Android 15 API 35 x86_64,
fingerprint `Android/sdk_phone64_x86_64/emu64x:15/AE3A.240806.019/12368160:userdebug/test-keys`.
Emulator 36.5.11, WHPX, GLES SwiftShader, Vulkan dimatikan, 2 GB RAM, satu core, 720×1280.
Tidak menggunakan mikrofon host; AudioRecord membaca audio sintetis bawaan emulator.
Layar virtual aktif dan terbuka. Demo tidak meminta internet; server/akun tidak disiapkan.

APK dibangun melalui Gradle terpin, lalu dipasang dan dijalankan langsung agar daemon build dan emulator tidak berebut RAM:

```powershell
adb -s emulator-5556 install -r android/recording-core/build/outputs/apk/androidTest/debug/recording-core-debug-androidTest.apk
adb -s emulator-5556 install -r android/core-demo/build/outputs/apk/debug/core-demo-debug.apk
adb -s emulator-5556 install -r android/core-demo/build/outputs/apk/androidTest/debug/core-demo-debug-androidTest.apk
adb -s emulator-5556 shell am instrument -w -r -e class id.swaralara.core.LocalVaultTest id.swaralara.core.test/androidx.test.runner.AndroidJUnitRunner
adb -s emulator-5556 shell am instrument -w -r -e class id.swaralara.coredemo.LocalFlowTest id.swaralara.coredemo.test/androidx.test.runner.AndroidJUnitRunner
```

`LocalVaultTest`: **OK (6 tests)**, 6,618 detik. `LocalFlowTest`: **OK (1 test)**, 12,744 detik.
Lama seluruh suite bukan pengukuran latency aktivasi atau benchmark audio.
Log runner dan hasil JUnit JVM tersedia di [test-results/2026-11-18](test-results/2026-11-18/).
Perintah `connectedDebugAndroidTest` belum dijalankan; yang dieksekusi adalah runner APK tes yang sama via adb.

Pemeriksaan manual tambahan pada emulator yang sama:

- Force-stop setelah >4 detik capture, buka kembali: brankas tetap berisi rekaman **INTERRUPTED**, satu segmen final/2 detik tetap ditemukan.
- Force-stop segera setelah aktivasi: rekaman 0 segmen tetap terlihat interrupted; buffer yang belum diamankan tidak diklaim tersedia.
- Cabut izin mikrofon via `pm revoke`, buka kembali dan tahan tombol: **Izinkan mikrofon**, status Siap,
  service tidak aktif. Izin dikembalikan setelah skenario uji.
- Manifest APK diperiksa dengan `aapt dump permissions`: tidak ada INTERNET, izin foreground microphone tersedia.
  Merged manifest mengonfirmasi `allowBackup=false`, aturan ekstraksi data dan service non-exported.

Perangkat fisik, rotasi, storage penuh, panggilan masuk, layar terkunci, gap/overrun serta baterai masih belum diuji.
Emulator dihentikan setelah pengujian; tidak ada service perekaman yang dibiarkan berjalan.
