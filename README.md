# SwaraLara

Prototipe Android preservasi rekaman terenkripsi. Bahasa produk: Indonesia.
Mulai dari **core-demo**, tanpa akun, server, kunci Supabase, atau permission internet.
Gunakan ucapan simulasi; prototipe belum divalidasi untuk pengaduan nyata.

M0 sudah build. Alur utama M1 lulus pada emulator Android 15: 6 test JVM, 6 test vault Android,
dan 1 test gestur/recorder/pemulihan/player. Android lint lulus dengan nol error.
Perangkat fisik dan integrasi backend belum diuji; rincian serta log aktual ada di [progres](docs/progress.md).

## Menjalankan

1. Siapkan JDK 17 lengkap, Android SDK platform 35 dan build-tools 35.0.0.
2. Salin `android/local.properties.example` ke `android/local.properties`; sesuaikan `sdk.dir`.
3. Atur `JAVA_HOME` ke JDK dan jalankan dari `android/`:

```powershell
.\gradlew.bat :core-crypto:test :recording-core:testDebugUnitTest :core-demo:assembleDebug :app:assembleDebug
.\gradlew.bat :core-demo:lintDebug :recording-core:lintDebug
.\gradlew.bat :core-demo:installDebug
adb shell am start -n id.swaralara.coredemo/.MainActivity
```

APK: `android/core-demo/build/outputs/apk/debug/core-demo-debug.apk` setelah build berhasil.
Pada macOS/Linux gunakan `./gradlew`. Dependency pertama membutuhkan internet; aplikasi demo tidak.
Windows juga dapat memakai `scripts/verify.ps1 -JavaHome '<path JDK 17>'`; tambah `-DeviceTests` saat perangkat tersedia.
Jika koneksi Java ke Maven gagal pada negosiasi TLS, gunakan opsi `-Tls12` pada script tersebut.

## Alur demo lokal

Izinkan mikrofon → tahan 1,5 detik → tunggu status **Merekam** → ucapkan data simulasi →
**Hentikan** → pilih rekaman di brankas → **Periksa keutuhan** → **Uji pemulihan 2 dari 3** →
**Uji korupsi pada salinan** → **Siapkan pemutaran** → **Putar**.
Lepas sebelum ambang membatalkan; lepas sesudah aktif tetap merekam. Tombol berhenti tersedia juga di notifikasi.

Durasi dihitung dari frame PCM tersimpan, termasuk tail. Data demo terpisah dari aplikasi utama.
Hapus aplikasi/Keystore dapat menghilangkan akses; belum ada pemulihan di luar perangkat.
Verifikasi segmen belum membuktikan kelengkapan akhir terhadap manifest bertanda tangan.

## Struktur dan progres

- `android/core-crypto`: AES-GCM, codec SWL1, chain, segmenter, adapter Bouncy Castle Shamir dan unit tests.
- `android/recording-core`: facade, AudioRecord foreground service, Keystore, Room, recovery file, AudioTrack, panel Compose.
- `android/core-demo`: aplikasi uji lokal `id.swaralara.coredemo`.
- `android/app`: scaffold aplikasi utama untuk Orang 1, `id.swaralara.app`.
- [Progres dan hambatan](docs/progress.md), [pengujian](docs/core-testing.md), [kontrak integrasi](docs/core-contract.md).

Branch inti mengikuti brief: `feat/recording-crypto`. Branch rekan yang disarankan: `feat/app-backend`.
Commit dilakukan per fondasi/inti/pengujian. Tidak ada deploy, push, atau perubahan database hosted otomatis.
M2 baru diaktifkan setelah gate pengujian M1 terpenuhi; rekaman `demo_2of3` tidak dapat diunggah sebagai rekaman integrated.
