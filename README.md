# SwaraLara

Prototipe Android preservasi rekaman terenkripsi. Bahasa produk: Indonesia.
Mulai dari **core-demo**, tanpa akun, server, kunci Supabase, atau permission internet.
Gunakan ucapan simulasi; prototipe belum divalidasi untuk pengaduan nyata.

M0 sudah build. Alur utama M1 lulus pada emulator Android 15: 6 test JVM, 6 test vault Android,
dan 1 test gestur/recorder/pemulihan/player. Android lint lulus dengan nol error.
M2 menambahkan backend API, policy bertanda tangan dan sinkronisasi Android.
Dua belas tes backend dan sepuluh tes Android lulus; gate Supabase penuh dan perangkat fisik masih terbuka.
Rincian serta log aktual ada di [progres](docs/progress.md).

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
- `android/app`: login, identitas/trust, policy capture dan antrean upload M2, `id.swaralara.app`.
- `supabase`: migrations/RLS, Edge API dan pengujian PostgreSQL/HTTP.
- [Progres dan hambatan](docs/progress.md), [pengujian](docs/core-testing.md), [kontrak integrasi](docs/core-contract.md).

Branch inti mengikuti brief: `feat/recording-crypto`; task M2 memakai `feat/app-backend`.
Commit dan push dilakukan sesuai permintaan pengguna. Database hosted belum diubah.
Rekaman `demo_2of3` tidak dapat diunggah sebagai rekaman integrated.

## Tampilan aplikasi dan konfigurasi

Aplikasi utama memakai layar Beranda, Brankas, Perangkat, Akses, dan Pengaturan
dengan tema plum/lilac sesuai referensi desain. Lihat [panduan frontend](docs/app-frontend.md).
Contoh konfigurasi publik ada di [`.env.example`](.env.example),
[`android/local.properties.example`](android/local.properties.example), dan
[`supabase/.env.example`](supabase/.env.example). Android membaca `local.properties`;
`.env.example` adalah template dan tidak dimuat otomatis.
Gunakan perangkat fisik ADB atau preview web localhost untuk verifikasi UI; jangan jalankan emulator.

## Backend dan integrasi Android M2

Node 24+: `npm ci`, lalu `npm test`. Test suite menjalankan migration PostgreSQL
dan adapter Supabase terhadap fixture HTTP. Untuk menjalankan Supabase lokal asli
dibutuhkan Docker engine dan Supabase CLI; ikuti [panduan backend](docs/backend-testing.md).
Lihat [kontrak API](docs/backend-api.md) untuk auth, trust dan upload/commit.

Isi URL/publishable key pada `android/local.properties`, build `:app:assembleDebug`.
Login dan daftarkan perangkat, pasangkan dua akun/perangkat uji melalui undangan,
cocokkan fingerprint kedua pihak lalu pilih policy sebelum merekam. WorkManager
mengantrekan ciphertext, commit server membuktikan header/hash/chain, dan receipt
memperbarui status lokal. Saat gagal/token expired, data lokal tetap tersedia.
Distribusi share dan pemulihan inti M3 belum terhubung ke UI/backend;
sync M2 tetap mempertahankan DEK lokal. Signed manifest/checkpoint M4 belum diimplementasikan.

## Inti M3 — Orang 2

`core.keyExchange` menyediakan pin public key, envelope HPKE bertanda tangan,
acknowledgment, request/release, pemulihan threshold dan lifecycle kunci.
Kontrak transport dan batas integrasi ada di [m3-core-contract.md](docs/m3-core-contract.md).
Fitur ini belum dihubungkan ke layar/API M3 Orang 1. Rekaman legacy tetap dipertahankan.

Tes lokal tanpa emulator/server:

```powershell
cd android
.\gradlew.bat :core-crypto:test :recording-core:testDebugUnitTest
cd ..
node scripts/verify-m3-signatures.ts
```

Tes memakai Tink/JCA sebenarnya, tanpa simulasi Android Keystore. Fixture signature
publik berlabel JVM; tidak berisi private key atau share plaintext. Tes Android M3
masih menunggu kapasitas emulator/perangkat uji; hasil aktual dicatat di progres.
