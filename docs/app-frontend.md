# Tampilan aplikasi SwaraLara

Implementasi Android Compose mengikuti enam referensi layar yang diberikan pada
19 November 2026: Beranda, Merekam, Rekaman, Akses, Permintaan Akses, dan Perangkat.
Brankas serta Pengaturan memakai tema yang sama. Bingkai iPhone dalam referensi
tidak digambar di dalam aplikasi; status bar dan navigasi sistem mengikuti perangkat.

## Alur

- Beranda: pilih Kejadian atau Penuturan, izinkan mikrofon, lalu tahan 1,5 detik.
  Lepas sebelum ambang membatalkan. Setelah aktif, rekaman berjalan sampai tombol berhenti.
- Merekam: layar penuh, waktu berdasarkan frame audio tersimpan, jumlah segmen aktual,
  dan tombol berhenti yang tidak menunggu operasi jaringan.
- Brankas: daftar rekaman lokal. Buka kartu untuk memeriksa integritas, menyiapkan
  pemutaran, memutar, menjeda, menutup, atau membaca metadata audit.
- Perangkat: daftarkan, undang, salin token, hubungkan, dan cocokkan fingerprint
  sebelum konfirmasi. Kebijakan rekaman bersama hanya dapat dipilih setelah hubungan aktif dan dipin.
- Akses: muat permintaan, buka detail, lalu setujui atau tolak secara eksplisit.
  Keputusan dikirim dengan tanda tangan perangkat sesuai kontrak Edge API.
- Pengaturan: masuk/daftar/keluar dan memilih kembali penyimpanan lokal.

Daftar kosong ditampilkan sebagai keadaan kosong. Tidak ada rekaman, identitas,
status verifikasi, atau persetujuan contoh yang ditampilkan sebagai data nyata.
Konfigurasi backend tetap dibaca dari `android/local.properties`.
Template publik ada di `.env.example`; file tersebut tidak dimuat otomatis.
Salin `android/local.properties.example` ke `android/local.properties`, kemudian
isi URL dan publishable key. Untuk Supabase lokal pada perangkat ADB, jalankan
`adb reverse tcp:54321 tcp:54321` dan gunakan `http://127.0.0.1:54321`.
Konfigurasi Edge API menggunakan `supabase/.env.example`.

## Pemeriksaan

```powershell
cd android
.\gradlew.bat :app:assembleDebug :app:assembleDebugAndroidTest :app:lintDebug :core-crypto:test :recording-core:testDebugUnitTest
.\gradlew.bat :app:connectedDebugAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=id.swaralara.app.FrontendFlowTest
```

`FrontendFlowTest` memeriksa navigasi, pembatalan tekan singkat, rekaman mikrofon
sebenarnya, penyimpanan, pemeriksaan integritas, serta persiapan/pemutaran/penutupan audio.
Tes dijalankan pada perangkat fisik ADB Android 13+ dengan mikrofon.
Jangan menjalankan emulator untuk proyek ini di mesin pengguna.
Pastikan tidak ada sesi lain yang membuat Android membisukan mikrofon aplikasi.

Hasil pemeriksaan 19 November 2026:

- APK debug berhasil dibangun; Android lint: 0 error, 5 warning.
- Delapan tes `core-crypto` dan tujuh tes `recording-core` lulus.
- Pemeriksaan ADB pada Redmi 23021RAA2Y / Android 14: navigasi lima menu,
  pembatalan tekan singkat, rekaman 13 detik, penyimpanan, verifikasi parsial,
  persiapan pemutar, pemutaran, dan penutupan berhasil.
- Alur akun, pasangan perangkat, dan persetujuan lintas akun belum diuji terhadap
  backend hosted; memerlukan konfigurasi dan dua akun/perangkat yang sesuai.

APK debug: `android/app/build/outputs/apk/debug/app-debug.apk`.
