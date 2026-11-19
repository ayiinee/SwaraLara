# M3 — integrasi distribusi dan pemulihan kunci

M3 menghubungkan core kriptografi, klien Android, worker dan Edge API produksi.
Supabase hosted sengaja tidak dijalankan pada task ini atas permintaan pengguna;
konfigurasi project nyata akan disiapkan pengguna. Tidak memerlukan Docker atau emulator.

## Alur aplikasi

1. Masuk dengan akun berbeda pada perangkat masing-masing, lalu **Daftarkan**.
2. Undang pendamping, hubungkan token, cocokkan kedua fingerprint melalui saluran
   terpisah, lalu konfirmasi. Backend menyimpan proof SWD2 asli; Android memvalidasi
   proof, hash dan fingerprint sebelum mem-pin identitas.
3. Pilih pemilik + satu pendamping (`owner_required_2of2`), atau pilih dua pendamping
   berbeda untuk `recovery_2of3`. Kebijakan menjadi snapshot tetap untuk rekaman baru.
4. Rekam dan hentikan. UploadWorker mengirim ciphertext immutable, lalu mengantrekan
   EnvelopeWorker. Core membagi DEK, mengenkripsi setiap share dengan HPKE, dan
   mempertahankan envelope yang sama untuk retry.
5. Perangkat pemegang memverifikasi policy/owner, membuka share miliknya di core,
   menyimpan ciphertext, lalu mengirim acknowledgment bertanda tangan. Pemilik
   mengambil **bytes acknowledgment asli** dan memverifikasinya di core.
6. Setelah semua receipt dan acknowledgment valid, pemilik dapat memilih
   **Aktifkan akses bersama saja**. Dialog memperoleh persetujuan eksplisit sebelum
   core menghapus pembungkus DEK dan KEK lokal. Satu upload tidak menghapus kunci.
7. Pada **Akses**, anggota meminta pembukaan. Setiap pemegang harus menekan Setujui
   sendiri; peminta tidak otomatis menyetujui bagian miliknya. Worker tidak pernah
   memanggil approve/release. Dua bagian berbeda diperlukan; kebijakan 2-of-2 juga
   mensyaratkan pemilik, sedangkan dua pendamping cukup untuk 2-of-3.
8. Setelah status ready, peminta memperoleh release dan URL ciphertext melalui
   otorisasi perangkat bertanda tangan. Ciphertext diunduh bertahap, diperiksa
   hash/ID/indeks/chain/format, dan diimpor tanpa DEK. Core memulihkan DEK hanya
   dalam lease memori lalu mengautentikasi GCM sebelum player menerima PCM.
9. Tutup player/background/expiry membersihkan lease. Pembatalan menghancurkan
   kunci request lokal, disimpan untuk retry transport, dan diteruskan kepada anggota.

Request pending dipulihkan dari Room setelah restart; percobaan ulang tidak membuat
request/keyset baru. Approval yang response-nya hilang aman diulang tanpa menambah
jumlah pemegang. Request expired/denied/cancelled tidak menghasilkan izin baca baru.
Receipt upload, acknowledgment holder, status ready, dan keberhasilan GCM berbeda.

Roster pendamping lain hanya dapat dipin setelah policy ditandatangani oleh pemilik
yang **sudah dipin**. Proof dan fingerprint setiap anggota tetap diverifikasi terhadap
snapshot tersebut. Tidak ada trust-on-first-use otomatis dari response server.

## Konfigurasi Supabase yang disiapkan pengguna

- Isi URL dan public/publishable key pada `android/local.properties`, mengikuti
  `android/local.properties.example` dan `.env.example`.
- Terapkan migration 001 sampai **202611190005_m3_transport.sql** berurutan dan
  deploy function `api`. Migration 004 menegakkan binding/replay/lifecycle; migration
  005 menambahkan proof perangkat, bytes ack/cancel, receipt dan query transport.
- Service-role secret tetap hanya di environment server. Jangan masukkan ke APK.
- Perangkat lama harus **Daftarkan** ulang setelah migration 005 agar server
  memperoleh proof aslinya. Kunci/fingerprint lama tetap dipakai; tidak dibuat ulang.
- Untuk Supabase lokal yang sudah tersedia, gunakan `adb reverse` dan origin
  `http://127.0.0.1:<port>` pada debug build. Tidak perlu menyiapkan Docker untuk
  menjalankan pengujian fixture di bawah.

## Pengujian yang dapat diulang

```powershell
npm test
$env:JAVA_HOME='<JDK 17>'
android/gradlew.bat -p android :core-crypto:test :recording-core:testDebugUnitTest :app:assembleDebug :app:assembleDebugAndroidTest
powershell -File scripts/verify-m3-android.ps1 -Serial <serial-perangkat>
```

Runner terakhir menjalankan API/SQL/adapter produksi pada fixture Auth/Storage lokal,
menggunakan tiga identitas Tink/Android Keystore serta database terpisah pada satu
ponsel fisik. Audio sintetis dipakai; ini bukan pengujian tiga ponsel fisik atau
Supabase hosted. Pengujian memakai **CloudClient dan codec produksi**, mencakup dua
kebijakan, retry receipt/keputusan, retirement DEK, pemulihan owner, download/import
ke peminta lain, GCM, AudioTrack, cancellation dan pembersihan kunci.

Runner hanya membuat ADB reverse miliknya dan membersihkannya setelah tes. Data
aplikasi pengguna tidak dihapus. Credential fixture ephemeral dan log berada di
`.tools/m3-integration`, diabaikan Git. Jangan jalankan emulator.

## Hasil aktual 19 November 2026

| Pemeriksaan | Hasil |
|---|---|
| Suite backend lengkap | 28 PASS, 0 FAIL; API/SQL produksi melalui PGlite dan fixture HTTP |
| Regresi penolakan tambahan | 1 PASS, 0 FAIL; deny idempotent, tidak bisa diubah menjadi approve atau izin download |
| JVM standar core/protokol | 8 core-crypto + 7 M3ProtocolTest PASS |
| Android M3TransportIntegrationTest | OK (1 test), 56,345 detik; tiga identitas terisolasi pada Xiaomi 23021RAA2Y, Android 14 |
| Typecheck / lint Deno | PASS pada function produksi; format file M3 diperiksa |
| Build app + APK instrumentasi | BUILD SUCCESSFUL |
| Android lint | 0 error, 5 warning |

Total backend adalah 29 kasus unik: suite 28 kasus, kemudian satu kasus deny baru
dijalankan terpisah. JVM working tree juga memuat tes audit/reference/benchmark dari
pekerjaan sebelumnya; hasil tambahannya tidak dihitung sebagai 15 tes standar M3.
Log tersimpan di [hasil M3](test-results/2026-11-19/m3/).

Regresi yang ditemukan saat pengujian: PCM 8.000 byte berada di bawah buffer stream
8.192 byte dan tidak selesai diputar. Player kini mengatur start threshold pada
Android API 31+; tes klip pendek 4.000 frame berhasil sampai COMPLETED. Ini bukan
klaim pengukuran latency mikrofon atau kompatibilitas seluruh perangkat Android.

## Batas yang tetap berlaku

- Pengujian Supabase hosted dan beberapa ponsel fisik menunggu environment/perangkat.
- Signed final manifest/checkpoint dan kronologi terenkripsi adalah M4. Status
  VERIFIED PARTIAL membuktikan segmen yang tersedia, bukan kelengkapan akhir tepercaya.
- Cancellation/expiry menghentikan tindakan/izin baru; tidak dapat menarik kembali
  share, plaintext, atau capability Storage singkat yang sudah diterima.
- Identitas anggota snapshot immutable. Mengganti perangkat yang hilang dengan
  identitas baru memerlukan alur enrollment/rotasi kebijakan tersendiri.
