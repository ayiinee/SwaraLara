# Checklist integrasi

- [x] Empat modul memiliki versi dependency langsung terpin dan Gradle wrapper dengan checksum.
- [x] RecorderPanel/SecurePlaybackPanel dan facade tersedia, satu implementasi untuk demo/host utama.
- [x] Codec segmen dan format share **demo** didokumentasikan.
- [x] Snapshot menyediakan bytes ciphertext yang sama; receipt demo tidak menghasilkan status synced.
- [x] Resolusi dependency dan lock transitif, schema Room serta APK debug/demo/test dihasilkan pada JDK lengkap.
- [x] Android lint berhasil, 0 error (peringatan nonfatal dicatat di progres).
- [x] Tes Android Room/Keystore/service/gesture/player lulus di emulator API 35; runner APK dijalankan via adb.
- [x] Fixture ciphertext sintetis untuk handoff parser/header/hash tersedia tanpa DEK/share.
- [ ] Alur rekam simulasi sampai playback lulus pada Android fisik.
- [x] App mengintegrasikan komponen inti melalui facade pada task M2 yang diminta pengguna.
- [x] Policy snapshot SWP1 dan public key perangkat diimplementasikan pada kedua sisi.
- [x] API upload/commit mengembalikan receipt recordingId/index/hash/waktu server dan diuji negatif pada PostgreSQL/HTTP fixture.
- [x] Outbox + migration Room + retry idempotent diterapkan dan lulus pengujian emulator API35.
- [x] demo_2of3/fallback ditolak untuk cloud oleh core dan API.
- [ ] Supabase Auth/PostgREST/Storage/Edge Runtime asli diuji dengan Docker/hosted project uji.
- [ ] HPKE/signature/binding dan approval diuji di perangkat/akun berbeda.
- [ ] Penghapusan envelope penuh hanya setelah sync + ack semua pemegang yang diwajibkan.

App hanya memakai facade core; perubahan Room/outbox berada di recording-core.
Instruksi pengguna membuka scope backend M2; kontrak aktual dicatat pada core-contract
dan backend-api. M3/M4 masih memerlukan pengujian distribusi/approval terpisah.
