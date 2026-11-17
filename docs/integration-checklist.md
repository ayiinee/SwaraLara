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
- [ ] Orang 1 mengintegrasikan komponen ke layar produk melalui facade.
- [ ] Policy snapshot, public key perangkat dan anggota integrated disepakati kedua pihak.
- [ ] API upload/commit mengembalikan receipt recordingId/index/hash/waktu server dan diuji negatif.
- [ ] Outbox + migration Room + retry idempotent diterapkan oleh pemilik core/client bersama.
- [ ] demo_2of3/fallback tidak diunggah dengan snapshot/ack buatan.
- [ ] HPKE/signature/binding dan approval diuji di perangkat/akun berbeda.
- [ ] Penghapusan envelope penuh hanya setelah sync + ack semua pemegang yang diwajibkan.

Integrasi backend bukan alasan mengubah internal cipher/Room dari app. Perubahan schema server milik Orang 1
harus disepakati pada kontrak sebelum diimplementasikan di dua branch.
