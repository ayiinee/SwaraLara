# Arsitektur lokal M0–M1

`core-demo` dan scaffold `app` menggunakan `CoreRuntime` dari `recording-core`.
Satu singleton per proses aplikasi memiliki facade recorder, vault, player, dan coroutine scope.
Activity tidak memiliki AudioRecord atau DEK. Sandbox aplikasi dan Keystore berbeda untuk kedua application ID.

```text
RecorderPanel → RecorderController → RecordingService (microphone foreground)
  → AudioRecord → PcmSegmenter → SegmentSession (core-crypto)
  → ciphertext .tmp + fsync → rename final .swseg → transaksi indeks Room

SecureVault → Keystore unwrap → pemeriksaan hash/chain/format/tag/frame
SecurePlaybackController → autentikasi setiap segmen → AudioTrack (PCM hanya dalam memori)
```

Recorder tidak sticky. Restart proses merekonsiliasi final yang belum diindeks, membuang hanya `.tmp`,
dan menandai sesi aktif sebagai interrupted. ID/DEK/counter sesi lama tidak dilanjutkan.
Kegagalan verifikasi mempertahankan file final dan indeks lama agar perubahan tidak disahkan ulang.

Room v1 hanya memuat tiga entity yang digunakan M1: LocalRecording, LocalSegment, LocalKeyEnvelope.
Metadata bebas/kronologi belum tersedia. Tidak ada kolom plaintext sensitif atau backup aplikasi.
Penambahan outbox/trusted-device/note dilakukan melalui migration ketika fitur terkait benar-benar diimplementasikan.

Crypto audio memakai JCA sistem, bukan penggantian provider Android secara global.
DEK baru 32 byte dibungkus AES-GCM Keystore dengan AAD ID rekaman. Envelope 60 byte disimpan Room.
Shamir demo berlangsung hanya dalam memori; ketiga pasangan memulihkan kunci dan memverifikasi audio.
Penghapusan byte array adalah best effort, bukan jaminan penghapusan seluruh salinan JVM/pustaka.

M1 tidak memiliki manifest/signature/checkpoint tepercaya. Hasil sukses adalah VERIFIED_PARTIAL,
meskipun penghentian normal berstatus SEALED; tail deletion yang juga mengubah indeks lokal belum dapat dibuktikan.
Tidak ada klaim waktu kejadian independen, distribusi bagian, atau server tahan penghapusan.
