# Format kriptografi v1

Semua integer big endian; PCM plaintext dalam memori signed 16-bit little endian mono.
Header `.swseg` 82 byte dipakai utuh sebagai AES-256-GCM AAD. Tag 16 byte berada di akhir ciphertext.

| Offset | Byte | Field |
|---|---:|---|
| 0 | 4 | ASCII SWL1 |
| 4 | 16 | UUID raw, most-significant lalu least-significant long |
| 20 | 4 | index UInt32 |
| 24 | 4 | sampleRate UInt32, didukung 16000/44100/48000 |
| 28 | 1 | channels = 1 |
| 29 | 1 | pcmEncoding = 1 |
| 30 | 4 | sampleCount (frame per kanal) |
| 34 | 12 | nonce: prefix acak 8 + index UInt32 |
| 46 | 32 | SHA256 seluruh objek sebelumnya, nol pada index 0 |
| 78 | 4 | ciphertextLength = sampleCount × 2 + 16 |
| 82 | variabel | ciphertext + tag |

Parser menolak extra/truncated bytes, counter overflow, konfigurasi tidak didukung, sampleCount tidak positif
atau >192000, index nonce tidak cocok, dan previousHash bukan nol pada index pertama.
Verifikasi stream memeriksa ID, indeks kontigu, konfigurasi, prefix nonce konsisten, hash objek, chain, tag dan jumlah frame.
GCM memakai `doFinal` sebelum PCM diberikan ke player. Tidak ada plaintext file.

Vektor header: UUID `00112233-4455-6677-8899-aabbccddeeff`, index 0, sampleRate 16000,
sampleCount 2, prefix `0001020304050607`, previousHash nol:

```text
53574c3100112233445566778899aabbccddeeff0000000000003e80010100000002
000102030405060700000000
0000000000000000000000000000000000000000000000000000000000000000
00000014
```

Tes menggabungkan baris menjadi tepat 82 byte. Vektor ini tidak mengandung kunci atau audio nyata.
DEK baru CSPRNG 32 byte per session; prefix CSPRNG 8 byte; index hanya naik. Percobaan enkripsi mengonsumsi
index; kegagalan menutup sesi. Retry tidak memanggil encrypt, hanya membaca bytes final.

Shamir dipin `shamir-bc-gf256-v1`, Bouncy Castle 1.83 `Algorithm.AES`, `Mode.Table`, GF(256) modulus AES
`x^8+x^4+x^3+x+1` (0x11b). Threshold 2, count 3, secret 32 byte, koordinat 1/2/3.
Adapter memakai `resplit` untuk DEK yang sudah dibuat, bukan secret baru independen.
Mode/basis ini tidak diasumsikan kompatibel dengan pustaka lain. BC buffers internal dibersihkan sebatas API memungkinkan.

Codec **khusus demo** `SWD1`: magic 4 + UUID 16 + threshold 1 (=2) + count 1 (=3) + x 1 + y 32 = 55 byte.
Tolak ID salah, x duplikat, kurang bagian, x di luar 1..3, magic/ukuran/threshold/count salah.
Bytes hanya berada dalam test/memori; tidak disimpan atau dikirim. Codec ini belum mempunyai holderDeviceId atau
policySnapshotHash; **dilarang** dipakai sebagai codec bagian integrated. HPKE/signature/binding lengkap dikerjakan M3.

Envelope DEK lokal: IV GCM 12 + ciphertext 32 + tag 16 = 60 byte. KEK AES-256 AndroidKeystore alias
`swaralara.local-kek.v1`; AAD UTF-8 `swaralara/local-dek/v1/<uuid>`. Tidak memerlukan biometrik per segmen.
M1 mempertahankan envelope; belum ada distribusi atau penghapusan sesudah ack pemegang.
