# Kontrak backend yang menunggu M2

PRD bagian 9–10 tetap menjadi spesifikasi API target, bukan pernyataan endpoint sudah tersedia.
Implementasi server berada pada kepemilikan Orang 1 di `supabase/`; belum ada backend untuk dihubungkan.

Handoff inti saat ini adalah `EncryptedRecordingSnapshot` dan `UploadReceipt` di [core-contract.md](core-contract.md).
Alur lokal kini lulus pada emulator API 35. Fixture dua objek SWL1 tersedia di
[fixtures/synthetic-segments-v1.json](fixtures/synthetic-segments-v1.json) untuk menguji parser/hash/chain backend
tanpa key/share. Policy demo fixture tidak boleh melewati endpoint pendaftaran rekaman integrated.
Saat M2 dibuka: JWT diverifikasi server, actor dari JWT, seluruh resource diotorisasi, private bucket API-gated,
commit membaca dan memverifikasi file/header/hash, retry objek identik idempotent. Tidak ada server decrypt/combine-shares.
Rekaman M1 `demo_2of3` tidak memenuhi policy snapshot integrated dan ditolak untuk cloud.
