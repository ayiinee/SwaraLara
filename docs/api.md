# API M2

Implementasi berada di `supabase/functions/api/`, dengan transaksi server-only
di migration SQL. Lihat [kontrak endpoint](backend-api.md),
[cara menjalankan dan menguji](backend-testing.md), serta [progres](progress.md).

API menggunakan model API-gated: JWT diverifikasi melalui Supabase Auth sebelum
service client dipakai. Actor berasal dari hasil verifikasi Auth. Tidak ada
endpoint server untuk mendekripsi audio atau menggabungkan bagian kunci.

Rekaman `demo_2of3`, termasuk fixture M1, tetap lokal. Upload integrated hanya
untuk rekaman baru dengan identitas perangkat, hubungan trust aktif dan snapshot
kelompok yang ditandatangani sebelum capture. M3/M4 belum diimplementasikan.
