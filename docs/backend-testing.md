# Menjalankan dan menguji M2

Node 24+, `npm ci`, lalu `npm test`. Versi dev/runtime dipin di package-lock.
Tes memakai PostgreSQL embedded PGlite untuk menjalankan kedua migration nyata,
privileges/RLS, transaksi, auth negatif, fingerprint, policy, upload/commit dan retry.
Fixture schema `auth`/`storage` hanya menggantikan metadata provider lokal.

Tes HTTP tambahan menjalankan adapter `@supabase/supabase-js` produksi dengan
fixture protokol Auth/RPC/Storage: JWT HMAC runtime, key ephemeral, ciphertext
sintetis dan private object map. Ini membuktikan kontrak transport dan adapter,
**belum menggantikan pengujian Supabase Auth/Storage/Edge Runtime sesungguhnya**.
Fixture hanya bind loopback. Route `/__test__/...` ada di server test saja;
tidak ada route tersebut pada function produksi.

Pemeriksaan TypeScript dan formatting:

```powershell
.\node_modules\.bin\deno.cmd fmt --check supabase/functions/api
.\node_modules\.bin\deno.cmd check --config supabase/functions/api/deno.json supabase/functions/api/index.ts
.\node_modules\.bin\deno.cmd lint --config supabase/functions/api/deno.json supabase/functions/api
```

Lint mengizinkan explicit `any` pada batas JSON/RPC yang divalidasi runtime;
refactor DTO statis belum dilakukan. Regex penolak karakter kontrol memiliki
pengecualian lokal karena pola itu disengaja, bukan error pengetikan escape.

Untuk stack Supabase lokal sesungguhnya, siapkan Docker engine dan Supabase CLI,
lalu dari root (folder konfigurasi sudah tersedia; tidak perlu init):

```powershell
supabase start
supabase db reset
Copy-Item supabase/.env.example supabase/.env.local
supabase functions serve api --env-file supabase/.env.local
```

`db reset` di atas hanya untuk database lokal sekali pakai, bukan hosted project.
CLI/runtime menyediakan `SUPABASE_URL`, `SUPABASE_ANON_KEY` dan
`SUPABASE_SERVICE_ROLE_KEY`. File env tambahan hanya mengatur
`SWL_PUBLIC_SUPABASE_URL` agar signed URL memakai origin yang dapat dijangkau
Android (`http://10.0.2.2:54321` dari emulator). Hosted URL menggunakan HTTPS.
Service secret tidak pernah masuk APK; Android hanya memakai publishable/anon key.
Kebijakan gateway verify_jwt false mengizinkan health publik; router tetap
memverifikasi semua route lain melalui Auth sebelum privileged access.

Isi `android/local.properties` (diabaikan Git):

```properties
sdk.dir=D:/Android/Sdk
SUPABASE_URL=http://10.0.2.2:54321
SUPABASE_PUBLISHABLE_KEY=<publishable atau anon key lokal>
```

Build `:app:assembleDebug`, login dua akun pada dua instalasi/perangkat uji,
daftarkan public identity lewat aplikasi, buat/terima undangan, cocokkan kedua
fingerprints lewat saluran terpisah lalu konfirmasi kedua pihak. Pilih policy
pemilik + pemegang sebelum merekam. Rekaman baru disinkronkan oleh WorkManager;
retry manual tersedia. Data fallback/demo tetap lokal. Konfirmasi email lokal
dapat diperiksa pada Inbox Supabase lokal, tidak memakai akun/password seed.

Untuk tes Android otomatis memakai fixture HTTP:

1. Jalankan `node supabase/tests/contract-server.ts`. Password runtime ditulis
   hanya ke `.tools/m2-contract-fixture.json` yang diabaikan Git.
2. Set URL Android `http://10.0.2.2:8787`, publishable key
   `local-contract-fixture-public`, build APK app/test/core/demo. Gunakan AVD API35
   dan audio sintetis; jangan memakai rekaman nyata.
3. Install APK app dan app-test, lalu jalankan (PowerShell):

```powershell
$fixture = Get-Content .tools/m2-contract-fixture.json -Raw | ConvertFrom-Json
adb -s emulator-5556 shell am instrument -w -r `
  -e class id.swaralara.app.CloudIntegrationTest `
  -e fixturePassword $fixture.password -e fixturePublishableKey $fixture.key `
  id.swaralara.app.test/androidx.test.runner.AndroidJUnitRunner
```

4. `CloudVaultTest` memeriksa migrasi database v1 ke v2 dan lifecycle receipt/key;
   `LocalVaultTest` dan `LocalFlowTest` menjadi regresi lokal. Jangan menyebut
   build sukses sebagai hasil instrumented test; periksa `OK (n tests)` runner.

Tes cloud merekam melalui AudioRecord/core yang sama, memakai public Tink/JCA
key Android asli, menandatangani policy, mengunggah file ciphertext aktual,
memutus commit, mengulang setelah receipt hilang, memeriksa account isolation,
worker dan refresh token expired. Test holder ephemeral didaftarkan/ditandatangani
lewat API; tidak ada private key, share atau acknowledgment holder yang di-seed.

Gate deployment yang masih perlu lingkungan provider nyata:

- Jalankan migration di Supabase lokal dan cek akses REST/Storage langsung
  dengan anon/JWT user, termasuk policy restrictive dan signed upload tanpa upsert.
- Ulangi alur Auth refresh/signup dan upload/commit di Edge Runtime, bukan fixture.
- Uji expiry capability URL, gateway, dan public origin Docker dari Android.
- Uji perangkat fisik, interupsi jaringan/OS dan media/storage penuh.

Hasil aktual dan hambatan mesin dicatat di [progres](progress.md), dengan log
yang tidak memuat credential/signed URL pada `docs/test-results/`.
