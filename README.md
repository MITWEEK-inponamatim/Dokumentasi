# ThreatLens

Deteksi penipuan untuk nomor, tautan, dan aplikasi Android — dikhususkan untuk nomor Indonesia (`+62`), dengan papan cerita warga dan meja moderasi.

Empat repo, dijalankan jadi satu stack dengan Docker Compose.

---

## 1. Fitur utama

**Tiga deteksi**

| Deteksi | Cara kerja |
|---|---|
| Tautan (`/recognize` → tab Tautan) | Chromium terisolasi membuka halaman, membandingkan host awal vs akhir setelah redirect, membaca form action lintas-domain, lalu menggabungkannya dengan reputasi URL (Safe Browsing, VirusTotal, IC4, Malwarebytes). Hasilnya ada di alamat sendiri: `/recognize/url/<scan_id>`. |
| Aplikasi APK | Hash SHA-256 + pemeriksaan statis (Androguard) di container tanpa akses internet: izin, kemampuan SMS/accessibility/overlay-install, token bot Telegram tertanam, launcher tersembunyi, petunjuk packer, dan pre-check zip-bomb. APK tidak pernah dieksekusi. Hasil di `/recognize/apk/<scan_id>`. |
| Nomor telepon | Normalisasi E.164 (hanya `+62`), deteksi nomor premium, lalu digabung dengan laporan warga. Halaman hasil: `/recognize/phone/<nomor>`, termasuk bagian "Kata warga". |

**Domain mirip brand (lookalike).** 80 brand Indonesia (bank, e-wallet, e-commerce, logistik) + layanan global dicocokkan secara deterministik dan offline: substitusi karakter (`g00gle.com`), typosquatting (`goggle.com`), homograph/punycode, brand disisipkan (`bca-login.xyz`), brand di bawah domain lain (`google.com.secure-login.xyz`). Hasilnya maksimal `suspicious` — kemiripan nama bukan bukti halaman berbahaya.

**Papan cerita warga (`/community`).** Tiga tab beralamat sendiri — `/community/latest`, `/community/popular`, `/community/phone`. Penulis dapat menceritakan pengalaman atas satu nomor `+62` dengan gambar bukti wajib; identitas tampil sebagai alias (`Warga-a1b2c3`), bukan nama asli. Vote hanya mengubah urutan feed, tidak pernah mengubah risiko sebuah nomor.

**Laporan nomor berbahaya.** Satu laporan per akun per nomor, kategori tetap lima, gambar bukti wajib dan diverifikasi dari magic byte. Sebuah nomor baru masuk daftar "Nomor berbahaya" setelah **satu laporan disetujui moderator** — ambangnya adalah keputusan manusia yang membaca laporan dan screenshot-nya, bukan jumlah kepala.

**Meja moderasi (`/admin`).** Pintunya `/admin/login` (email + password). Setelah masuk:
- `/admin/dasbor` — jumlah akun, laporan, cerita, dan nomor berbeda dilaporkan; grafik garis pertumbuhan untuk angka yang dipilih; donut kategori laporan; filter 7 hari / 1 bulan / 3 bulan / 1 tahun.
- `/admin/laporan` — antrean laporan nomor, setujui / tolak / tandai spam.
- `/admin/posting` — antrean cerita warga, turunkan cerita.

**Verdict bisa dibaca.** Level risiko tidak pernah berbohong: kalau ada pemeriksaan yang gagal dijalankan, itu muncul sebagai `checks_unavailable` di halaman hasil, bukan diam-diam dianggap bersih. Klaim berisiko tinggi dari model saja tidak cukup — butuh sumber kedua yang bukan model.

**Keamanan.** CSP + HSTS + `nosniff` + `frame-ancestors 'none'`, browser scan hanya bisa keluar lewat proxy DNS-pinning (port 80/443), worker APK read-only tanpa rute internet, log meredam API key/JWT/DSN, sesi idle 1 jam keluar sendiri, ikon dibundel offline (tidak ada fetch ke API pihak ketiga).

---

## 2. Yang perlu kamu siapkan

Ini **bukan** stack yang bisa jalan sepenuhnya offline. Kodenya jalan di laptopmu, tapi lima layanan luar ikut dibutuhkan:

| Layanan | Untuk apa | Wajib? |
|---|---|---|
| **Supabase** (project hosted) | Database, auth, Storage | Ya — tanpa ini tidak ada yang jalan |
| **OpenAI** | Agen pemeriksa tautan/APK | Ya, untuk deteksi |
| **Cloudflare Turnstile** | Anti-bot di form login | Ya, untuk login |
| **Google OAuth** | Login warga | Ya, kalau mau login |
| **Cloudinary** | Penyimpanan gambar bukti laporan & cerita | Ya, kalau mau melapor/m posting |
| Safe Browsing, VirusTotal, IC4, Malwarebytes, Exa, MobSF, sandbox dinamis | Sumber reputasi tambahan | Tidak — yang tidak diset hanya dilaporkan sebagai "belum diperiksa" |

**Perangkat di laptopmu:** Docker Desktop (status *Running*) dan Git. Untuk menjalankan tes tanpa container, tambahkan Node.js 20+, Go 1.23+, dan Python 3.10+.

---

## 3. Ambil kodenya

Keempat repo harus **sejajar** di dalam satu folder induk — bukan bersarang, bukan submodule. Compose memakai path `../frontend`, `../backend`, `../analysis-service`, jadi posisi folder menentukan.

```bash
mkdir mitweek && cd mitweek

git clone https://github.com/MITWEEK-inponamatim/infra.git
git clone https://github.com/MITWEEK-inponamatim/frontend.git
git clone https://github.com/MITWEEK-inponamatim/backend.git
git clone https://github.com/MITWEEK-inponamatim/analysis-service.git
```

Hasilnya harus begini:

```text
mitweek/
├── infra/              # compose, migrasi Supabase, dokumentasi
├── frontend/           # Next.js 16 + React 19
├── backend/            # Go API
└── analysis-service/   # Python: agen deteksi, LangGraph, worker browser/APK
```

---

## 4. Buat file `.env`

Ada empat file contoh. `docker compose` **gagal lebih dulu** kalau salah satu file `.env` belum ada, jadi buat semuanya sebelum menjalankan.

```bash
cp frontend/.env.example        frontend/.env
cp backend/.env.example         backend/.env
cp analysis-service/.env.example analysis-service/.env
cp infra/supabase/.env.example  infra/supabase/.env
```

Semua `.env` sudah di-ignore Git. Jangan pernah commit nilai aslinya — yang di-commit hanya `.env.example`.

### `frontend/.env`

| Variabel | Nilai |
|---|---|
| `NEXT_PUBLIC_SUPABASE_URL` | URL project Supabase-mu |
| `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY` | publishable key (`sb_publishable_…`) |
| `NEXT_PUBLIC_TURNSTILE_SITE_KEY` | site key Turnstile |
| `NEXT_PUBLIC_API_BASE_URL` | `http://localhost:8080` |
| `NEXT_PUBLIC_IDLE_TIMEOUT_SECONDS` | `3600` |

### `backend/.env`

| Variabel | Nilai |
|---|---|
| `SUPABASE_URL` | sama seperti di frontend |
| `SUPABASE_PUBLISHABLE_KEY` / `SUPABASE_SECRET_KEY` / `SUPABASE_JWT_SECRET` | dari Supabase → Settings → API |
| `TURNSTILE_SECRET_KEY` | secret key Turnstile |
| `TURNSTILE_EXPECTED_HOSTNAME` | `localhost` |
| `SERVICE_API_KEY` | bebas, asal panjang — **wajib identik** dengan di `analysis-service/.env` |
| `PRE_COOKIE_SECRET` | bebas, asal panjang (dipakai untuk alias penulis) |
| `DATABASE_URL` | **boleh kosong.** Kalau terisi, Go baca Postgres langsung lewat pgx; kalau kosong, lewat PostgREST. Keduanya jalan |
| Sisanya | punya default di kode, biarkan seperti contoh |

### `analysis-service/.env`

| Variabel | Nilai |
|---|---|
| `SUPABASE_URL` / `SUPABASE_SECRET_KEY` | sama seperti di backend |
| `SERVICE_API_KEY` | **sama persis** dengan backend |
| `OPENAI_API_KEY` + `OPENAI_MODEL` | kunci agen |
| `CLOUDINARY_URL` + `CLOUDINARY_CLOUD_NAME` | lihat catatan Cloudinary di §8 |
| `DATABASE_URL_SESSION` | kolom `connectionString` Supabase → Settings → Database. Kosong pun jalan, hanya checkpoint LangGraph dilaporkan tidak tersedia |
| `SAFE_BROWSING_API_KEY`, `VIRUSTOTAL_API_KEY`, `EXA_API_KEY`, `MOBSF_URL`, `MOBSF_API_KEY`, `DYNAMIC_ANALYSIS_URL` | opsional; kalau kosong, hasilnya muncul sebagai "pemeriksaan tidak tersedia" |

### `infra/supabase/.env`

`SUPABASE_AUTH_EXTERNAL_GOOGLE_CLIENT_ID` dan `…_SECRET` dari Google Cloud Console (lihat §7).

---

## 5. Generate kunci worker browser & APK

Dua file ini tidak ada di repo dan tidak boleh kamu tulis manual. `browser-*` dan `analysis-worker` menerima kunci **turunan** dari `SERVICE_API_KEY` (HMAC-SHA256), supaya keduanya tidak pernah memegang kunci induk. `analysis-worker` menolak start kalau `FILE_WORKER_SERVICE_KEY` kosong.

Buka **PowerShell** (skripnya bukan Bash), dari folder `mitweek`:

```powershell
Set-Location infra

$workspace = (Resolve-Path "..").Path
$lines = [System.IO.File]::ReadAllLines((Join-Path $workspace "analysis-service/.env"))
$key = $lines | Where-Object { $_ -match '^SERVICE_API_KEY=' }
if (@($key).Count -ne 1) { throw "Expected one SERVICE_API_KEY in analysis-service/.env" }
$raw = $key[0].Substring('SERVICE_API_KEY='.Length)
function New-DerivedKey([string]$domain) {
  $hmac = [System.Security.Cryptography.HMACSHA256]::new([Text.Encoding]::UTF8.GetBytes($raw))
  try { return -join ($hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($domain)) | ForEach-Object { $_.ToString('x2') }) } finally { $hmac.Dispose() }
}
$browser = @("BROWSER_SERVICE_KEY=$(New-DerivedKey 'threatlens-browser-service')", 'BROWSER_MAX_RESPONSE_MB=20')
$worker = @("FILE_WORKER_SERVICE_KEY=$(New-DerivedKey 'threatlens-file-service')", 'WORKER_MAX_CONCURRENCY=2', 'WORKER_MAX_BODY_MB=52', 'WORKER_APK_TIMEOUT_SECONDS=150')
[System.IO.File]::WriteAllText((Join-Path $workspace "analysis-service/.env.browser"), ($browser -join [Environment]::NewLine) + [Environment]::NewLine, [System.Text.UTF8Encoding]::new($false))
[System.IO.File]::WriteAllText((Join-Path $workspace "analysis-service/.env.worker"), ($worker -join [Environment]::NewLine) + [Environment]::NewLine, [System.Text.UTF8Encoding]::new($false))
Remove-Variable raw
```

Hasilnya dua file baru: `analysis-service/.env.browser` dan `analysis-service/.env.worker`. **Ulangi langkah ini setiap kali kamu mengganti `SERVICE_API_KEY`** — kalau tidak, scan URL dan APK langsung gagal dengan error 401 internal.

---

## 6. Jalankan migrasi database (langkah yang paling sering terlewat)

Database-nya project Supabase-mu. Skema dan fungsi agregat berada di `infra/supabase/migrations/` dan **harus dijalankan satu per satu sesuai urutan nama file** — nomornya adalah urutannya.

| File | Kalau tidak dijalankan |
|---|---|
| `202610300001_initial_schema.sql` | tidak ada apa pun |
| `202610300002_langgraph_schema.sql` | checkpoint agen tidak tersedia |
| `202610300004_phone_reports_trust.sql` | laporan ganda lolos, hanya ditahan pengecekan aplikasi |
| `202610300005_phone_reports_note.sql` | catatan laporan tidak tersimpan (`note_saved: false`) |
| `202611040006_phone_reports_evidence.sql` | **setiap laporan nomor ditolak `503`**, gambar terhapus lagi |
| `202611040007_community_posts.sql` | papan warga 503, cerita baru ditolak |
| `202611060008_scan_evidence_items.sql` | item bukti scan tidak tersimpan |
| `202611070001_admin_roles.sql` | tidak ada akun admin → `/admin` selalu ditolak |
| `202611090009_dangerous_numbers_single_approval.sql` | daftar "Nomor berbahaya" masih pakai ambang lama |
| `202611100010_admin_desk_stats.sql` | **`/admin/dasbor` menampilkan "Angka dasbor belum bisa diambil"** |

### Cara A — Supabase SQL Editor (paling mudah)

Supabase Dashboard → **SQL Editor** → buka file migrasi → paste isinya → **Run**, mulai dari `0001` sampai `0010`. Setelah selesai, jalankan ini satu kali supaya PostgREST melihat fungsi baru:

```sql
select pg_notify('pgrst', 'reload schema');
```

Kalau langkah ini dilewat, `admin_desk_stats()` sudah ada di database tapi PostgREST masih menjawab `404`, dan dasbor tetap error.

### Cara B — Supabase CLI

```bash
cd infra
supabase login
supabase link --project-ref PROJEK_REF_MU
supabase db push
```

Cek cepat bahwa yang penting benar-benar ada, jalankan di SQL Editor:

```sql
select to_regprocedure('public.admin_desk_stats(text)') as fungsi_sudah_ada;
select count(*) as jumlah_cerita from public.community_posts;
```

---

## 7. Konfigurasi auth Supabase

**URL aplikasi.** Supabase → Authentication → URL Configuration:
- Site URL: `http://localhost:3000`
- Redirect URLs: `http://localhost:3000/auth/callback`

**Google OAuth.** Google Cloud Console → buat **OAuth client ID tipe Web**, tambahkan `https://<project-ref>.supabase.co/auth/v1/callback` ke *Authorized redirect URIs*. Masukkan client ID + secret ke `infra/supabase/.env` (§4), lalu terapkan ke Supabase dari folder `infra`:

```powershell
Set-Location infra
.\supabase\apply-auth-config.ps1 -Preview   # lihat dulu apa yang akan diubah
.\supabase\apply-auth-config.ps1            # terapkan
```

**Akun admin (meja moderasi).** Login `/admin/login` memakai **email + password**, bukan Google. Jadi buat akun khusus untuk moderator, lalu angkat role-nya:

1. Supabase → Authentication → Users → **Add user** → email + password, *Auto Confirm User* dicentang.
2. Buka SQL Editor dan jalankan (ganti email dengan akun tadi):

```sql
update public.profiles
   set role = 'admin'
 where id = (select id from auth.users where email = 'moderator@contoh.id');

select id, role from public.profiles where role = 'admin';
```

Baris terakhir harus mengembalikan akunmu. Kalau kosong, `/admin` akan langsung melempar kamu keluar lagi.

---

## 8. Nyalakan stack-nya

Dari folder `mitweek`:

```bash
docker compose -f infra/docker-compose.yml up --build -d
```

Build pertama mengambil image Chromium dan menaruh dependensi Python/Go/Node di dalam container, jadi **bisa 10–20 menit**. Pantau dengan:

```bash
docker compose -f infra/docker-compose.yml ps
```

Tujuh service harus naik; lima di antaranya ditandai `(healthy)`:

| Service | Peran |
|---|---|
| `frontend` | Next.js di `http://localhost:3000` |
| `go-api` | API publik di `http://localhost:8080` — satu-satunya yang bisa disentuh browser selain frontend |
| `analysis-service` | Orkestrasi agen + risk engine (hanya di network internal, tidak dipublikasikan) |
| `browser-gateway` / `browser-worker` / `browser-egress` | Chromium terisolasi + proxy keluar |
| `analysis-worker` | Analisis APK statis, tanpa internet |

**Cloudinary — jebakan yang nyata.** SDK Cloudinary hanya membaca `CLOUDINARY_URL` **kalau `CLOUDINARY_CLOUD_NAME` tidak diset**. Proyek ini menyetel keduanya, dan nama cloud di URL harus sama dengan `CLOUDINARY_CLOUD_NAME` (host `dlwbthmsn0` salah; yang benar `wbthmsn0` — jangan ikut prefiks `d`). Kalau upload bukti gagal, laporan **ditolak** `503 evidence_unavailable` dan baris database tidak dibuat — itu memang disengaja, bukan bug.

---

## 9. Bukti bahwa stack-mu benar-benar jalan

Jalankan berurutan. Semua langkah ini harus hijau sebelum kamu bilang "sudah jalan".

1. **Halaman terbuka** — `http://localhost:3000` menampilkan landing page, dan **ikon-ikonnya muncul** (kalau kotak kosong, lihat §11).
2. **Login warga** — tombol masuk mengarah ke Google dan kamu kembali ke `/recognize` tanpa error.
3. **Pemeriksaan tautan** — tab Tautan, masukkan satu URL yang jelas aman. Loading selesai di `/recognize`, lalu halaman pindah sendiri ke `/recognize/url/<scan_id>`. Buka tautan itu langsung dengan Ctrl+Shift+R — hasilnya harus tetap ada, tidak menjalankan scan ulang.
4. **Pemeriksaan nomor** — tab Telepon, cari `+62` yang pernah dilaporkan. Halaman `/recognize/phone/<nomor>` harus menampilkan "Kata warga" kalau ada laporannya.
5. **Laporan nomor** — `/community/phone` → kirim laporan dengan gambar. Kalau balik ke form dan tidak muncul error tapi laporannya tidak ada, hampir pasti migrasi `0006` belum jalan.
6. **Papan warga** — `/community/latest`, buat satu cerita dengan gambar, vote, dan komentari. Buka `/community/latest` di tab lain sebagai akun kedua untuk memastikan komentar tampil.
7. **Meja moderasi** — `http://localhost:3000/admin/login`, masuk dengan akun admin. `/admin/dasbor` harus menampilkan angka (bukan kartu error), grafik garis berubah saat kamu klik kartu metrik, dan filter rentang mengubah label sumbu. Lalu `/admin/laporan` → setujui laporan dari langkah 5, dan cek nomor itu muncul di tab "Nomor berbahaya".
8. **Kesehatan internal** — dari laptop:

```bash
curl -s -H "X-Service-Key: <SERVICE_API_KEY kamu>" http://localhost:8080/internal/v1/metrics
```

Harus mengembalikan JSON berisi counter (`scans_created`, `jobs_completed`, dst) dan store aktif (`pgx` atau `postgrest`).

---

## 10. Menjalankan tanpa Docker (untuk develop)

Container tetap dipakai untuk `analysis-service`. Untuk mengubah kode frontend/backend sambil melihat hasilnya:

```bash
# terminal 1 — Go API di host, membaca backend/.env
cd backend && go run .

# terminal 2 — Next.js dev di host, membaca frontend/.env
cd frontend && npm install && npm run dev
```

`NEXT_PUBLIC_API_BASE_URL` sudah menunjuk ke `http://localhost:8080`, jadi frontend dev bisa memakai `go-api` yang jalan di host maupun di container. Jangan lupa `docker compose -f infra/docker-compose.yml stop go-api frontend` supaya port tidak rebutan.

Perintah pemeriksaan sebelum commit:

```bash
(cd backend && go test ./...)
(cd analysis-service && python -m pytest)
(cd frontend && npm install && npm run icons && npm run lint && npx tsc --noEmit && npm run build)
docker compose -f infra/docker-compose.yml config --quiet
```

---

## 11. Kalau ada yang tidak jalan

| Gejala | Penyebab & perbaikan |
|---|---|
| `/admin/dasbor` menampilkan "Angka dasbor belum bisa diambil" | Migrasi `202611100010` belum jalan, **atau** sudah jalan tapi PostgREST belum reload schema. Jalankan `select pg_notify('pgrst', 'reload schema');`. Kalau masih gagal, cek log: `docker compose -f infra/docker-compose.yml logs go-api \| grep "desk stats"` — baris itu menyebut penyebab aslinya. |
| Semua laporan nomor → `503` | Migrasi `0006` belum diterapkan. |
| Papan warga → `503 service_unavailable` | Migrasi `0007` belum diterapkan. |
| `/admin/login` melempar kamu keluar lagi | Akun belum di-`role = 'admin'` (lihat §7), atau kolom role belum ada karena `202611070001` belum jalan. |
| Login warga gagal di callback | Site URL / Redirect URL Supabase belum `http://localhost:3000` dan `…/auth/callback`. |
| Scan URL selalu "bukti belum cukup" | `BROWSER_EGRESS_PROXY_URL` dan `--host-resolver-rules` harus menunjuk **satu nilai yang sama** (`http://browser-egress:8888`). Kalau beda subnet, tiap halaman mati dengan `ERR_PROXY_CONNECTION_FAILED` dan verdict-nya tetap terlihat normal. Jangan tulis IP subnetnya di kode. |
| `analysis-worker` tidak mau start | `analysis-service/.env.worker` belum dibuat — ulangi §5. Log-nya menyebut cara memperbaikinya. |
| Upload bukti / screenshot gagal senyap | Nama cloud di `CLOUDINARY_URL` tidak sama dengan `CLOUDINARY_CLOUD_NAME` (lihat §8). |
| Semua ikon tampil kosong | Tambahkan ikon baru tanpa menjalankan `npm run icons`. Ikon dibundel offline, bukan diambil dari API Iconify. |
| `docker compose up` langsung gagal | Salah satu `.env` belum dibuat (§4). Compose menolak kalau `env_file` tidak ada. |
| Port 3000/8080 sudah dipakai | Hentikan proses lain, atau `docker compose -f infra/docker-compose.yml down` lalu naikkan lagi. |

---

## 12. Struktur & dokumentasi lanjutan

```text
frontend/          src/app (rute) · src/components (UI per area) · src/lib (typenya API) · src/hooks
backend/           main.go (rute) · admin.go (meja moderasi) · community.go · store.go (Postgres/PostgREST)
analysis-service/  app/scanners.py · app/graph (LangGraph url/phone/application) · app/risk.py · app/brand_guard.py
infra/             docker-compose.yml · supabase/migrations · docs/API_Contracts.md
```

- `infra/docs/API_Contracts.md` — setiap batas HTTP: rute publik, rute internal dengan service key, dan bentuk body-nya.
- `infra/README.md` — keputusan desain per subsistem, termasuk ambang risiko dan alasan tiap batasan.
- `PANDUAN_SETUP_TIM.md` — versi pendek dokumen ini, khusus langkah setup.
