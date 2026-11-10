# ThreatLens

ThreatLens adalah web berbasis komunitas seputar keamanan digital yang memeriksa nomor telepon, tautan, aplikasi Android yang dipakai penipu (khusus untuk nomor Indonesia), Media edukasi terkait penipuan digital, dan komunitas untuk berbagi pengalamannya terkait penipuan digital dan pelaporan nomor berbahaya. Hasil pemeriksaan mesin digabungkan dengan laporan warga, dan keduanya hanya naik menjadi peringatan resmi setelah admin menyetujuinya.

Proyek terdiri dari empat repo yang dijalankan menjadi satu stack dengan Docker Compose. Dokumen ini menjelaskan dua hal: apa saja yang dibangun, dan bagaimana menjalankannya di komputer lokal sampai benar-benar berfungsi.

---

## 1. Fitur utama

ThreatLens menjawab satu pertanyaan: apakah pihak yang baru menghubungi kita itu penipu. Jawaban datang dari tiga jalur yang berbeda, yaitu mesin pemeriksa, laporan warga, dan keputusan moderator. Ketiganya ditampilkan terpisah agar pengguna tahu bagian mana yang merupakan hasil pengukuran dan bagian mana yang masih dugaan.

| Rute | Isi | Butuh login |
|---|---|---|
| `/` | Halaman publik: bagian pembuka dengan kartu periksa, daftar modus penipuan, dan bagian peringatan | Tidak |
| `/recognize` | Tiga tab pemeriksaan: Tautan, Telepon, APK | Ya |
| `/recognize/url/<scan_id>`, `/recognize/apk/<scan_id>` | Halaman hasil untuk satu pemeriksaan. Bisa disimpan, dibuka lagi, dan dibagikan | Ya |
| `/recognize/phone/<nomor>` | Halaman hasil pemeriksaan nomor, termasuk bagian "Kata warga" | Ya |
| `/history` | Daftar pemeriksaan terakhir, setiap baris menaut ke halaman hasilnya | Ya |
| `/learn`, `/learn/<id>` | Modul edukasi berupa simulasi percakapan penipuan | Ya |
| `/guide` | Panduan darurat: langkah 15 menit, nomor call center bank, hotline resmi | Ya |
| `/community/latest`, `/community/popular`, `/community/phone` | Papan cerita warga | Ya |
| `/admin/login`, lalu `/admin/dasbor`, `/admin/laporan`, `/admin/posting` | Meja moderasi | Akun admin |

### 1.1 Tiga jenis pemeriksaan

**Tautan.** Halaman dibuka dengan Chromium di dalam worker terpisah, jadi yang dinilai adalah halaman yang benar-benar tampil, bukan perkiraan dari teks URL. Yang dibandingkan adalah host awal dengan host akhir setelah redirect, action form yang menuju domain lain, halaman yang memakai nama brand di bawah domain asing, dan metadata halaman. Temuan tersebut digabung dengan reputasi eksternal (Google Safe Browsing, VirusTotal, IC4, Malwarebytes) lalu dibaca agen LLM dengan batas tetap: dua ronde panggilan tool dan maksimal enam tool yang benar-benar dieksekusi untuk satu pemeriksaan. Jika redirect berpindah domain, dilakukan satu pemeriksaan tambahan ke tujuan tersebut dan ke action form lintas domain, maksimal dua target, tanpa membuka sesi browser kedua.

**APK.** Berkas diperiksa secara statis dan tidak pernah dijalankan. Pertama dihitung SHA-256-nya, lalu reputasi hash ditanyakan ke VirusTotal, itu pun hanya jika pengguna mencentang izin unggah ke layanan eksternal. Sebelum isi arsip dibongkar, dijalankan pemeriksaan zip-bomb: jumlah entri, ukuran tiap entri, total ukuran setelah diekstrak, dan rasio kompresi. Setelah itu Androguard mengambil izin dan kode, dan aturan deterministik menggabungkannya, antara lain izin SMS yang berdampingan dengan aksesibilitas atau kemampuan instalasi overlay, token bot Telegram yang tertanam di berkas, ikon launcher yang disembunyikan, dan petunjuk penggunaan packer. Nama paket dan domain yang tertulis di dalam APK ikut dibandingkan dengan daftar brand resmi.

**Nomor telepon.** Hanya nomor Indonesia yang dilayani. Normalisasi ke E.164 dilakukan satu kali oleh Python; Go API menyimpan hasil hitung tersebut dan tidak menyalin aturannya sendiri. Angka `0` setelah `62` dibuang di ketiga bahasa, sehingga `0812…`, `62812…`, dan `+62 0812…` menunjuk ke alamat yang sama. Pemeriksaan melihat bentuk nomor premium seperti 0900, yang biasa dipakai pada modus telepon tak dikenal yang menagih, lalu mengambil laporan warga atas nomor tersebut. Bagian "Kata warga" menampilkan kategori, status, dan umur laporan, maksimal 20 entri, tanpa menampilkan identitas pelapor.

Pemeriksaan nomor tidak pernah menyimpulkan sebuah nomor aman. Tidak ada dasar data resmi untuk menyatakan nomor perorangan bersih, jadi yang dilaporkan hanya apa yang sudah dinyatakan orang lain tentang nomor itu.

### 1.2 Cara vonis ditetapkan

Bagian ini yang paling sering membuat produk sejenis kehilangan kepercayaan, yaitu ketika mesin menyatakan aman tanpa bukti.

| Vonis | Kondisi | Tindakan yang disarankan |
|---|---|---|
| **BERBAHAYA** (`confirmed_threat`, level tinggi) | Satu sumber reputasi independen menyatakan berbahaya | Jangan buka tautan dan jangan berikan data apa pun. Blokir dan laporkan |
| **WASPADA** (`suspicious`, level tinggi) | Temuan tinggi yang didukung sumber non-model, atau beberapa temuan sedang | Jangan masukkan kredensial. Verifikasi lewat kanal resmi |
| **WASPADA** (`suspicious`, level sedang) | Ada temuan sedang, belum cukup untuk naik level | Verifikasi sebelum bertindak |
| **AMAN** (`low`) | Minimal dua sumber independen yang hasilnya bersih dan tidak ada temuan sedang ke atas | Tidak ada sinyal bahaya, tetapi tetap berhati-hati |
| **BUKTI BELUM CUKUP** (`insufficient_evidence`, level `unknown`) | Selain kondisi di atas | Jangan ambil kesimpulan |

Empat aturan menjaga tabel di atas:

1. **Klaim dari model tidak berdiri sendiri.** Agen LLM hampir selalu menemukan sesuatu yang terdengar mengkhawatirkan. Jika level tinggi hanya dinyatakan model dan tidak ada sumber lain dengan severity sedang ke atas, vonis ditahan pada WASPADA dan skornya dipotong maksimal 69. Alasan pemotongan ditampilkan di halaman hasil.
2. **Vonis aman butuh bukti, bukan sekadar tidak ada temuan.** Skor rendah tidak membuat sesuatu menjadi AMAN. Harus ada minimal dua pemeriksaan yang benar-benar selesai dan hasilnya bersih.
3. **Satu sumber tidak boleh menyimpulkan.** Jika pemeriksaan positif yang berhasil dijalankan kurang dari dua, skor dikunci di 60.
4. **Pemeriksaan yang gagal selalu diberitahu.** Setiap pemeriksaan yang tidak selesai, karena kuota habis, timeout, HTTP 429, atau layanannya belum dikonfigurasi, masuk ke `checks_unavailable` dan tampil di halaman hasil. Pengguna tidak pernah melihat kata bersih dari pemeriksaan yang sebenarnya tidak jalan.

Skor 0 sampai 100 dihitung dengan kalibrasi. Tiap temuan memberi bobot severity dikali bobot sumber dikali tingkat keyakinan, dan bukti dari sumber independen digabungkan secara multiplikatif. Beberapa temuan sedang bisa menaikkan skor, sementara satu temuan lemah dari model tidak dapat menghasilkan angka tinggi sendirian.

### 1.3 Pendeteksi domain mirip brand

`brand_guard.py` membandingkan setiap host dengan 80 brand resmi pada `app/data/brands.json`, mencakup bank dan e-wallet Indonesia, e-commerce, layanan logistik, serta beberapa layanan global. Pencocokan bersifat deterministik dan offline, tanpa panggilan jaringan.

| Teknik | Contoh | Level |
|---|---|---|
| Substitusi karakter | `g00gle.com`, `paypa1.com` | tinggi |
| Typosquatting | `goggle.com`, `gooogle.com` | tinggi |
| Homograph dan punycode | `xn--80ak6aa92e.com`, `gооgle.com` | tinggi |
| Nama brand disisipkan | `bca-login.xyz`, `shopee-promo.click` | tinggi |
| Brand di bawah domain lain | `google.com.secure-login.xyz` | tinggi |
| Brand sebagai subdomain | `login.google.security-check.xyz` | sedang |
| Brand di TLD lain | `bca.com` | sedang |

Yang diperiksa adalah host awal, host akhir setelah redirect, domain action form, dan domain yang tertulis di dalam APK. Domain resmi seperti `bca.co.id` dan `mail.google.com` tidak ditandai. Daftar brand dapat diganti melalui `BRAND_ALLOWLIST_PATH` tanpa mengubah kode.

Catatan yang ditulis di antarmuka, bukan hanya di dokumen: yang dideteksi adalah kemiripan nama, bukan bukti bahwa halaman tersebut berbahaya. Phishing yang dipasang di layanan resmi dan domain acak tanpa kemiripan brand tidak tertangkap di bagian ini.

### 1.4 Papan cerita warga

Papan di `/community` dipakai warga menceritakan pengalaman atas satu nomor `+62`. Susunannya mengikuti feed foto, bukan halaman produk.

- Tiga tab punya alamat sendiri: `/community/latest` (Terbaru), `/community/popular` (Terpopuler), dan `/community/phone` (Nomor berbahaya). `/community` meneruskan ke `latest` dan tetap membawa `?nomor=`. Pemisahan ini dibuat karena tab yang dimaksudkan untuk dibagikan atau dibuka kembali esok hari harus bisa ditunjuk sebuah tautan.
- Nomor adalah penanda utama, bukan penulisnya. Setiap baris diawali nomor `+62 812-3456-7890` dalam cetak tebal yang menaut ke halaman nomor tersebut. Identitas penulis tampil sebagai alias `Warga-a1b2c3`, yaitu enam karakter pertama HMAC dari user id; id aslinya tidak pernah dikirim ke browser.
- Gambar bukti wajib untuk setiap cerita, disimpan lewat jalur yang sama dengan laporan nomor.
- Vote hanya mengubah urutan feed. Satu akun punya satu suara per cerita, berupa berguna, tidak berguna, atau cabut suara. Vote tidak memengaruhi risiko, level, maupun daftar Nomor berbahaya, karena jika ikut menghitung, daftar itu bisa dimenangkan oleh siapa pun dengan banyak akun.
- Komentar dua tingkat. Balasan ke balasan ditolak dengan `reply_too_deep`, dan komentar induk harus berada di cerita yang sama.
- Pemilik dapat menghapus cerita atau komentarnya sendiri secara permanen, tanpa arsip dan tanpa salinan. Balasan merupakan anak dari komentarnya, sehingga ikut terhapus, termasuk balasan dari akun lain. Karena itu tampilan konfirmasi menjelaskannya sebelum tindakan, bukan sesudah. Moderator menurunkan cerita, tidak menghapus tulisan penulisnya.
- Cerita warga bukan bukti dan bukan vonis. Satu cerita yang benar atas sebuah nomor belum tentu tentang orang yang sama, karena nomor bisa dipalsukan dan bisa berpindah pemilik. Tidak ada cerita yang dapat menaikkan risiko sebuah nomor.

Batas penulisan: enam cerita per jam, lima komentar per menit, dua puluh komentar per jam, tiga puluh vote per menit.

### 1.5 Laporan nomor berbahaya

Jalur ini adalah satu-satunya yang dapat menempatkan sebuah nomor ke daftar berbahaya.

- Gambar bukti wajib, satu berkas per laporan, maksimal 5 MB. Tipe dibaca dari magic byte, bukan dari ekstensi: `png`, `jpeg`, `webp`, `heic`, dan `heif` diterima; `gif` dan berkas non-gambar ditolak.
- Jika penyimpanan bukti gagal, laporan ditolak dengan `503` dan tidak ada baris database yang dibuat. Aturan bukti wajib tidak boleh melonggar menjadi sekadar anjuran.
- Satu laporan per akun per nomor. Laporan kedua atas nomor yang sama dijawab `409 duplicate_report`, sehingga satu orang tidak dapat membuat sebuah nomor tampak dilaporkan banyak orang.
- Semua laporan mulai pada status `pending`. Sebuah klaim tidak menaikkan risiko sampai moderator membaca laporannya beserta gambarnya.
- Nomor masuk daftar berbahaya setelah satu laporan disetujui. Yang menjadi ambang adalah keputusan manusia yang memeriksa bukti, bukan jumlah pelapor. Pelapor tidak dapat menaikkan laporannya sendiri, dan warga yang benar tidak perlu menunggu orang asing kedua kebetulan melaporkan nomor yang sama.
- Kolom catatan untuk pelapor dibatasi 280 karakter dan hanya dibaca moderator. Isinya tidak dikirim ke LLM dan tidak ditampilkan ke pengguna lain.
- Bukti disimpan pada folder dengan akhiran acak, sehingga URL bukti tidak dapat dijelajahi. Penghapusan memanggil CDN invalidate; secara terukur URL yang sama berubah menjadi 404 dalam 30 detik.

Batas penulisan: sepuluh laporan per jam per akun.

### 1.6 Modul edukasi

Delapan simulasi percakapan penipuan tersedia di `/learn`. Setiap skenario dibuka sebagai percakapan dengan tampilan aplikasi pesan: balon pesan, header, bilah input, latar coretan, dan lampiran yang dapat disentuh langsung. Pilihannya bercabang, pihak lawan memberi reaksi atas balasan yang dipilih, dan tiap keputusan dinilai.

| Skenario | Modus yang dilatih |
|---|---|
| Percakapan dengan Kurir J&T Palsu | Lampiran APK berkedok resi paket; berkas APK-nya benar-benar tampil sebagai lampiran di dalam percakapan |
| Panggilan CS Bank BCA Palsu | Perubahan tarif yang meminta pengguna pindah ke kanal resmi palsu |
| Undangan Pernikahan Teman Lama | Tautan undangan yang meminta nomor dan kode verifikasi |
| Teror Salah Transfer Pinjol Ilegal | Utang fiktif disertai ancaman menyebarkan data |
| Pemberitahuan Surat Tilang ETLE | Denda palsu dengan tautan pembayaran |
| Wawancara Kerja Freelance Bodong | Pekerjaan yang meminta biaya lebih dahulu |
| Pemenang Undian Belanja Marketplace | Hadiah yang meminta pajak sebelum dicairkan |
| Titip Dana Trading Kripto Bodong | Janji imbal hasil dan dana yang tidak kembali |

Setelah percakapan selesai, muncul lembar bedah forensik yang menjelaskan taktik apa yang dipakai penipu pada setiap pesan, panel telemetri yang memperlihatkan data apa yang bocor dari pilihan pengguna, dan skor 0 sampai 100. Rekor tiap skenario disimpan di perangkat, sehingga skenario dengan skor rendah dapat diulang. Tujuannya bukan menghafal jawaban yang benar, melainkan mengenali polanya ketika percakapan serupa terjadi sungguhan.

### 1.7 Panduan darurat

Halaman `/guide` ditujukan untuk orang yang sedang mengalami penipuan, jadi isinya tindakan beserta nomor yang benar, bukan penjelasan umum.

**Checklist 15 menit**, dibagi dalam empat fase dengan langkah yang dapat dicentang.

- Fase 1, menit 0 sampai 5: hubungi call center bank untuk memblokir rekening dan m-banking, minta pemblokiran rekening penampung tujuan transfer, lalu catat nomor tiket pengaduan resmi dari bank.
- Fase 2, menit 5 sampai 10: aktifkan mode pesawat dan matikan Wi-Fi, cabut izin aksesibilitas, hapus berkas APK trojan dari ponsel.
- Fase 3, menit 10 sampai 15: ganti kata sandi email utama dari perangkat lain yang bersih, lakukan logout pada semua sesi, pindahkan 2FA ke aplikasi authenticator dan tinggalkan SMS.
- Fase 4: ekspor dan amankan seluruh bukti digital berupa tangkapan layar dan mutasi rekening, buat laporan polisi resmi di SPKT atau Patroli Siber Polri, lalu laporkan nomor dan rekening ke Satgas PASTI OJK dan Kominfo.

**Direktori call center sepuluh bank.** Untuk setiap bank tersedia nama resmi, hotline, nomor internasional, nomor WhatsApp resmi, dan catatan jam layanan. Contohnya Halo BCA 1500888 dengan WhatsApp resmi +62 811-1500-888, Mandiri Call 14000, dan Contact BRI 1500017. Bagian ini berguna karena penipu biasanya menghubungi korbannya lebih dahulu dan menyediakan nomor call center palsu; nomornya tidak diambil dari pemberi telepon, melainkan dari daftar ini. Setiap entri juga mengingatkan bahwa WhatsApp bank resmi selalu punya centang hijau.

**Enam hotline nasional** dalam lima kategori: Penegakan Hukum Kepolisian (110), Otoritas Jasa Keuangan (157), Kementerian Komunikasi dan Informatika, Bank Sentral Republik Indonesia, dan Perlindungan Korban Kejahatan. Seluruhnya dapat langsung dihubungi dari halaman.

### 1.8 Meja moderasi

Console tim berada di `/admin`. Rute ini selalu menuju `/admin/login` lebih dahulu dan tidak pernah langsung membuka halaman belakangnya, karena moderator yang dikirim ke login warga akan kembali tanpa role-nya diperiksa. Akun yang bukan admin langsung dikeluarkan lagi dari sesi tersebut.

- `/admin/dasbor` menampilkan empat angka inti, yaitu akun baru, laporan nomor berbahaya, cerita warga, dan nomor berbeda dilaporkan; grafik garis pertumbuhan untuk angka yang dipilih; serta donut kategori laporan. Rentang waktu 7 hari, 1 bulan, 3 bulan, dan 1 tahun, masing-masing dibandingkan dengan periode sebelumnya. Seluruh angka dihitung di Postgres oleh satu fungsi dan diambil dengan satu panggilan, supaya tidak ada empat query yang hasilnya saling berbeda.
- `/admin/laporan` adalah antrean laporan nomor dengan filter status dan pencarian. Satu baris memuat klaim, gambar bukti, dan data pelapor. Keputusan setujui, tolak, atau tandai spam dikirim apa adanya sebagai status ke layanan internal, dan satu persetujuan itulah yang menaikkan nomor ke daftar berbahaya.
- `/admin/posting` adalah antrean cerita warga, tempat moderator menurunkan cerita yang melanggar tanpa menghapus tulisan pemiliknya.
- Sesi yang menganggur satu jam dikembalikan ke pintu masuk beserta alasannya, sehingga moderator tahu mengapa ia keluar.

### 1.9 Batas teknis

- Worker browser berjalan non-root, tanpa jaringan internet langsung dan tanpa jaringan backend. Seluruh akses keluar lewat proxy egress yang mem-pin DNS dan hanya mengizinkan HTTP dan HTTPS pada port 80 dan 443.
- Worker APK memakai root filesystem read-only, tanpa rute internet sama sekali, dengan batas CPU, memori, dan jumlah proses. Worker ini hanya mengambil bukti; seluruh keputusan risiko berada di `analysis-service`.
- Worker browser dan APK menerima kunci turunan HMAC dari `SERVICE_API_KEY`, bukan kunci induknya.
- Batas layanan: enam scan per menit, empat puluh scan per jam, dan dua belas scan APK per jam. APK mendapat kuota tersendiri karena satu pemindaian jauh lebih mahal. Ukuran unggahan maksimal 50 MB.
- Sesi keluar otomatis setelah satu jam tanpa aktivitas, dengan batas keras 24 jam. Callback OAuth tidak memicu logout mendadak.
- `next.config.ts` mengirim CSP, HSTS, `nosniff`, `Referrer-Policy`, `frame-ancestors 'none'`, dan Permissions-Policy. Log Python melewati filter yang menutup API key, JWT, rahasia 64 hex, bearer token, dan DSN database sebelum ditulis.
- Ikon dibundel di dalam aplikasi, tidak diambil dari API pihak ketiga, sehingga halaman tetap tampil utuh tanpa koneksi keluar.
- Berkas yang kedaluwarsa dihapus oleh tugas latar: objek di Storage lebih dahulu, lalu barisnya. Intervalnya dapat diatur.

### 1.10 Bagian yang tidak dibuat

- Pencarian nama pemilik nomor dan integrasi layanan seperti GetContact. Keduanya menuntut akun atau kredensial pada layanan pihak ketiga yang klausulnya melarang pemakaian tersebut, dan akan menyimpan data pribadi orang lain tanpa dasar hukum. ThreatLens melaporkan bahwa sebuah nomor sudah ditandai orang lain, bukan bahwa nomor itu milik seseorang.
- Emulator untuk menjalankan APK. Kami tidak mengirim emulator. Jika sandbox analisis dinamis tidak disediakan, scan mencatat `dynamic_analysis` sebagai pemeriksaan yang tidak tersedia, tidak berpura-pura memiliki cakupan runtime.
- Moderasi otomatis. Keputusan yang menaikkan risiko sebuah nomor selalu diambil oleh manusia.

---

## 2. Yang perlu disiapkan

Stack ini berjalan di komputer lokal, tetapi tidak sepenuhnya offline. Database, auth, penyimpanan berkas, dan model bahasa berada di layanan pihak ketiga.

| Layanan | Kegunaan | Kondisi |
|---|---|---|
| Supabase (proyek hosted) | Database, auth, Storage | Wajib |
| OpenAI | Agen pemeriksa tautan dan APK | Wajib untuk deteksi |
| Cloudflare Turnstile | Anti-bot pada form login | Wajib untuk login |
| Google OAuth | Login warga | Wajib untuk login |
| Cloudinary | Penyimpanan gambar bukti laporan dan cerita | Wajib jika akan melapor atau posting |
| Safe Browsing, VirusTotal, IC4, Malwarebytes, Exa, MobSF, sandbox dinamis | Sumber reputasi tambahan | Opsional. Yang tidak diisi hanya dilaporkan sebagai pemeriksaan yang tidak tersedia |

Di komputer lokal: Docker Desktop dalam keadaan berjalan, dan Git. Untuk menjalankan tes di luar container diperlukan Node.js 20+, Go 1.23+, dan Python 3.10+.

---

## 3. Mengambil kode

Keempat repo harus berada sejajar di dalam satu folder induk, tidak bersarang dan tidak sebagai submodule. `docker-compose.yml` memakai path `../frontend`, `../backend`, dan `../analysis-service`, jadi posisi folder menentukan apakah build berhasil.

```bash
mkdir mitweek
cd mitweek

git clone https://github.com/MITWEEK-inponamatim/infra.git
git clone https://github.com/MITWEEK-inponamatim/frontend.git
git clone https://github.com/MITWEEK-inponamatim/backend.git
git clone https://github.com/MITWEEK-inponamatim/analysis-service.git
```

Bentuk akhirnya:

```text
mitweek/
├── infra/              # compose, migrasi Supabase, dokumentasi
├── frontend/           # Next.js 16 dan React 19
├── backend/            # Go API
└── analysis-service/   # Python: agen deteksi, LangGraph, worker browser dan APK
```

---

## 4. Membuat file .env

Ada empat file contoh. Docker Compose berhenti lebih dahulu jika salah satu `.env` belum ada, jadi buat semuanya sebelum menjalankan.

```bash
cp frontend/.env.example           frontend/.env
cp backend/.env.example            backend/.env
cp analysis-service/.env.example   analysis-service/.env
cp infra/supabase/.env.example     infra/supabase/.env
```

Semua `.env` sudah di-ignore oleh Git. Yang di-commit hanya `.env.example`.

### `frontend/.env`

| Variabel | Nilai |
|---|---|
| `NEXT_PUBLIC_SUPABASE_URL` | URL proyek Supabase |
| `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY` | publishable key |
| `NEXT_PUBLIC_TURNSTILE_SITE_KEY` | site key Turnstile |
| `NEXT_PUBLIC_API_BASE_URL` | `http://localhost:8080` |
| `NEXT_PUBLIC_IDLE_TIMEOUT_SECONDS` | `3600` |

### `backend/.env`

| Variabel | Nilai |
|---|---|
| `SUPABASE_URL` | sama dengan yang di frontend |
| `SUPABASE_PUBLISHABLE_KEY`, `SUPABASE_SECRET_KEY`, `SUPABASE_JWT_SECRET` | Supabase, Settings, API |
| `TURNSTILE_SECRET_KEY` | secret key Turnstile |
| `TURNSTILE_EXPECTED_HOSTNAME` | `localhost` |
| `SERVICE_API_KEY` | bebas, asal panjang. Wajib sama persis dengan di `analysis-service/.env` |
| `PRE_COOKIE_SECRET` | bebas, asal panjang. Dipakai untuk membentuk alias penulis |
| `DATABASE_URL` | boleh kosong. Jika terisi, Go membaca Postgres lewat pgx; jika kosong, lewat PostgREST. Keduanya berjalan |
| `DATABASE_URL_SESSION` | tidak dipakai di sisi Go |
| Sisa variabel | punya default di kode, biarkan seperti contoh |

### `analysis-service/.env`

| Variabel | Nilai |
|---|---|
| `SUPABASE_URL`, `SUPABASE_SECRET_KEY` | sama dengan yang di backend |
| `SERVICE_API_KEY` | sama persis dengan yang di backend |
| `OPENAI_API_KEY`, `OPENAI_MODEL` | kunci dan model agen |
| `CLOUDINARY_URL`, `CLOUDINARY_CLOUD_NAME` | lihat catatan Cloudinary pada bagian 8 |
| `DATABASE_URL_SESSION` | kolom `connectionString` pada Supabase, Settings, Database. Boleh kosong; jika kosong, checkpoint LangGraph dilaporkan tidak tersedia dan analisis tetap jalan |
| `SAFE_BROWSING_API_KEY`, `VIRUSTOTAL_API_KEY`, `EXA_API_KEY`, `MOBSF_URL`, `MOBSF_API_KEY`, `DYNAMIC_ANALYSIS_URL` | opsional |

### `infra/supabase/.env`

`SUPABASE_AUTH_EXTERNAL_GOOGLE_CLIENT_ID` dan `SUPABASE_AUTH_EXTERNAL_GOOGLE_SECRET` dari Google Cloud Console, seperti pada bagian 7.

---

## 5. Membuat kunci turunan worker

Dua file berikut tidak ada di repo dan tidak perlu ditulis manual. Worker browser dan worker APK menerima kunci turunan dari `SERVICE_API_KEY` berupa HMAC-SHA256, supaya keduanya tidak pernah memegang kunci induk. `analysis-worker` menolak start jika `FILE_WORKER_SERVICE_KEY` kosong.

Jalankan di **PowerShell**, dari folder `mitweek`:

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

Hasilnya `analysis-service/.env.browser` dan `analysis-service/.env.worker`. Ulangi langkah ini setiap kali `SERVICE_API_KEY` diganti. Jika tidak, scan URL dan APK gagal dengan error 401 internal.

---

## 6. Menjalankan migrasi database

Ini langkah yang paling sering terlewat, dan tanpa langkah ini ada fitur yang tampak rusak padahal datanya belum ada. Skema berada di `infra/supabase/migrations/` dan dijalankan satu per satu sesuai urutan nama file.

| File | Jika belum dijalankan |
|---|---|
| `202610300001_initial_schema.sql` | Tidak ada satu pun fungsi yang bekerja |
| `202610300002_langgraph_schema.sql` | Checkpoint agen tidak tersedia |
| `202610300004_phone_reports_trust.sql` | Laporan ganda hanya ditahan pemeriksaan aplikasi |
| `202610300005_phone_reports_note.sql` | Catatan laporan tidak tersimpan, jawaban `note_saved: false` |
| `202611040006_phone_reports_evidence.sql` | Setiap laporan nomor ditolak `503`, gambar yang sudah terunggah dihapus lagi |
| `202611040007_community_posts.sql` | Papan warga menjawab 503, cerita baru ditolak |
| `202611060008_scan_evidence_items.sql` | Item bukti scan tidak tersimpan |
| `202611070001_admin_roles.sql` | Tidak ada akun admin, `/admin` selalu menolak |
| `202611090009_dangerous_numbers_single_approval.sql` | Daftar Nomor berbahaya masih memakai ambang lama |
| `202611100010_admin_desk_stats.sql` | `/admin/dasbor` menampilkan "Angka dasbor belum bisa diambil" |

### Cara pertama, lewat Supabase SQL Editor

Buka Supabase Dashboard, masuk ke SQL Editor, lalu jalankan isi setiap file dari `0001` sampai `0010` berturut-turut. Setelah selesai, jalankan satu perintah ini agar PostgREST melihat fungsi baru:

```sql
select pg_notify('pgrst', 'reload schema');
```

Tanpa perintah terakhir, `admin_desk_stats()` sudah ada di database tetapi PostgREST masih menjawab 404, dan dasbor tetap menampilkan error.

### Cara kedua, lewat Supabase CLI

```bash
cd infra
supabase login
supabase link --project-ref PROJECT_REF_ANDA
supabase db push
```

Pemeriksaan singkat setelahnya, jalankan di SQL Editor:

```sql
select to_regprocedure('public.admin_desk_stats(text)') as fungsi_sudah_ada;
select count(*) as jumlah_cerita from public.community_posts;
```

---

## 7. Konfigurasi auth

### URL aplikasi

Supabase, Authentication, URL Configuration:

- Site URL: `http://localhost:3000`
- Redirect URLs: `http://localhost:3000/auth/callback`

### Google OAuth

Di Google Cloud Console, buat OAuth client ID tipe Web, lalu tambahkan `https://<project-ref>.supabase.co/auth/v1/callback` ke Authorized redirect URIs. Masukkan client ID dan secret ke `infra/supabase/.env`, kemudian terapkan dari folder `infra`:

```powershell
Set-Location infra
.\supabase\apply-auth-config.ps1 -Preview
.\supabase\apply-auth-config.ps1
```

Jalankan yang pertama lebih dahulu untuk melihat apa yang akan diubah.

### Membuat akun moderator

Login meja moderasi memakai email dan password, bukan Google, jadi moderator membutuhkan akun sendiri.

1. Supabase, Authentication, Users, Add user. Isi email dan password, centang Auto Confirm User.
2. Jalankan di SQL Editor, ganti email dengan akun yang baru dibuat:

```sql
update public.profiles
   set role = 'admin'
 where id = (select id from auth.users where email = 'moderator@contoh.id');

select id, role from public.profiles where role = 'admin';
```

Perintah kedua harus menampilkan akun tersebut. Jika hasilnya kosong, `/admin/login` akan langsung mengeluarkan Anda lagi.

---

## 8. Menjalankan stack

Dari folder `mitweek`:

```bash
docker compose -f infra/docker-compose.yml up --build -d
```

Build pertama mengambil image Chromium dan memasang dependensi Python, Go, dan Node.js di dalam container, jadi dapat memakan waktu 10 sampai 20 menit. Pantau keadaannya dengan:

```bash
docker compose -f infra/docker-compose.yml ps
```

Tujuh service harus naik, lima di antaranya berstatus healthy:

| Service | Peran |
|---|---|
| `frontend` | Next.js pada `http://localhost:3000` |
| `go-api` | API publik pada `http://localhost:8080`. Selain frontend, hanya inilah yang bisa dijangkau browser |
| `analysis-service` | Orkestrasi agen dan risk engine, hanya di network internal |
| `browser-gateway`, `browser-worker`, `browser-egress` | Chromium terisolasi beserta proxy keluarnya |
| `analysis-worker` | Analisis APK statis, tanpa akses internet |

Untuk menghentikan: `docker compose -f infra/docker-compose.yml down`. Untuk melihat log satu service: `docker compose -f infra/docker-compose.yml logs -f go-api`.

Catatan Cloudinary. SDK membaca `CLOUDINARY_URL` hanya jika `CLOUDINARY_CLOUD_NAME` tidak diset. Proyek ini menyetel keduanya, jadi nama cloud pada URL harus sama dengan nilai `CLOUDINARY_CLOUD_NAME`; host `dlwbthmsn0` tidak valid, yang benar `wbthmsn0` tanpa awalan `d`. Kegagalan upload bukti membuat laporan ditolak dengan `503 evidence_unavailable` dan baris database tidak dibuat. Itu perilaku yang dirancang, bukan kerusakan.

---

## 9. Memastikan semuanya benar-benar berjalan

Lakukan berurutan. Semua langkah ini harus berhasil sebelum stack dinyatakan siap.

1. Buka `http://localhost:3000`. Halaman tampil dan ikon muncul. Jika kotaknya kosong, lihat bagian 11.
2. Login warga lewat Google dan tiba di `/recognize` tanpa error.
3. Periksa satu tautan yang jelas aman pada tab Tautan. Proses selesai di `/recognize`, lalu halaman berpindah sendiri ke `/recognize/url/<scan_id>`. Buka alamat itu dengan Ctrl+Shift+R; hasilnya harus tetap ada dan tidak menjalankan pemeriksaan ulang.
4. Periksa satu nomor `+62` yang sudah pernah dilaporkan di tab Telepon. `/recognize/phone/<nomor>` harus menampilkan bagian Kata warga jika ada laporannya.
5. Kirim satu laporan dari `/community/phone` beserta gambarnya. Jika kembali ke form tanpa pesan error tetapi laporan tidak muncul, hampir pasti migrasi `0006` belum dijalankan.
6. Buat satu cerita di `/community/latest` dengan gambar, beri vote, dan komentari. Buka alamat yang sama pada tab lain dengan akun kedua untuk memastikan komentar tampil.
7. Buka `/admin/login` dan masuk dengan akun moderator. `/admin/dasbor` harus menampilkan angka, bukan kartu error. Klik kartu metrik untuk memindahkan garis, dan ganti rentang untuk melihat label sumbu berubah.
8. Setujui laporan dari langkah 5 lewat `/admin/laporan`, lalu pastikan nomor itu muncul di tab Nomor berbahaya pada `/community/phone`.
9. Periksa kesehatan layanan dari komputer:

```bash
curl -s -H "X-Service-Key: ISI_SERVICE_API_KEY_ANDA" http://localhost:8080/internal/v1/metrics
```

Yang keluar adalah JSON berisi pencacah seperti `scans_created` dan `jobs_completed`, dan store aktif, `pgx` atau `postgrest`.

---

## 10. Berkembang tanpa container

Container tetap dipakai untuk `analysis-service`. Untuk mengubah kode frontend atau backend sambil melihat hasilnya:

```bash
# terminal pertama, Go API di host, membaca backend/.env
cd backend
go run .

# terminal kedua, Next.js dev di host, membaca frontend/.env
cd frontend
npm install
npm run dev
```

`NEXT_PUBLIC_API_BASE_URL` menunjuk ke `http://localhost:8080`, jadi frontend dev bisa memakai Go API di host maupun di container. Hentikan dulu pasangan di container agar port tidak rebutan:

```bash
docker compose -f infra/docker-compose.yml stop go-api frontend
```

Periksa sebelum commit:

```bash
(cd backend && go test ./...)
(cd analysis-service && python -m pytest)
(cd frontend && npm install && npm run icons && npm run lint && npx tsc --noEmit && npm run build)
docker compose -f infra/docker-compose.yml config --quiet
```

Perintah `npm run icons` tidak boleh dilewat. Ia menyusun ulang bundel ikon dari referensi yang ada di `src/`; ikon baru yang belum masuk bundel tampil kosong.

---

## 11. Jika ada yang tidak berjalan

| Gejala | Penyebab dan perbaikan |
|---|---|
| `/admin/dasbor` menampilkan "Angka dasbor belum bisa diambil" | Migrasi `202611100010` belum dijalankan, atau sudah dijalankan tetapi PostgREST belum membaca ulang schema. Jalankan `select pg_notify('pgrst', 'reload schema');`. Jika masih gagal, periksa `docker compose -f infra/docker-compose.yml logs go-api` dan cari baris yang diawali `desk stats`; baris itu menyebut penyebab aslinya |
| Semua laporan nomor berbalik `503` | Migrasi `0006` belum diterapkan |
| Papan warga menjawab `503 service_unavailable` | Migrasi `0007` belum diterapkan |
| `/admin/login` mengeluarkan Anda lagi | Akun belum berrole `admin` (bagian 7), atau kolom role belum ada karena `202611070001` belum diterapkan |
| Login warga gagal di callback | Site URL dan Redirect URL Supabase belum `http://localhost:3000` dan `http://localhost:3000/auth/callback` |
| Scan URL selalu menjawab bukti belum cukup | `BROWSER_EGRESS_PROXY_URL` dan `--host-resolver-rules` harus menunjuk satu nilai yang sama, `http://browser-egress:8888`. Jika keduanya berbeda subnet, setiap halaman mati dengan `ERR_PROXY_CONNECTION_FAILED` dan vonisnya tetap terlihat wajar. Jangan menulis IP subnet di kode, keduanya dibaca dari satu nilai |
| `analysis-worker` tidak mau start | `analysis-service/.env.worker` belum dibuat, ulangi bagian 5. Log worker menyebutkan cara memperbaikinya |
| Upload bukti atau screenshot gagal tanpa pesan | Nama cloud pada `CLOUDINARY_URL` tidak sama dengan `CLOUDINARY_CLOUD_NAME` (bagian 8) |
| Semua ikon tampil kosong | Ikon baru ditambahkan tanpa `npm run icons`. Ikon dibundel lokal, tidak diambil dari API Iconify |
| `docker compose up` gagal sebelum build | Salah satu `.env` belum dibuat. Compose menolak jika `env_file` tidak ditemukan |
| Port 3000 atau 8080 sudah dipakai | Hentikan proses lain, atau jalankan `down` lalu naikkan kembali |
| Scan nomor mengembalikan hasil kosong untuk nomor luar negeri | Bukan kerusakan. Layanan hanya menerima `+62`, dan untuk di luar itu pemeriksa menyatakan tidak bisa memeriksa, bukan menyatakan aman |

---

## 12. Struktur dan dokumen lanjutan

```text
frontend/          src/app (rute) · src/components (UI per area) · src/lib (tipe API) · src/hooks
backend/           main.go (rute) · admin.go (meja moderasi) · community.go · store.go (Postgres dan PostgREST)
analysis-service/  app/scanners.py · app/graph (LangGraph url, phone, application) · app/risk.py · app/brand_guard.py
infra/             docker-compose.yml · supabase/migrations · docs/API_Contracts.md
```

- `infra/docs/API_Contracts.md`, daftar setiap batas HTTP: rute publik, rute internal dengan service key, dan bentuk body-nya.
- `infra/README.md`, keputusan desain per subsistem beserta alasan tiap batasan.
- `PANDUAN_SETUP_TIM.md`, versi pendek dari bagian setup di dokumen ini.
