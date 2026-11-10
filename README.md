# ThreatLens

Deteksi penipuan untuk nomor, tautan, dan aplikasi Android — dikhususkan untuk nomor Indonesia (`+62`), dengan papan cerita warga dan meja moderasi.

Empat repo, dijalankan jadi satu stack dengan Docker Compose.

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

**APK.** Berkas diperiksa secara statis dan tidak pernah dijalankan. Pertama dihitung SHA-256-nya, lalu reputasi hash ditanyakan ke VirusTotal, itu pun hanya jika pengguna mencentang izin unggah ke layanan eksternal. Sebelum isi arsip dibongkar, dijalankan pemeriksaan zip-bomb: jumlah entri, ukuran tiap entri, total ukuran setelah解压, dan rasio kompresi. Setelah itu Androguard mengambil izin dan kode, dan aturan deterministik menggabungkannya, antara lain izin SMS yang berdampingan dengan aksesibilitas atau kemampuan instalasi overlay, token bot Telegram yang tertanam di berkas, ikon launcher yang disembunyikan, dan petunjuk penggunaan packer. Nama paket dan domain yang tertulis di dalam APK ikut dibandingkan dengan daftar brand resmi.

**Nomor telepon.** Hanya nomor Indonesia yang dilayani. Normalisasi ke E.164 dilakukan satu kali oleh Python; Go API menyimpan hasil hitung tersebut dan tidak menyalin aturannya sendiri. Angka `0` setelah `62` dibuang di ketiga bahasa, sehingga `0812…`, `62812…`, dan `+62 0812…` menunjuk ke alamat yang sama. Pemeriksaan melihat bentuk nomor premium seperti 0900, yang biasa dipakai pada modus telepon tak dikenal yang menagih, lalu mengambil laporan warga atas nomor tersebut. Bagian "Kata warga" menampilkan kategori, status, dan umur laporan, maksimal 20 entri, tanpa menampilkan identitas pelapor.

Pemeriksaan nomor tidak pernah menyimpulkan sebuah nomor aman. Tidak ada dasar data resmi untuk menyatakan nomor perorangan bersih, jadi yang dilaporkan hanya apa yang sudah dinyatakan orang lain tentang nomor itu.

### 1.2 Cara vonis ditetapkan

Bagian ini yang paling sering membuat produk sejenis kehilangan kepercayaan, yaitu quando mesin menyatakan aman tanpa bukti.

| Vonis | Kondisi | Tindakan yang disarankan |
|---|---|---|
| **BERBAHAYA** (`confirmed_threat`, level tinggi) | Satu sumber reputasi independen menyatakan berbahaya | Jangan buka tautan dan jangan berikan data apa pun. Blokir dan laporkan |
| **WASPADA** (`suspicious`, level tinggi) | Temuan tinggi yang didukung sumber non-model, atau beberapa temuan sedang | Jangan masukkan kredensial. Verifikasi lewat kanal resmi |
| **WASPADA** (`suspicious`, level sedang) | Ada temuan sedang, belum cukup untuk naik level | Verifikasi sebelum bertindak |
| **AMAN** (`low`) | Minimal dua sumber independen yang检查结果 bersih dan tidak ada temuan sedang ke atas | Tidak ada sinyal bahaya, tetapi tetap berhati-hati |
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
- Berkti disimpan pada folder dengan akhiran acak, sehingga URL bukti tidak dapat dijelajahi. Penghapusan memanggil CDN invalidate; secara terukur URL yang sama berubah menjadi 404 dalam 30 detik.

Batas penulisan: sepuluh laporan per jam per akun.

### 1.6 Modul edukasi

Delapan simulasi percakapan penipuan tersedia di `/learn`. Setiap skenario dibuka sebagai percakapan dengan tampilan pesan instan: gelembung pesan, header, bilah input, latar coretan, dan lampiran yang dapat disentuh langsung. Pilihannya bercabang, pihak lawan memberi reaksi atas balasan yang dipilih, dan tiap keputusan dinilai.

| Skenario | Modus yang dilatih |
|---|---|
| Percakapan dengan Kurir J&T Palsu | Lampiran APK berkedok resi paket; berkas APK-nya benar-benar tampil sebagai lampiran di gelembung pesan |
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
