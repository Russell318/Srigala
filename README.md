# 🐺 SRIGALA — Secure File Transfer (Kode Terpisah + Dekripsi Interaktif)



## 1. Struktur Berkas

```
srigala/
├── app.py                 # Flask app: routing, state, alur dekripsi interaktif
├── crypto_utils.py         # SEMUA fungsi kriptografi (4 pilar keamanan)
├── network_relay.py        # Socket TCP: framing pesan + server relay
├── templates/
│   ├── setup.html          # Form pilih peran (HOST/CLIENT)
│   ├── nav.html             # Menu navigasi (dipakai di semua halaman)
│   ├── dashboard.html       # Ringkasan status + jalan pintas
│   ├── send.html            # Halaman khusus KIRIM file
│   ├── inbox.html           # Halaman khusus TERIMA & daftar file untuk didekripsi
│   ├── decrypt.html         # Proses dekripsi & verifikasi 5-langkah per file
│   └── keys.html            # Kunci identitas + tombol Generate + edukasi
├── static/
│   └── style.css            # CSS terpisah dari HTML
└── data/                    # dibuat otomatis: kunci & file diterima per user
```

## 1b. Menu: Kirim & Terima (dua arah, HOST maupun CLIENT)

Menu navigasi sekarang punya 4 halaman: **🏠 Dashboard**, **📤 Kirim File**,
**📥 Terima & Dekripsi**, **🔑 Kunci & Generate**. Peran HOST/CLIENT **tidak**
membatasi arah pengiriman — begitu HOST menjalankan server relay dan CLIENT
berhasil terhubung ke situ, **keduanya** muncul sebagai peer online satu sama
lain dan **sama-sama bisa memakai halaman Kirim maupun Terima**. HOST bukan
cuma penerima, dan CLIENT bukan cuma pengirim.

Kalau di dashboard Anda melihat **"Status koneksi: Terputus"** dan daftar
peer kosong, itu artinya belum ada koneksi TCP yang berhasil ke server relay
— cek 3 hal ini:
1. Komputer yang berperan **HOST** benar-benar sudah dijalankan & server
   relay-nya aktif (lihat log `[RELAY] Server relay berjalan di ...`).
2. Alamat IP & port yang diisi di sisi **CLIENT** sama persis dengan IP
   komputer HOST + port relay-nya (bukan port GUI Flask).
3. Kedua komputer satu jaringan dan tidak diblokir firewall/NAT (kalau beda
   VM/jaringan virtual seperti VirtualBox NAT, biasanya perlu port-forward
   atau ganti ke mode "Bridged"/host-only).

Setelah itu klik "🔄 Refresh direktori" di halaman manapun.

Python (logika) dan HTML (tampilan) sekarang benar-benar terpisah — cocok
untuk dipelajari satu-per-satu: mulai dari `crypto_utils.py` (paling inti),
lalu `network_relay.py`, baru `app.py`, baru `templates/*.html`.

## 2. Instalasi & Menjalankan

```bash
pip install flask cryptography
python app.py 5001    # instance 1
python app.py 5002    # instance 2 (di komputer lain: python app.py, default port 5000)
```

Buka browser sesuai port, misal `http://127.0.0.1:5001`, lalu pilih peran
**HOST** atau **CLIENT** seperti pada versi sebelumnya (lihat contoh skenario
2 komputer di bagian bawah).

## 3. Soal Dekripsi: Otomatis vs Interaktif

Di versi lama, begitu file terenkripsi sampai, aplikasi **langsung**
mendekripsi dan memverifikasinya di belakang layar — Anda hanya melihat
hasil akhirnya ("SAH" atau "GAGAL"). Prosesnya benar tapi tidak terlihat.

Di **SRIGALA**, file yang masuk berstatus **"⏳ Menunggu Dekripsi"** dan
tetap dalam bentuk terenkripsi (nonce, ciphertext, hash, tanda tangan — semua
masih tersimpan apa adanya). Anda harus membuka halaman file itu dan menekan
tombol **"🔓 Mulai Proses Dekripsi & Verifikasi"**. Setelah itu, ke-5 langkah
berikut dijalankan dan ditampilkan satu-per-satu, lengkap dengan detail teknis:

| # | Langkah | Pilar Keamanan |
|---|---|---|
| 1 | Penurunan kunci sesi (ECDH P-256 + HKDF-SHA256) | Kerahasiaan |
| 2 | Dekripsi AES-256-GCM (auth tag) | Kerahasiaan + Integritas |
| 3 | Pencocokan hash SHA-256 | Integritas |
| 4 | Verifikasi tanda tangan ECDSA | Autentikasi |
| 5 | Pencocokan kunci publik pengirim ke direktori server | Non-Repudiasi |

File hanya **disimpan ke disk & bisa diunduh** kalau ke-5 langkah di atas
semuanya berhasil. Kalau salah satu gagal, Anda tetap bisa melihat langkah
mana yang gagal dan kenapa — bagus untuk latihan (mis. coba kirim file lalu
utak-atik paketnya untuk melihat langkah mana yang menangkapnya).

Ini murni perubahan **kapan** dekripsi dijalankan (dipicu Anda, bukan
otomatis saat file tiba) — keamanannya tidak berkurang: kunci privat Anda
tetap tidak pernah dikirim ke mana pun, dan verifikasi tetap wajib lolos
sebelum file bisa dibuka.

## 4. Fitur Baru: Halaman "Kunci & Edukasi" (`/keys`)

- Menampilkan kunci publik identitas Anda + sidik jari (fingerprint) singkat.
- Tombol **"♻️ Buat Ulang Kunci (Regenerate)"** — untuk latihan: lihat sendiri
  bagaimana file yang ditandatangani dengan kunci lama akan gagal di langkah
  "Pencocokan identitas" kalau Anda mengganti kunci.
- Penjelasan singkat bagaimana tiap pilar keamanan bekerja, jadi bisa dibaca
  langsung dari GUI tanpa buka kode.

Kunci **privat** tidak pernah ditampilkan di GUI mana pun — hanya tersimpan
lokal di `data/<username>/keys/`.

## 5. Memilih Peran & Skenario 2 Komputer

Sama seperti sebelumnya:

- **Komputer A** (mis. IP 192.168.1.10): `python app.py`, buka
  `http://127.0.0.1:5000`, pilih **HOST**, username `Alfha`, port relay `9100`.
- **Komputer B**: `python app.py`, buka `http://127.0.0.1:5000`, pilih
  **CLIENT**, username `Beta`, isi Alamat IP `192.168.1.10`, Port `9100`.
- Setelah keduanya "Mulai", masing-masing saling melihat sebagai peer online
  dan bisa kirim file terenkripsi. Penerima lalu membuka halaman dekripsi
  untuk memverifikasi & membuka file.

## 6. Pemetaan ke 4 Pilar Keamanan (ringkas)

| Pilar | Mekanisme |
|---|---|
| Keamanan (Kerahasiaan) | AES-256-GCM, kunci sesi diturunkan via ECDH (P-256) + HKDF-SHA256 |
| Integritas | Auth tag AES-GCM + pencocokan hash SHA-256 |
| Autentikasi | Tanda tangan ECDSA atas hash file, diverifikasi dengan kunci publik pengirim dari direktori server |
| Non-Repudiasi | Tanda tangan hanya bisa dibuat dengan kunci privat milik pengirim → tak bisa disangkal |

Server relay (mode HOST) **tidak pernah** melihat isi file asli maupun kunci
AES — end-to-end encryption di level aplikasi, sama seperti versi sebelumnya.

## 7. Catatan

- Direktori kunci publik memakai model trust-on-first-use (cukup untuk demo/latihan).
- Setiap pengiriman file memakai kunci ephemeral ECC sekali pakai (forward secrecy sederhana per-transfer).
- File yang gagal verifikasi tidak disimpan dan tidak bisa diunduh.
- Ini server pengembangan Flask (`debug=False`) — untuk penggunaan nyata di luar
  jaringan lokal/latihan, perlu HTTPS, otentikasi tambahan, dan hardening lain.
