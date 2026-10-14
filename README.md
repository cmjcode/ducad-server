# ducad-server

Server otentikasi DUCAD: login Google, GitHub, dan Sign in with Apple, lalu
menerbitkan JWT DUCAD. Aplikasi DUCAD tidak pernah mengurus OAuth sendiri —
ia membuka browser ke server ini dan menjemput tokennya lewat ticket polling.

Keputusan di balik bentuknya ada di
[`ducad-editor/docs/adr/0003-identitas-auth-ducad.md`](../ducad-editor/docs/adr/0003-identitas-auth-ducad.md).

**Yang TIDAK ada di sini**: sinkronisasi dokumen, tim, kolaborasi, enkripsi
vault. Berkas `.ducad` tetap di perangkat pengguna. Empat tabel di
[`src/db/schema.sql`](src/db/schema.sql) adalah seluruh keadaan yang disimpan.

---

## 1. Mengapa server sendiri

DUCAD sebelumnya menumpang server auth bersama milik tim. Dua masalah membuat
basis kode ini dipisahkan:

- **Identitas.** Satu set kredensial OAuth membuat layar consent Google/GitHub
  menyebut nama aplikasi lain, bukan DUCAD — pada momen paling sensitif dalam
  alur login.
- **Percabangan merek.** Alternatifnya adalah memilih kredensial berdasarkan
  query `client` di server bersama, yang menaruh percabangan merek di jalur
  paling sensitif keamanan demi menghemat satu deployment.

Karena itu server ini hanya melayani DUCAD. Query `client=ducad` yang dikirim
klien tetap diterima demi kompatibilitas, tapi tidak disimpan dan tidak
memengaruhi apa pun — halaman suksesnya selalu bermerek DUCAD.

## 2. Menjalankan secara lokal

```bash
cp env.example .env          # lalu isi DATABASE_URL + JWT_SECRET minimal
cargo run                    # migrasi skema jalan otomatis saat start
```

Menunjuk aplikasi DUCAD ke server lokal:

```bash
DUCAD_SERVER_URL=http://127.0.0.1:8430 cargo run -p ducad-app   # di ducad-editor/
```

Google dan GitHub bisa diuji lewat `http://` lokal. **Apple tidak** — lihat §5.

Gerbang mutu (sama seperti yang dijalankan CI):

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
```

## 3. Endpoint

| Metode | Path | Otentikasi | Keterangan |
|---|---|---|---|
| GET | `/health` | — | `ok`; dipakai health check Docker |
| GET | `/api/v1/auth/login/{google\|github\|apple}` | — | 302 ke provider. Klien menambahkan `?client=ducad&ticket=…[&port=…]` |
| GET | `/api/v1/auth/callback/{google\|github}` | — | Redirect balik dari provider |
| POST | `/api/v1/auth/callback/apple` | — | Apple memakai `form_post`, bukan redirect |
| POST | `/api/v1/auth/ticket/poll` | — | Body `{"ticket":"…"}` |
| POST | `/api/v1/auth/refresh` | — | Body `{"refresh_token":"…"}`; token diputar setiap pakai |
| POST | `/api/v1/auth/logout` | — | Body `{"refresh_token":"…"}` |
| GET | `/api/v1/users/me` | Bearer | Profil pemanggil |
| DELETE | `/api/v1/users/me` | Bearer | Hapus akun (App Store Guideline 5.1.1(v)) |

Balasan poll: `{"success":true,"data":{"status":"pending"}}`, atau `status`
`completed` (+`token`), atau `error` (+`error`). Teks `error` ditampilkan apa
adanya di UI aplikasi, jadi ia ditulis dalam bahasa Indonesia.

## 4. Variabel environment

Daftar lengkap beserta penjelasannya ada di [`env.example`](env.example).
Panduan langkah-demi-langkah mendapatkan kredensial (Client ID, Secret, Key ID, Team ID, dan `.p8`) untuk GitHub, Google, dan Apple tersedia di [`tutorial_register_github_google_apple.md`](tutorial_register_github_google_apple.md).

Yang wajib: `DATABASE_URL` dan `JWT_SECRET` — tanpa keduanya proses menolak
start.

Provider yang kredensialnya belum diisi tidak mematikan server: permintaan
login ke provider itu dijawab galat yang menyebut env var yang kurang, dan
pesan itu sampai ke UI aplikasi lewat status ticket `error`. Jadi konfigurasi
setengah jadi terlihat sebagai pesan jelas, bukan login yang menggantung.

## 5. Menyiapkan Sign in with Apple

Urutannya penting, dan satu langkah paling sering tertukar:
**`APPLE_CLIENT_ID` adalah Services ID, bukan bundle ID aplikasi.**

1. **App ID.** Di Apple Developer → Identifiers, pastikan App ID
   `id.ducad.studio` punya capability **Sign in with Apple** aktif.
2. **Services ID.** Buat identifier baru bertipe *Services IDs*, misal
   `id.ducad.studio.signin`. Aktifkan Sign in with Apple, lalu konfigurasikan:
   - **Primary App ID**: `id.ducad.studio`
   - **Domains and Subdomains**: `api.ducad.app`
   - **Return URLs**: `https://api.ducad.app/api/v1/auth/callback/apple`
3. **Key.** Keys → buat key baru dengan Sign in with Apple aktif, unduh
   `AuthKey_XXXXXXXXXX.p8` (**hanya bisa diunduh sekali**). Catat Key ID; Team
   ID ada di kanan atas portal.
4. **Pasang di server** sebagai `APPLE_PRIVATE_KEY_PATH` (disarankan, `.p8`
   di-mount sebagai berkas rahasia) atau `APPLE_PRIVATE_KEY` (PEM inline).

Yang perlu diketahui sebelum menguji:

- **Return URL wajib HTTPS.** Apple menolak `http://` dan `localhost`, jadi
  Sign in with Apple **tidak bisa diuji** lewat server lokal biasa. Pakai
  server staging ber-HTTPS, atau tunnel ber-HTTPS yang domainnya sudah
  terdaftar di Services ID.
- **`form_post`, bukan redirect.** Karena server meminta scope `email`, Apple
  mem-POST hasilnya ke callback. Itulah sebabnya klien mengandalkan ticket
  polling, bukan callback loopback.
- **Nama hanya dikirim sekali.** Apple mengirim nama pengguna hanya pada
  otorisasi pertama; server menyimpannya dan tidak menimpanya dengan `NULL`
  pada login berikutnya. Untuk menguji ulang dari nol, cabut izinnya di
  Apple ID → Sign in with Apple.
- **Email relay privat.** Pengguna bisa menyembunyikan alamat aslinya,
  sehingga emailnya berupa `…@privaterelay.appleid.com` yang bisa berotasi.
  Identitas akun dikunci ke klaim `sub`; email tidak pernah dipakai sebagai
  kunci akun (lihat §7).

## 6. Deploy

```bash
cp env.example .env        # isi kredensial produksi
./deploy.sh                # build image, jalankan, cek /health
```

`deploy.sh` sengaja **tidak** membuat `.env` otomatis dari `env.example`:
menyalinnya akan menjalankan produksi dengan `JWT_SECRET` contoh.

Proses ini tidak meneminasi TLS. Taruh di belakang nginx/Caddy yang memegang
sertifikat `api.ducad.app`, dan arahkan ke port yang dipublikasikan container.

## 7. Catatan desain yang mudah salah paham

- **Email bukan kunci akun.** Upsert dikunci ke `(provider, provider_id)`.
  Login lewat dua provider dengan alamat yang sama menghasilkan dua akun —
  itu disengaja: menggabungkan berdasarkan email berarti pemegang akun GitHub
  dengan alamat tersebut bisa masuk ke akun Google seseorang.
- **Ticket adalah kredensial pembawa.** Siapa pun yang menebaknya sebelum
  pengguna selesai login bisa menjemput tokennya. Karena itu ticket dibuat
  klien dari CSPRNG 128-bit, dan server menjadikannya sekali pakai
  (`consumed`) begitu dijemput.
- **Ticket tak dikenal dijawab `pending`, bukan `error`.** Klien mulai
  memolling sebelum pengguna selesai login, jadi baris ticket bisa belum ada
  saat poll pertama datang.
- **Kegagalan callback dituliskan ke ticket.** Tanpa itu aplikasi hanya diam
  sampai timeout 3 menit ketika kode kedaluwarsa atau provider tak bisa
  dihubungi.
- **Nama tampilan dari provider di-escape sebelum masuk halaman sukses.**
  `serde_json` tidak meng-escape `<`, sehingga nama yang memuat `</script>`
  akan menutup blok skrip lebih awal — XSS dengan data yang dikendalikan
  orang lain. Lihat `auth::success_page::escape_for_script`.
- **`refresh_token` diputar setiap dipakai**, jadi token yang bocor hanya bisa
  dipakai sekali.
