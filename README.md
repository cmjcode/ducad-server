# ducad-server

Server akun DUCAD: login Google, GitHub, dan Sign in with Apple, lalu
menerbitkan JWT DUCAD. Aplikasi DUCAD tidak pernah mengurus OAuth sendiri —
ia membuka browser ke server ini dan menjemput tokennya lewat ticket polling.
Selain identitas, server menyimpan tier lisensi (Free/Pro) dan menjadi tempat
sinkronisasi manual berkas `.ducad` + preferensi antar Mac/iPad/Linux/Windows.

Keputusan di balik bentuknya ada di
[`ducad-editor/docs/adr/0003-identitas-auth-ducad.md`](../ducad-editor/docs/adr/0003-identitas-auth-ducad.md).

**Yang TIDAK ada di sini**: sinkronisasi otomatis/real-time, tim,
kolaborasi, enkripsi vault, pembayaran. Sinkronisasi bersifat manual (klien
memutuskan kapan unggah/unduh) dengan deteksi konflik lewat `revision`. Tujuh
tabel di [`src/db/schema.sql`](src/db/schema.sql) adalah seluruh keadaan yang
disimpan — isi berkas berupa blob di MySQL yang sama.

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
| DELETE | `/api/v1/users/me` | Bearer | Hapus akun (App Store Guideline 5.1.1(v)); berkas awan & prefs ikut terhapus (cascade) |
| PUT | `/api/v1/users/me/avatar` | Bearer | Body PNG/JPEG mentah, maks 1 MB |
| GET | `/api/v1/users/{id}/avatar` | — | Foto profil unggahan |
| GET | `/api/v1/sync/files` | Bearer | Daftar metadata berkas + `used_bytes`, `quota_bytes`, `max_file_bytes`, `max_files`, `tier` |
| GET | `/api/v1/sync/files/{id}` | Bearer | Isi berkas mentah; header `X-Ducad-Name` (percent-encoded), `X-Ducad-Revision`, `X-Ducad-Sha256` |
| PUT | `/api/v1/sync/files?name=…&base_revision=n[&force=true]` | Bearer | Body = isi `.ducad`; upsert per nama. 409 `conflict`, 413 `file_too_large`, 403 `quota_exceeded` |
| DELETE | `/api/v1/sync/files/{id}` | Bearer | `{"deleted":true}` |
| GET | `/api/v1/sync/prefs` | Bearer | `{"prefs":…\|null,"revision":n,"updated_at":…\|null}` |
| PUT | `/api/v1/sync/prefs` | Bearer | Body `{"prefs":{…}}`, maks 64 KB, last-write-wins |

Balasan poll: `{"success":true,"data":{"status":"pending"}}`, atau `status`
`completed` (+`token`), atau `error` (+`error`). Teks `error` ditampilkan apa
adanya di UI aplikasi, jadi ia ditulis dalam bahasa Indonesia.

Galat sinkronisasi yang perlu dibedakan klien membawa field `code` mesin
selain teks `error`: `conflict` (409, plus `current`: CloudFile atau `null`),
`file_too_large` (413), `quota_exceeded` (403). Aturan revisi unggahan:
`base_revision=0` = berkas belum boleh ada, `n>0` = revisi server harus `n`,
`force=true` = timpa. Kuota dihitung dengan mengganti ukuran berkas lama bila
menimpa. Berkas yang jauh melebihi `SYNC_MAX_FILE_MB` (+64 KB) ditolak axum
dengan 413 tanpa body JSON.

## 4. Variabel environment

Daftar lengkap beserta penjelasannya ada di [`env.example`](env.example).
Panduan langkah-demi-langkah mendapatkan kredensial (Client ID, Secret, Key ID, Team ID, dan `.p8`) untuk GitHub, Google, dan Apple tersedia di [`tutorial_register_github_google_apple.md`](tutorial_register_github_google_apple.md).

Yang wajib: `DATABASE_URL` dan `JWT_SECRET` — tanpa keduanya proses menolak
start.

Tier dan kuota:

| Env | Default | Arti |
|---|---|---|
| `DEFAULT_LICENSE_TIER` | `Free` | Tier akun BARU (`Free`/`Pro`, tidak peka huruf; nilai lain = gagal start) |
| `SYNC_QUOTA_FREE_MB` | 50 | Total byte semua berkas akun Free |
| `SYNC_QUOTA_PRO_MB` | 5120 | Total byte akun Pro |
| `SYNC_MAX_FILE_MB` | 32 | Batas satu berkas, semua tier |
| `SYNC_MAX_FILES_FREE` | 20 | Jumlah berkas maksimum akun Free |
| `SYNC_MAX_FILES_PRO` | 2000 | Jumlah berkas maksimum akun Pro |

**Akun lama tetap pada tiernya.** Default `DEFAULT_LICENSE_TIER` berubah dari
`Pro` ke `Free`, tapi baris `users` yang sudah ada tidak dimigrasi — akun yang
dibuat saat default masih `Pro` tetap Pro sampai diturunkan manual (§8).
Tier yang tidak dikenal di basis data dihitung sebagai Free untuk kuota.

`SYNC_MAX_FILE_MB` juga menentukan batas body PUT berkas; bila dinaikkan,
naikkan pula `client_max_body_size` di reverse proxy dan `max_allowed_packet`
MySQL (default MySQL 8: 64 MB).

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

## 8. Perintah admin

Tier Pro diberikan manual (belum ada pembayaran). Biner yang sama punya dua
subcommand yang memakai `DATABASE_URL` yang sama, menjalankan migrasi, lalu
keluar — tanpa menyalakan HTTP dan tanpa butuh `JWT_SECRET`:

```bash
ducad-server list-users                      # semua akun + jumlah/byte berkas awan
ducad-server list-users --email a@contoh.id  # akun dengan email itu
ducad-server set-tier <user_id|email> Pro    # atau Free; tidak peka huruf
```

Di container: `docker compose exec <service> ducad-server list-users`. Lokal:
`cargo run -- set-tier a@contoh.id pro`.

Satu email bisa dimiliki lebih dari satu akun (login lewat provider berbeda =
akun berbeda, §7). Bila `set-tier` dengan email cocok ke >1 akun, perintah
gagal dan mencetak id-nya; ulangi dengan `user_id` yang dimaksud. Menurunkan
akun ke Free tidak menghapus berkas yang sudah melebihi kuota — unggahan
berikutnya saja yang ditolak `quota_exceeded`.
