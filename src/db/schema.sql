-- Skema MySQL ducad-server.
--
-- Tujuh tabel: lima untuk identitas (users, sessions, oauth_states,
-- auth_tickets, user_avatars) dan dua untuk sinkronisasi manual antar
-- perangkat (cloud_files, user_prefs). Tabel sinkronisasi sengaja berdiri
-- sendiri dan hanya menunjuk ke users lewat foreign key, bukan menyisipkan
-- kolom ke tabel identitas.
--
-- Seluruh pernyataan idempotent dan dijalankan otomatis saat proses start
-- (`db::run_migrations`). Pemisahnya adalah `;`, jadi jangan pakai `;`
-- selain sebagai pengakhir pernyataan.

CREATE TABLE IF NOT EXISTS users (
    id            VARCHAR(36)  NOT NULL PRIMARY KEY,
    provider      VARCHAR(20)  NOT NULL,             -- 'google' | 'github' | 'apple'
    provider_id   VARCHAR(255) NOT NULL,             -- klaim `sub` (Apple/Google) atau id numerik (GitHub)
    -- SENGAJA tidak UNIQUE. Identitas akun dikunci ke (provider,
    -- provider_id): email Apple bisa berupa alamat relay privat yang
    -- berotasi, dan menggabungkan akun berdasarkan email berarti pemegang
    -- akun GitHub dengan alamat yang sama bisa masuk ke akun Google
    -- seseorang. Konsekuensinya: login lewat dua provider = dua akun.
    email         VARCHAR(255) NOT NULL,
    display_name  VARCHAR(255) NULL,
    avatar_url    TEXT         NULL,
    -- 'Free' | 'Pro'. Ditampilkan klien sebagai "Ducad {license_tier} Tier"
    -- dan menentukan kuota sinkronisasi (nilai lain dihitung sebagai Free).
    -- Nilai untuk akun baru datang dari DEFAULT_LICENSE_TIER, bukan dari
    -- default kolom ini - default di sini hanya jaring pengaman untuk INSERT
    -- manual. Basis data lama tetap memakai DEFAULT 'Pro' karena CREATE
    -- TABLE IF NOT EXISTS tidak mengubah tabel yang sudah ada, dan itu tidak
    -- apa-apa karena server selalu mengisi kolom ini secara eksplisit.
    license_tier  VARCHAR(20)  NOT NULL DEFAULT 'Free',
    created_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uq_users_provider (provider, provider_id),
    INDEX idx_users_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Sesi = refresh token. Satu baris per perangkat yang login.
--
-- Tidak ada kolom `device_info`: belum ada UI "perangkat aktif" yang
-- membacanya, dan satu-satunya nilai yang bisa diisi di sini adalah
-- User-Agent browser yang dipakai mengotorisasi — bukan perangkat yang
-- memegang sesinya. Tambahkan bersama fiturnya, bukan sebelumnya.
CREATE TABLE IF NOT EXISTS sessions (
    id            VARCHAR(36)  NOT NULL PRIMARY KEY,
    user_id       VARCHAR(36)  NOT NULL,
    refresh_token VARCHAR(128) NOT NULL UNIQUE,      -- 64 byte acak, hex
    expires_at    DATETIME     NOT NULL,
    created_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_sessions_user (user_id),
    INDEX idx_sessions_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Nonce CSRF sekali pakai, umur 10 menit. Dihapus saat callback dipakai.
--
-- Tidak ada kolom `code_verifier`: PKCE tidak dipakai (ketiga provider
-- diajak bicara dengan client secret dari sisi server, bukan dari klien
-- publik), dan tidak ada kolom nama klien — server ini hanya melayani DUCAD.
CREATE TABLE IF NOT EXISTS oauth_states (
    state         VARCHAR(64) NOT NULL PRIMARY KEY,
    provider      VARCHAR(20) NOT NULL,
    redirect_port INT         NULL,                  -- port loopback klien, bila ada
    ticket        VARCHAR(64) NULL,
    expires_at    DATETIME    NOT NULL,
    created_at    DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_oauth_states_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Relai ticket: satu-satunya jalur pengambilan token yang bekerja di App
-- Sandbox macOS, di iPadOS, dan untuk Sign in with Apple (lihat ADR 0003 §3).
--
-- `payload` menampung DUA hal tergantung `status`: JSON TokenResponse saat
-- 'ready', dan pesan galat untuk pengguna saat 'error'.
CREATE TABLE IF NOT EXISTS auth_tickets (
    ticket     VARCHAR(64) NOT NULL PRIMARY KEY,
    status     VARCHAR(20) NOT NULL DEFAULT 'pending', -- 'pending' | 'ready' | 'error' | 'consumed'
    payload    MEDIUMTEXT  NULL,
    expires_at DATETIME    NOT NULL,
    created_at DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_auth_tickets_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Foto profil yang diunggah pengguna sendiri (mis. akun Apple, yang tidak
-- memberi foto). Satu baris per pengguna; unggahan baru menimpa yang lama.
-- Selama baris ini ada, `users.avatar_url` menunjuk ke
-- `/api/v1/users/{id}/avatar?v=<versi>` dan login ulang lewat provider TIDAK
-- menimpanya (lihat `upsert_user`). Isi dibatasi 1 MB oleh handler, jadi
-- MEDIUMBLOB (16 MB) cukup.
CREATE TABLE IF NOT EXISTS user_avatars (
    user_id      VARCHAR(36) NOT NULL PRIMARY KEY,
    content_type VARCHAR(32) NOT NULL,                -- 'image/png' | 'image/jpeg'
    data         MEDIUMBLOB  NOT NULL,
    updated_at   DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Berkas `.ducad` yang disinkronkan pengguna. Isi disimpan sebagai blob di
-- MySQL yang sama: volume yang diharapkan kecil (kuota Free 50 MB) dan satu
-- tempat penyimpanan berarti satu cadangan dan satu transaksi untuk revisi
-- dan isi sekaligus. LONGBLOB karena batas per berkas (SYNC_MAX_FILE_MB,
-- default 32 MB) melewati 16 MB milik MEDIUMBLOB - pastikan
-- max_allowed_packet server MySQL lebih besar dari batas itu.
--
-- `revision` mulai 1 dan naik 1 di setiap unggahan sukses. Klien mengirim
-- revisi terakhir yang ia lihat, sehingga unggahan dari perangkat yang
-- ketinggalan ditolak 409 alih-alih menimpa hasil kerja perangkat lain.
--
-- UNIQUE (user_id, name) memakai collation tabel (utf8mb4_unicode_ci), jadi
-- nama tidak peka huruf besar-kecil. Disengaja: "Bracket.ducad" dan
-- "bracket.ducad" akan bertabrakan di sistem berkas macOS/Windows.
--
-- Daftar berkas TIDAK pernah membaca kolom `data`, hanya metadata.
CREATE TABLE IF NOT EXISTS cloud_files (
    id         VARCHAR(36)  NOT NULL PRIMARY KEY,
    user_id    VARCHAR(36)  NOT NULL,
    name       VARCHAR(255) NOT NULL,
    size       BIGINT       NOT NULL,
    sha256     CHAR(64)     NOT NULL,                -- hex huruf kecil
    revision   INT          NOT NULL DEFAULT 1,
    data       LONGBLOB     NOT NULL,
    created_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE KEY uq_cloud_files_user_name (user_id, name),
    INDEX idx_cloud_files_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Preferensi aplikasi yang ikut berpindah perangkat. Satu baris per
-- pengguna, last-write-wins (preferensi tidak sebernilai berkas desain,
-- jadi konfliknya tidak ditanyakan ke pengguna). MEDIUMTEXT berisi JSON,
-- bukan tipe JSON MySQL: isinya hanya disimpan dan dikembalikan utuh, tidak
-- pernah dikueri per field. Handler membatasinya 64 KB.
CREATE TABLE IF NOT EXISTS user_prefs (
    user_id    VARCHAR(36) NOT NULL PRIMARY KEY,
    prefs      MEDIUMTEXT  NOT NULL,
    revision   INT         NOT NULL DEFAULT 1,
    updated_at DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
