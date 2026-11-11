//! Konfigurasi server, seluruhnya dari environment variable.

use std::env;

use crate::tier::{SyncLimits, Tier};

#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub server_port: u16,
    /// URL publik server, tanpa garis miring di ujung. Dipakai menurunkan
    /// redirect URI ketiga provider bila tidak diset eksplisit.
    pub server_base_url: String,

    pub jwt_secret: String,
    pub jwt_access_expiry_minutes: i64,
    pub jwt_refresh_expiry_days: i64,

    pub google_client_id: String,
    pub google_client_secret: String,
    pub google_redirect_uri: String,

    pub github_client_id: String,
    pub github_client_secret: String,
    pub github_redirect_uri: String,

    /// Sign in with Apple. Tidak ada secret statis seperti Google/GitHub:
    /// "client secret" adalah JWT ES256 yang dicetak per permintaan dari
    /// team id, key id, dan kunci privat `.p8` (lihat `auth::providers`).
    ///
    /// `apple_client_id` adalah **Services ID**, BUKAN bundle ID aplikasi —
    /// ini kesalahan konfigurasi yang paling sering terjadi.
    pub apple_client_id: String,
    pub apple_team_id: String,
    pub apple_key_id: String,
    /// Isi PEM PKCS#8 dari berkas AuthKey `.p8`.
    pub apple_private_key: String,
    pub apple_redirect_uri: String,

    /// Origin yang diizinkan CORS. Aplikasi desktop/iPad tidak mengirim
    /// header `Origin` sama sekali, jadi ini hanya relevan untuk halaman web
    /// (landing page) yang memanggil server.
    pub allowed_origins: Vec<String>,

    /// Tier lisensi yang diberikan ke akun baru, sudah dinormalkan ke bentuk
    /// kanonik (`Free`/`Pro`). Nilai ini dikirim apa adanya ke klien dan
    /// ditampilkan di drawer akun ("Ducad {tier} Tier").
    pub default_license_tier: String,

    /// Kuota sinkronisasi berkas per tier (env `SYNC_*`).
    pub sync: SyncLimits,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let server_base_url =
            env::var("SERVER_BASE_URL").unwrap_or_else(|_| "http://localhost:8430".to_string());
        let base = server_base_url.trim_end_matches('/').to_string();

        Ok(Config {
            database_url: required_env("DATABASE_URL")?,
            server_port: parse_env("SERVER_PORT", 8430),
            jwt_secret: required_env("JWT_SECRET")?,
            jwt_access_expiry_minutes: parse_env("JWT_ACCESS_EXPIRY_MINUTES", 60),
            jwt_refresh_expiry_days: parse_env("JWT_REFRESH_EXPIRY_DAYS", 30),

            google_client_id: optional_env("GOOGLE_CLIENT_ID"),
            google_client_secret: optional_env("GOOGLE_CLIENT_SECRET"),
            google_redirect_uri: redirect_uri("GOOGLE_REDIRECT_URI", &base, "google"),

            github_client_id: optional_env("GITHUB_CLIENT_ID"),
            github_client_secret: optional_env("GITHUB_CLIENT_SECRET"),
            github_redirect_uri: redirect_uri("GITHUB_REDIRECT_URI", &base, "github"),

            apple_client_id: optional_env("APPLE_CLIENT_ID"),
            apple_team_id: optional_env("APPLE_TEAM_ID"),
            apple_key_id: optional_env("APPLE_KEY_ID"),
            apple_private_key: read_apple_private_key()?,
            apple_redirect_uri: redirect_uri("APPLE_REDIRECT_URI", &base, "apple"),

            allowed_origins: env::var("ALLOWED_ORIGINS")
                .unwrap_or_else(|_| "https://ducad.app".to_string())
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),

            default_license_tier: default_license_tier(
                env::var("DEFAULT_LICENSE_TIER").ok().as_deref(),
            )?
            .as_str()
            .to_string(),

            sync: sync_limits_from_env(),

            server_base_url: base,
        })
    }
}

impl Config {
    /// Hanya `DATABASE_URL` — untuk subcommand admin, yang tidak butuh
    /// `JWT_SECRET` maupun kredensial provider.
    pub fn database_url_from_env() -> anyhow::Result<String> {
        required_env("DATABASE_URL")
    }
}

/// Tier akun baru. Kosong/tidak diset → `Free`. Nilai yang tidak dikenal
/// adalah galat fatal, BUKAN jatuh ke default seperti `parse_env`: tier yang
/// salah ketik akan tersimpan permanen di setiap akun baru, jadi lebih baik
/// server menolak start.
fn default_license_tier(value: Option<&str>) -> anyhow::Result<Tier> {
    match value.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(Tier::Free),
        Some(v) => Tier::parse(v).ok_or_else(|| {
            anyhow::anyhow!("DEFAULT_LICENSE_TIER tidak dikenal: '{v}' (pilih Free atau Pro)")
        }),
    }
}

fn sync_limits_from_env() -> SyncLimits {
    let d = SyncLimits::default();
    SyncLimits {
        quota_free_bytes: parse_env_mb("SYNC_QUOTA_FREE_MB", d.quota_free_bytes),
        quota_pro_bytes: parse_env_mb("SYNC_QUOTA_PRO_MB", d.quota_pro_bytes),
        max_file_bytes: parse_env_mb("SYNC_MAX_FILE_MB", d.max_file_bytes),
        max_files_free: parse_env("SYNC_MAX_FILES_FREE", d.max_files_free),
        max_files_pro: parse_env("SYNC_MAX_FILES_PRO", d.max_files_pro),
    }
}

/// Env var dalam MB (biner) menjadi byte; tidak di-parse → default (byte).
fn parse_env_mb(key: &str, default_bytes: u64) -> u64 {
    env::var(key)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(|mb| mb.saturating_mul(crate::tier::MIB))
        .unwrap_or(default_bytes)
}

/// Redirect URI provider: nilai eksplisit bila ada, kalau tidak diturunkan
/// dari `SERVER_BASE_URL`. Env var yang diset tapi kosong diperlakukan sama
/// dengan tidak diset — itu bentuk yang dihasilkan `docker-compose` untuk
/// variabel yang belum diisi di `.env`.
fn redirect_uri(key: &str, base: &str, provider: &str) -> String {
    env::var(key)
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| format!("{base}/api/v1/auth/callback/{provider}"))
}

/// Kunci `.p8` Apple: berkas yang di-mount (disarankan) atau PEM inline.
///
/// Berkas yang tidak terbaca adalah galat fatal, bukan konfigurasi kosong —
/// path yang salah tulis harus terlihat saat start, bukan berubah menjadi
/// "Apple belum dikonfigurasi" yang menyesatkan saat pengguna mencoba login.
fn read_apple_private_key() -> anyhow::Result<String> {
    if let Ok(pem) = env::var("APPLE_PRIVATE_KEY")
        && !pem.trim().is_empty()
    {
        // Platform yang hanya punya env secret satu baris mengirim "\n"
        // literal; kembalikan menjadi baris baru sungguhan.
        return Ok(pem.replace("\\n", "\n"));
    }

    match env::var("APPLE_PRIVATE_KEY_PATH") {
        Ok(path) if !path.trim().is_empty() => {
            let p = path.trim();
            std::fs::read_to_string(p).map_err(|e| {
                anyhow::anyhow!("Tidak bisa membaca APPLE_PRIVATE_KEY_PATH di '{p}': {e}")
            })
        }
        _ => Ok(String::new()),
    }
}

fn required_env(key: &str) -> anyhow::Result<String> {
    env::var(key)
        .ok()
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("Environment variable wajib belum diset: {key}"))
}

fn optional_env(key: &str) -> String {
    env::var(key).unwrap_or_default().trim().to_string()
}

/// Nilai yang tidak bisa di-parse jatuh ke default alih-alih mematikan
/// server: satu salah ketik pada masa kedaluwarsa token tidak sepadan dengan
/// layanan yang tidak mau start.
fn parse_env<T: std::str::FromStr>(key: &str, default: T) -> T {
    env::var(key)
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirect_uri_diturunkan_dari_base_url() {
        // Env var tidak diset: pakai base URL.
        let uri = redirect_uri(
            "URI_YANG_TIDAK_PERNAH_DISET_DI_TES",
            "https://api.ducad.app",
            "apple",
        );
        assert_eq!(uri, "https://api.ducad.app/api/v1/auth/callback/apple");
    }

    #[test]
    fn tier_default_akun_baru_adalah_free() {
        assert_eq!(default_license_tier(None).ok(), Some(Tier::Free));
        assert_eq!(default_license_tier(Some("  ")).ok(), Some(Tier::Free));
    }

    #[test]
    fn tier_default_dinormalkan_dan_divalidasi() {
        assert_eq!(default_license_tier(Some("pro")).ok(), Some(Tier::Pro));
        assert_eq!(default_license_tier(Some(" FREE ")).ok(), Some(Tier::Free));
        assert!(default_license_tier(Some("Platinum")).is_err());
    }

    #[test]
    fn kuota_mb_tidak_diset_memakai_default() {
        assert_eq!(parse_env_mb("SYNC_TIDAK_PERNAH_DISET_DI_TES", 7), 7);
    }

    #[test]
    fn redirect_uri_google_dan_github_berbeda_path() {
        let g = redirect_uri("TIDAK_DISET_G", "https://api.ducad.app", "google");
        let h = redirect_uri("TIDAK_DISET_H", "https://api.ducad.app", "github");
        assert!(g.ends_with("/google"));
        assert!(h.ends_with("/github"));
        assert_ne!(g, h);
    }
}
