//! Urusan per-provider: URL otorisasi, pertukaran kode, dan pengambilan
//! identitas pengguna.
//!
//! Ketiga provider mengembalikan `ProviderIdentity` yang sama bentuknya,
//! sehingga `handler` tidak perlu tahu provider mana yang sedang dipakai
//! setelah titik ini.

use serde::Deserialize;

use crate::config::Config;
use crate::error::{AppError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provider {
    Google,
    GitHub,
    Apple,
}

impl Provider {
    /// Segmen path `/api/v1/auth/login/{…}` → varian.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "google" => Some(Provider::Google),
            "github" => Some(Provider::GitHub),
            "apple" => Some(Provider::Apple),
            _ => None,
        }
    }

    /// Nilai yang disimpan di kolom `provider`.
    pub fn as_str(self) -> &'static str {
        match self {
            Provider::Google => "google",
            Provider::GitHub => "github",
            Provider::Apple => "apple",
        }
    }

    /// Nama yang pantas muncul di pesan galat untuk pengguna.
    pub fn label(self) -> &'static str {
        match self {
            Provider::Google => "Login dengan Google",
            Provider::GitHub => "Login dengan GitHub",
            Provider::Apple => "Sign in with Apple",
        }
    }
}

/// Identitas pengguna yang seragam dari ketiga provider.
pub struct ProviderIdentity {
    /// Pengenal stabil dari provider: klaim `sub` (Google/Apple) atau id
    /// numerik (GitHub). Inilah kunci akun — bukan email.
    pub provider_id: String,
    pub email: String,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
}

/// Memastikan provider punya kredensial sebelum pengguna dialihkan.
///
/// Tanpa pemeriksaan ini, redirect akan tetap jalan dengan `client_id`
/// kosong dan pengguna mendarat di halaman galat provider yang tidak
/// menjelaskan apa pun. Pesan di sini justru yang dilihat pengguna di UI
/// DUCAD (lewat status ticket `error`), jadi ia menyebut env var yang kurang.
pub fn ensure_configured(config: &Config, provider: Provider) -> Result<()> {
    let kurang = match provider {
        Provider::Google if config.google_client_id.is_empty() => Some("GOOGLE_CLIENT_ID"),
        Provider::GitHub if config.github_client_id.is_empty() => Some("GITHUB_CLIENT_ID"),
        Provider::Apple if config.apple_client_id.is_empty() => {
            Some("APPLE_CLIENT_ID (Services ID)")
        }
        _ => None,
    };

    match kurang {
        Some(env_var) => Err(AppError::OAuth(format!(
            "{} belum dikonfigurasi di server ini: {} belum diset",
            provider.label(),
            env_var
        ))),
        None => Ok(()),
    }
}

/// URL otorisasi provider, lengkap dengan nonce `state`.
pub fn authorize_url(config: &Config, provider: Provider, state: &str) -> String {
    match provider {
        Provider::Google => format!(
            "https://accounts.google.com/o/oauth2/v2/auth\
             ?client_id={}&redirect_uri={}&response_type=code\
             &scope=openid%20email%20profile&state={}&prompt=select_account",
            config.google_client_id,
            urlencode(&config.google_redirect_uri),
            state,
        ),
        Provider::GitHub => format!(
            "https://github.com/login/oauth/authorize\
             ?client_id={}&redirect_uri={}&scope=read:user%20user:email&state={}",
            config.github_client_id,
            urlencode(&config.github_redirect_uri),
            state,
        ),
        // Meminta scope `email` mewajibkan `response_mode=form_post`, jadi
        // Apple mem-POST hasilnya ke callback alih-alih redirect dengan
        // query string seperti dua provider lain.
        Provider::Apple => format!(
            "https://appleid.apple.com/auth/authorize\
             ?client_id={}&redirect_uri={}&response_type=code\
             &scope=name%20email&response_mode=form_post&state={}",
            config.apple_client_id,
            urlencode(&config.apple_redirect_uri),
            state,
        ),
    }
}

/// Menukar kode otorisasi menjadi identitas pengguna.
pub async fn exchange_code(
    http: &reqwest::Client,
    config: &Config,
    provider: Provider,
    code: &str,
) -> Result<ProviderIdentity> {
    match provider {
        Provider::Google => exchange_google(http, config, code).await,
        Provider::GitHub => exchange_github(http, config, code).await,
        Provider::Apple => exchange_apple(http, config, code).await,
    }
}

// ─── Google ─────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct GoogleToken {
    access_token: String,
}

#[derive(Deserialize)]
struct GoogleUserInfo {
    sub: String,
    email: String,
    name: Option<String>,
    picture: Option<String>,
}

async fn exchange_google(
    http: &reqwest::Client,
    config: &Config,
    code: &str,
) -> Result<ProviderIdentity> {
    let token: GoogleToken = http
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            ("client_id", config.google_client_id.as_str()),
            ("client_secret", config.google_client_secret.as_str()),
            ("redirect_uri", config.google_redirect_uri.as_str()),
            ("code", code),
            ("grant_type", "authorization_code"),
        ])
        .send()
        .await
        .map_err(|e| AppError::OAuth(format!("Google tidak bisa dihubungi: {e}")))?
        .json()
        .await
        .map_err(|e| AppError::OAuth(format!("Balasan token Google tidak bisa dibaca: {e}")))?;

    let info: GoogleUserInfo = http
        .get("https://www.googleapis.com/oauth2/v3/userinfo")
        .bearer_auth(&token.access_token)
        .send()
        .await
        .map_err(|e| AppError::OAuth(format!("Profil Google tidak bisa diambil: {e}")))?
        .json()
        .await
        .map_err(|e| AppError::OAuth(format!("Profil Google tidak bisa dibaca: {e}")))?;

    Ok(ProviderIdentity {
        provider_id: info.sub,
        email: info.email,
        display_name: info.name,
        avatar_url: info.picture,
    })
}

// ─── GitHub ─────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct GitHubToken {
    access_token: String,
}

#[derive(Deserialize)]
struct GitHubUser {
    id: i64,
    login: String,
    name: Option<String>,
    avatar_url: Option<String>,
}

#[derive(Deserialize)]
struct GitHubEmail {
    email: String,
    primary: bool,
    verified: bool,
}

async fn exchange_github(
    http: &reqwest::Client,
    config: &Config,
    code: &str,
) -> Result<ProviderIdentity> {
    let token: GitHubToken = http
        .post("https://github.com/login/oauth/access_token")
        .header("Accept", "application/json")
        .form(&[
            ("client_id", config.github_client_id.as_str()),
            ("client_secret", config.github_client_secret.as_str()),
            ("redirect_uri", config.github_redirect_uri.as_str()),
            ("code", code),
        ])
        .send()
        .await
        .map_err(|e| AppError::OAuth(format!("GitHub tidak bisa dihubungi: {e}")))?
        .json()
        .await
        .map_err(|e| AppError::OAuth(format!("Balasan token GitHub tidak bisa dibaca: {e}")))?;

    let user: GitHubUser = http
        .get("https://api.github.com/user")
        .bearer_auth(&token.access_token)
        .send()
        .await
        .map_err(|e| AppError::OAuth(format!("Profil GitHub tidak bisa diambil: {e}")))?
        .json()
        .await
        .map_err(|e| AppError::OAuth(format!("Profil GitHub tidak bisa dibaca: {e}")))?;

    // GitHub tidak menyertakan email di `/user` bila pengguna
    // menyembunyikannya, jadi alamat utama diambil dari endpoint terpisah.
    let emails: Vec<GitHubEmail> = http
        .get("https://api.github.com/user/emails")
        .bearer_auth(&token.access_token)
        .send()
        .await
        .map_err(|e| AppError::OAuth(format!("Email GitHub tidak bisa diambil: {e}")))?
        .json()
        .await
        .map_err(|e| AppError::OAuth(format!("Email GitHub tidak bisa dibaca: {e}")))?;

    let email = pick_github_email(emails).ok_or_else(|| {
        AppError::OAuth(
            "Akun GitHub ini tidak punya alamat email terverifikasi yang bisa dipakai".to_string(),
        )
    })?;

    Ok(ProviderIdentity {
        provider_id: user.id.to_string(),
        email,
        display_name: user.name.or(Some(user.login)),
        avatar_url: user.avatar_url,
    })
}

/// Memilih alamat yang dipakai: utama + terverifikasi, kalau tidak ada yang
/// terverifikasi saja.
///
/// Dipisah agar bisa diuji, dan karena aturannya bukan sekadar "yang
/// pertama": akun dengan beberapa alamat bisa menaruh yang utama di urutan
/// mana pun. Alamat yang belum terverifikasi tidak pernah dipakai — siapa
/// pun bisa menambahkan alamat orang lain ke akun GitHub-nya.
fn pick_github_email(emails: Vec<GitHubEmail>) -> Option<String> {
    if let Some(utama) = emails
        .iter()
        .find(|e| e.primary && e.verified)
        .map(|e| e.email.clone())
    {
        return Some(utama);
    }
    emails.into_iter().find(|e| e.verified).map(|e| e.email)
}

// ─── Sign in with Apple ─────────────────────────────────────────────────────

#[derive(Deserialize)]
struct AppleToken {
    id_token: String,
}

/// Bagian `id_token` Apple yang dipakai.
///
/// `sub` adalah pengenal stabil per Services ID — satu-satunya kunci yang
/// bertahan, karena `email` bisa berupa alamat
/// `@privaterelay.appleid.com` yang berotasi atau dimatikan pengguna.
#[derive(Deserialize)]
struct AppleIdTokenClaims {
    sub: String,
    email: Option<String>,
}

/// Mencetak JWT ES256 berumur pendek sebagai ganti client secret statis.
///
/// Apple membolehkan umur sampai enam bulan, tapi satu jam sudah lebih dari
/// cukup karena token ini dibuat ulang setiap pertukaran kode.
fn apple_client_secret(config: &Config) -> Result<String> {
    use jsonwebtoken::{Algorithm, EncodingKey, Header};

    // Pemeriksaan ini terpisah dari `ensure_configured`: di sana hanya
    // `APPLE_CLIENT_ID` yang dibutuhkan untuk membangun URL otorisasi,
    // sedangkan di sini ketiga nilai plus kunci `.p8` harus lengkap.
    for (nilai, nama) in [
        (&config.apple_team_id, "APPLE_TEAM_ID"),
        (&config.apple_key_id, "APPLE_KEY_ID"),
        (
            &config.apple_private_key,
            "APPLE_PRIVATE_KEY / APPLE_PRIVATE_KEY_PATH",
        ),
    ] {
        if nilai.trim().is_empty() {
            return Err(AppError::OAuth(format!(
                "Sign in with Apple belum lengkap dikonfigurasi di server ini: {nama} belum diset"
            )));
        }
    }

    let now = chrono::Utc::now().timestamp();
    let claims = serde_json::json!({
        "iss": config.apple_team_id,
        "iat": now,
        "exp": now + 3600,
        "aud": "https://appleid.apple.com",
        "sub": config.apple_client_id,
    });

    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(config.apple_key_id.clone());

    let key = EncodingKey::from_ec_pem(config.apple_private_key.as_bytes())
        .map_err(|e| AppError::OAuth(format!("Kunci privat Apple tidak valid: {e}")))?;

    jsonwebtoken::encode(&header, &claims, &key)
        .map_err(|e| AppError::OAuth(format!("Client secret Apple gagal ditandatangani: {e}")))
}

async fn exchange_apple(
    http: &reqwest::Client,
    config: &Config,
    code: &str,
) -> Result<ProviderIdentity> {
    use jsonwebtoken::{Algorithm, DecodingKey, Validation};

    let client_secret = apple_client_secret(config)?;

    let token: AppleToken = http
        .post("https://appleid.apple.com/auth/token")
        .form(&[
            ("client_id", config.apple_client_id.as_str()),
            ("client_secret", client_secret.as_str()),
            ("code", code),
            ("grant_type", "authorization_code"),
            ("redirect_uri", config.apple_redirect_uri.as_str()),
        ])
        .send()
        .await
        .map_err(|e| AppError::OAuth(format!("Apple tidak bisa dihubungi: {e}")))?
        .json()
        .await
        .map_err(|e| AppError::OAuth(format!("Balasan token Apple tidak bisa dibaca: {e}")))?;

    // `id_token` ini datang langsung dari endpoint token Apple lewat TLS,
    // sebagai balasan atas permintaan yang ditandatangani dengan kunci kita
    // sendiri — memverifikasi tanda tangannya tidak menambah jaminan apa pun
    // di titik ini (alasan yang sama membuat jalur Google mempercayai
    // balasannya). Audiens tetap dipaku supaya token yang dicetak untuk
    // Services ID lain ditolak.
    let mut validation = Validation::new(Algorithm::ES256);
    validation.insecure_disable_signature_validation();
    validation.set_audience(&[config.apple_client_id.as_str()]);

    let claims = jsonwebtoken::decode::<AppleIdTokenClaims>(
        &token.id_token,
        &DecodingKey::from_secret(b""),
        &validation,
    )
    .map_err(|e| AppError::OAuth(format!("id_token Apple ditolak: {e}")))?
    .claims;

    // Apple menghilangkan klaim email bila pengguna menyembunyikan
    // alamatnya DAN sudah pernah mengotorisasi Services ID ini. Turunkan
    // alamat dari `sub` alih-alih menggagalkan login — kolom `email` NOT NULL.
    let email = claims
        .email
        .filter(|e| !e.trim().is_empty())
        .unwrap_or_else(|| format!("{}@privaterelay.appleid.com", claims.sub));

    Ok(ProviderIdentity {
        provider_id: claims.sub,
        email,
        // Nama tidak ada di `id_token`; ia datang lewat field `user` pada
        // form POST callback dan hanya pada otorisasi pertama.
        display_name: None,
        // Apple tidak menyediakan avatar.
        avatar_url: None,
    })
}

/// Membaca nama dari field `user` pada callback Apple:
/// `{"name":{"firstName":"Ada","lastName":"Lovelace"},"email":"…"}`.
pub fn parse_apple_user_name(raw: &str) -> Option<String> {
    let parsed: serde_json::Value = serde_json::from_str(raw).ok()?;
    let name = parsed.get("name")?;
    let first = name.get("firstName").and_then(|v| v.as_str()).unwrap_or("");
    let last = name.get("lastName").and_then(|v| v.as_str()).unwrap_or("");
    let full = format!("{first} {last}").trim().to_string();
    if full.is_empty() { None } else { Some(full) }
}

// ─── Percent-encoding ───────────────────────────────────────────────────────

/// Meng-encode redirect URI untuk disisipkan ke query string.
///
/// Bekerja per-byte, bukan per-`char`: `c as u8` akan memotong karakter
/// non-ASCII menjadi byte yang salah (bug yang gampang lolos karena redirect
/// URI biasanya ASCII semua).
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_uji() -> Config {
        Config {
            database_url: "mysql://uji".to_string(),
            server_port: 8430,
            server_base_url: "https://api.ducad.app".to_string(),
            jwt_secret: "rahasia".to_string(),
            jwt_access_expiry_minutes: 60,
            jwt_refresh_expiry_days: 30,
            google_client_id: "google-id".to_string(),
            google_client_secret: "google-secret".to_string(),
            google_redirect_uri: "https://api.ducad.app/api/v1/auth/callback/google".to_string(),
            github_client_id: "github-id".to_string(),
            github_client_secret: "github-secret".to_string(),
            github_redirect_uri: "https://api.ducad.app/api/v1/auth/callback/github".to_string(),
            apple_client_id: "id.ducad.studio.signin".to_string(),
            apple_team_id: "TEAM123456".to_string(),
            apple_key_id: "KEY1234567".to_string(),
            apple_private_key: String::new(),
            apple_redirect_uri: "https://api.ducad.app/api/v1/auth/callback/apple".to_string(),
            allowed_origins: vec!["https://ducad.app".to_string()],
            default_license_tier: "Pro".to_string(),
        }
    }

    #[test]
    fn provider_dikenali_dari_segmen_path() {
        assert_eq!(Provider::parse("apple"), Some(Provider::Apple));
        assert_eq!(Provider::parse("google"), Some(Provider::Google));
        assert_eq!(Provider::parse("github"), Some(Provider::GitHub));
        assert_eq!(
            Provider::parse("Apple"),
            None,
            "harus peka huruf besar/kecil"
        );
        assert_eq!(Provider::parse("facebook"), None);
    }

    #[test]
    fn as_str_cocok_dengan_nilai_kolom() {
        // Nilai ini masuk ke kolom `users.provider` dan dipakai mencocokkan
        // baris `oauth_states`; mengubahnya memutus akun yang sudah ada.
        assert_eq!(Provider::Apple.as_str(), "apple");
        assert_eq!(Provider::Google.as_str(), "google");
        assert_eq!(Provider::GitHub.as_str(), "github");
    }

    #[test]
    fn url_otorisasi_apple_memakai_form_post() {
        let url = authorize_url(&config_uji(), Provider::Apple, "nonce123");
        assert!(url.starts_with("https://appleid.apple.com/auth/authorize"));
        assert!(url.contains("client_id=id.ducad.studio.signin"));
        assert!(url.contains("response_mode=form_post"));
        assert!(url.contains("scope=name%20email"));
        assert!(url.contains("state=nonce123"));
        // Redirect URI harus ter-encode, bukan mentah.
        assert!(url.contains("redirect_uri=https%3A%2F%2Fapi.ducad.app"));
        assert!(!url.contains("redirect_uri=https://"));
    }

    #[test]
    fn url_otorisasi_google_meminta_openid_email_profile() {
        let url = authorize_url(&config_uji(), Provider::Google, "nonce123");
        assert!(url.contains("scope=openid%20email%20profile"));
        assert!(url.contains("response_type=code"));
    }

    #[test]
    fn provider_tanpa_kredensial_ditolak_dengan_nama_env_var() {
        let mut config = config_uji();
        config.apple_client_id = String::new();
        let err = ensure_configured(&config, Provider::Apple).expect_err("harus galat");
        let pesan = err.to_string();
        assert!(pesan.contains("Sign in with Apple"), "pesan: {pesan}");
        assert!(pesan.contains("APPLE_CLIENT_ID"), "pesan: {pesan}");

        // Provider lain tetap jalan meski Apple belum dikonfigurasi.
        assert!(ensure_configured(&config, Provider::Google).is_ok());
    }

    #[test]
    fn client_secret_apple_menolak_konfigurasi_setengah_jadi() {
        // `.p8` kosong: pesan harus menyebut env var kuncinya, bukan panik.
        let err = apple_client_secret(&config_uji()).expect_err("harus galat");
        assert!(
            err.to_string().contains("APPLE_PRIVATE_KEY"),
            "pesan: {err}"
        );
    }

    #[test]
    fn nama_apple_dibaca_dari_field_user() {
        let raw = r#"{"name":{"firstName":"Ada","lastName":"Lovelace"},"email":"a@b.c"}"#;
        assert_eq!(parse_apple_user_name(raw).as_deref(), Some("Ada Lovelace"));
    }

    #[test]
    fn nama_apple_sebagian_atau_kosong() {
        let hanya_depan = r#"{"name":{"firstName":"Ada","lastName":""}}"#;
        assert_eq!(parse_apple_user_name(hanya_depan).as_deref(), Some("Ada"));

        assert!(parse_apple_user_name(r#"{"name":{}}"#).is_none());
        assert!(parse_apple_user_name(r#"{"email":"a@b.c"}"#).is_none());
        assert!(parse_apple_user_name("bukan json").is_none());
    }

    #[test]
    fn email_github_memilih_yang_utama_dan_terverifikasi() {
        let emails = vec![
            GitHubEmail {
                email: "lama@contoh.id".to_string(),
                primary: false,
                verified: true,
            },
            GitHubEmail {
                email: "utama@contoh.id".to_string(),
                primary: true,
                verified: true,
            },
        ];
        assert_eq!(
            pick_github_email(emails).as_deref(),
            Some("utama@contoh.id")
        );
    }

    #[test]
    fn email_github_jatuh_ke_yang_terverifikasi_bila_tak_ada_utama() {
        let emails = vec![
            GitHubEmail {
                email: "belum@contoh.id".to_string(),
                primary: true,
                verified: false,
            },
            GitHubEmail {
                email: "sudah@contoh.id".to_string(),
                primary: false,
                verified: true,
            },
        ];
        assert_eq!(
            pick_github_email(emails).as_deref(),
            Some("sudah@contoh.id")
        );
    }

    #[test]
    fn email_github_tanpa_alamat_terverifikasi_kosong() {
        let emails = vec![GitHubEmail {
            email: "belum@contoh.id".to_string(),
            primary: true,
            verified: false,
        }];
        assert!(pick_github_email(emails).is_none());
    }

    #[test]
    fn urlencode_bekerja_per_byte() {
        assert_eq!(
            urlencode("https://api.ducad.app/x"),
            "https%3A%2F%2Fapi.ducad.app%2Fx"
        );
        assert_eq!(urlencode("a-b_c.d~e"), "a-b_c.d~e");
        // Non-ASCII: dua byte UTF-8, bukan satu byte terpotong.
        assert_eq!(urlencode("é"), "%C3%A9");
    }
}
