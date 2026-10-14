//! Bentuk data: baris basis data, body permintaan, dan payload respons.
//!
//! Bentuk `TokenResponse`/`UserResponse` adalah kontrak dengan
//! `ducad-cloud::types` di sisi klien. Mengganti nama atau menghapus field di
//! sini akan membuat login klien yang sudah terpasang gagal mem-parse token.

use serde::{Deserialize, Serialize};

// ─── Pengguna ───────────────────────────────────────────────────────────────

/// Baris `users`, sebatas kolom yang dibaca kode ini.
///
/// `provider`, `provider_id`, `created_at`, dan `updated_at` memang ada di
/// tabelnya (yang pertama dua membentuk kunci unik akun) tapi tidak dipetakan
/// di sini: tidak ada yang membacanya, dan memetakan kolom yang tak terpakai
/// membuat setiap SELECT harus ikut menyebutnya.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct User {
    pub id: String,
    pub email: String,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub license_tier: String,
}

/// Profil pengguna yang dikirim ke klien.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserResponse {
    pub id: String,
    pub email: String,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub license_tier: String,
}

impl From<User> for UserResponse {
    fn from(u: User) -> Self {
        UserResponse {
            id: u.id,
            email: u.email,
            display_name: u.display_name,
            avatar_url: u.avatar_url,
            license_tier: u.license_tier,
        }
    }
}

/// Balasan `DELETE /api/v1/users/me`. Alamat yang dihapus ikut dikembalikan
/// supaya klien bisa menampilkan konfirmasi sebelum menghapus sesi lokalnya.
#[derive(Debug, Serialize)]
pub struct DeleteAccountResponse {
    pub deleted: bool,
    pub email: String,
}

// ─── Otentikasi ─────────────────────────────────────────────────────────────

/// Klaim JWT token akses DUCAD.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    /// `user_id`
    pub sub: String,
    pub email: String,
    pub iat: usize,
    pub exp: usize,
}

/// Payload token: bentuk yang ditunggu `ducad-cloud::TokenResponse`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    /// Detik sampai `access_token` kedaluwarsa.
    pub expires_in: i64,
    pub user: UserResponse,
}

#[derive(Debug, Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Debug, Deserialize)]
pub struct LogoutRequest {
    pub refresh_token: String,
}

/// Query pada `GET /api/v1/auth/login/{provider}`.
///
/// `client` diterima demi kompatibilitas dengan URL yang dibentuk klien
/// (`client=ducad`) tapi tidak disimpan dan tidak memengaruhi apa pun: server
/// ini hanya melayani DUCAD, jadi halaman suksesnya selalu bermerek DUCAD.
#[derive(Debug, Deserialize)]
pub struct LoginQuery {
    pub ticket: Option<String>,
    pub port: Option<u16>,
    #[allow(dead_code)]
    pub client: Option<String>,
}

/// Callback redirect Google/GitHub.
#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    pub code: String,
    pub state: String,
}

/// Body yang di-POST Apple ke callback (`response_mode=form_post`).
///
/// Semua field kecuali `state` bersifat opsional: pengguna yang membatalkan
/// hanya mengirim `error`.
#[derive(Debug, Deserialize)]
pub struct AppleCallbackForm {
    pub state: String,
    pub code: Option<String>,
    /// JSON `{"name":{"firstName":…,"lastName":…},"email":…}`. Hanya dikirim
    /// pada otorisasi PERTAMA untuk Services ID ini — bila dibuang, tidak ada
    /// kesempatan kedua membaca nama pengguna.
    pub user: Option<String>,
    pub error: Option<String>,
}

// ─── Relai ticket ───────────────────────────────────────────────────────────

/// Baris `oauth_states`: nonce CSRF sekali pakai.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct OAuthStateRow {
    pub redirect_port: Option<i32>,
    pub ticket: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PollTicketRequest {
    pub ticket: String,
}

#[derive(Debug, Serialize)]
pub struct PollTicketResponse {
    /// `pending` | `completed` | `error`
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<TokenResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl PollTicketResponse {
    pub fn pending() -> Self {
        Self {
            status: "pending".to_string(),
            token: None,
            error: None,
        }
    }

    pub fn completed(token: TokenResponse) -> Self {
        Self {
            status: "completed".to_string(),
            token: Some(token),
            error: None,
        }
    }

    pub fn failed(message: String) -> Self {
        Self {
            status: "error".to_string(),
            token: None,
            error: Some(message),
        }
    }
}

// ─── Pembungkus respons ─────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct ApiResponse<T: Serialize> {
    pub success: bool,
    pub data: T,
}

impl<T: Serialize> ApiResponse<T> {
    pub fn ok(data: T) -> Self {
        ApiResponse {
            success: true,
            data,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token() -> TokenResponse {
        TokenResponse {
            access_token: "akses".to_string(),
            refresh_token: "segar".to_string(),
            expires_in: 3600,
            user: UserResponse {
                id: "usr_1".to_string(),
                email: "teknisi@ducad.app".to_string(),
                display_name: Some("Teknisi".to_string()),
                avatar_url: None,
                license_tier: "Pro".to_string(),
            },
        }
    }

    #[test]
    fn poll_pending_tidak_menyertakan_token_atau_error() {
        let json = serde_json::to_string(&ApiResponse::ok(PollTicketResponse::pending()))
            .expect("serialisasi pending");
        assert!(json.contains(r#""status":"pending""#));
        assert!(!json.contains("token"));
        assert!(!json.contains("error"));
    }

    #[test]
    fn poll_completed_membawa_token_di_dalam_data() {
        // Klien membaca `data.token` (lihat ducad-cloud::auth::parse_poll_response).
        let json = serde_json::to_string(&ApiResponse::ok(PollTicketResponse::completed(token())))
            .expect("serialisasi completed");
        let value: serde_json::Value = serde_json::from_str(&json).expect("parse ulang");
        assert_eq!(value["success"], true);
        assert_eq!(value["data"]["status"], "completed");
        assert_eq!(value["data"]["token"]["access_token"], "akses");
        assert_eq!(value["data"]["token"]["user"]["email"], "teknisi@ducad.app");
        assert_eq!(value["data"]["token"]["user"]["license_tier"], "Pro");
    }

    #[test]
    fn poll_error_meneruskan_pesan_ke_klien() {
        let response = PollTicketResponse::failed("Apple belum dikonfigurasi".to_string());
        let json = serde_json::to_string(&ApiResponse::ok(response)).expect("serialisasi error");
        let value: serde_json::Value = serde_json::from_str(&json).expect("parse ulang");
        assert_eq!(value["data"]["status"], "error");
        assert_eq!(value["data"]["error"], "Apple belum dikonfigurasi");
        assert!(value["data"].get("token").is_none());
    }

    #[test]
    fn token_response_bisa_dibaca_ulang_dari_json() {
        // Payload ticket disimpan sebagai JSON di basis data lalu dibaca lagi
        // saat poll; roundtrip-nya harus utuh.
        let json = serde_json::to_string(&token()).expect("serialisasi token");
        let ulang: TokenResponse = serde_json::from_str(&json).expect("deserialisasi token");
        assert_eq!(ulang.user.id, "usr_1");
        assert_eq!(ulang.expires_in, 3600);
    }
}
