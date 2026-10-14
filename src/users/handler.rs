//! Profil pengguna: membaca dan menghapus akun sendiri, serta foto profil
//! yang diunggah pengguna.

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::header;
use axum::response::IntoResponse;

use crate::AppState;
use crate::auth::handler::fetch_user;
use crate::error::{AppError, Result};
use crate::models::{ApiResponse, DeleteAccountResponse, JwtClaims, UserResponse};

/// `GET /api/v1/users/me`
pub async fn get_me(
    claims: JwtClaims,
    State(app): State<AppState>,
) -> Result<Json<ApiResponse<UserResponse>>> {
    let user = fetch_user(&app.db, &claims.sub).await?;
    Ok(Json(ApiResponse::ok(UserResponse::from(user))))
}

/// `DELETE /api/v1/users/me`
///
/// Diwajibkan App Store Review Guideline 5.1.1(v): aplikasi yang
/// memungkinkan pembuatan akun harus memungkinkan penghapusannya dari dalam
/// aplikasi, bukan hanya lewat situs web.
///
/// Satu DELETE cukup: `sessions.user_id` memakai `ON DELETE CASCADE`, jadi
/// seluruh sesi perangkat ikut terhapus dan refresh token yang masih
/// dipegang perangkat lain langsung tidak berlaku.
pub async fn delete_me(
    claims: JwtClaims,
    State(app): State<AppState>,
) -> Result<Json<ApiResponse<DeleteAccountResponse>>> {
    // Dibaca lebih dulu supaya balasannya bisa menyebut alamat yang dihapus,
    // dan supaya token yang hidup lebih lama dari barisnya menjawab 404
    // alih-alih melaporkan sukses atas penghapusan yang tidak terjadi.
    let user = fetch_user(&app.db, &claims.sub).await?;

    let result = sqlx::query("DELETE FROM users WHERE id = ?")
        .bind(&claims.sub)
        .execute(&app.db)
        .await?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound("Akun tidak ditemukan".to_string()));
    }

    tracing::info!(user_id = %claims.sub, "akun dihapus atas permintaan pemiliknya");

    Ok(Json(ApiResponse::ok(DeleteAccountResponse {
        deleted: true,
        email: user.email,
    })))
}

/// Batas ukuran foto profil unggahan. Klien sudah memperkecilnya ke 256 px
/// sebelum mengirim (puluhan KB), jadi 1 MB adalah jaring pengaman.
pub const MAX_AVATAR_BYTES: usize = 1024 * 1024;

/// Mengenali jenis gambar dari isinya, bukan dari header `Content-Type`
/// yang bisa diisi apa saja. Hanya PNG dan JPEG yang diterima: keduanya
/// aman ditampilkan apa adanya, berbeda dengan SVG yang bisa memuat skrip.
pub fn sniff_image(data: &[u8]) -> Option<&'static str> {
    if data.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("image/png")
    } else if data.starts_with(&[0xFF, 0xD8, 0xFF]) {
        Some("image/jpeg")
    } else {
        None
    }
}

/// URL publik foto unggahan. `v` berganti di setiap unggahan sehingga cache
/// klien (dikunci per URL) dan cache HTTP otomatis mengambil foto baru.
pub fn uploaded_avatar_url(base_url: &str, user_id: &str, version: i64) -> String {
    format!("{base_url}/api/v1/users/{user_id}/avatar?v={version}")
}

/// `PUT /api/v1/users/me/avatar`
///
/// Body = bytes gambar PNG/JPEG mentah. Menyimpan foto, mengarahkan
/// `avatar_url` ke foto itu, lalu mengembalikan profil terbaru.
pub async fn put_avatar(
    claims: JwtClaims,
    State(app): State<AppState>,
    body: Bytes,
) -> Result<Json<ApiResponse<UserResponse>>> {
    if body.is_empty() {
        return Err(AppError::BadRequest("Foto profil kosong".to_string()));
    }
    if body.len() > MAX_AVATAR_BYTES {
        return Err(AppError::BadRequest(
            "Foto profil terlalu besar (maksimal 1 MB)".to_string(),
        ));
    }
    let content_type = sniff_image(&body).ok_or_else(|| {
        AppError::BadRequest("Foto profil harus berupa PNG atau JPEG".to_string())
    })?;

    // Memastikan akunnya masih ada sebelum menulis (token bisa hidup lebih
    // lama dari barisnya).
    fetch_user(&app.db, &claims.sub).await?;

    sqlx::query(
        "INSERT INTO user_avatars (user_id, content_type, data) VALUES (?, ?, ?)
         ON DUPLICATE KEY UPDATE
             content_type = VALUES(content_type),
             data = VALUES(data),
             updated_at = CURRENT_TIMESTAMP",
    )
    .bind(&claims.sub)
    .bind(content_type)
    .bind(body.as_ref())
    .execute(&app.db)
    .await?;

    let version = chrono::Utc::now().timestamp_millis();
    let url = uploaded_avatar_url(&app.config.server_base_url, &claims.sub, version);
    sqlx::query("UPDATE users SET avatar_url = ? WHERE id = ?")
        .bind(&url)
        .bind(&claims.sub)
        .execute(&app.db)
        .await?;

    tracing::info!(user_id = %claims.sub, bytes = body.len(), "foto profil diunggah");

    let user = fetch_user(&app.db, &claims.sub).await?;
    Ok(Json(ApiResponse::ok(UserResponse::from(user))))
}

/// `GET /api/v1/users/{id}/avatar`
///
/// Publik (tanpa token), sama seperti foto profil Google/GitHub: klien
/// memuatnya lewat jalur unduh avatar yang sengaja tidak membawa token.
/// Id pengguna adalah UUID v4 acak, jadi URL-nya tidak bisa ditebak.
pub async fn get_avatar(
    State(app): State<AppState>,
    Path(user_id): Path<String>,
) -> Result<impl IntoResponse> {
    let row: Option<(String, Vec<u8>)> =
        sqlx::query_as("SELECT content_type, data FROM user_avatars WHERE user_id = ?")
            .bind(&user_id)
            .fetch_optional(&app.db)
            .await?;
    let (content_type, data) =
        row.ok_or_else(|| AppError::NotFound("Foto profil tidak ditemukan".to_string()))?;

    Ok((
        [
            (header::CONTENT_TYPE, content_type),
            // URL memuat versi (`?v=`), jadi isinya tidak pernah berubah.
            (
                header::CACHE_CONTROL,
                "public, max-age=31536000, immutable".to_string(),
            ),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_string()),
        ],
        data,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sniff_accepts_png_and_jpeg_only() {
        assert_eq!(sniff_image(b"\x89PNG\r\n\x1a\nrest"), Some("image/png"));
        assert_eq!(sniff_image(&[0xFF, 0xD8, 0xFF, 0xE0, 0]), Some("image/jpeg"));
        assert_eq!(sniff_image(b"<svg xmlns=\"http://www.w3.org/2000/svg\"/>"), None);
        assert_eq!(sniff_image(b"GIF89a"), None);
        assert_eq!(sniff_image(b""), None);
    }

    #[test]
    fn uploaded_url_carries_version() {
        assert_eq!(
            uploaded_avatar_url("https://api.ducad.app", "u-1", 42),
            "https://api.ducad.app/api/v1/users/u-1/avatar?v=42"
        );
    }
}
