//! Tipe galat dan pemetaannya ke respons HTTP.
//!
//! Pesan pada varian yang dibawa ke klien ditulis dalam bahasa Indonesia:
//! aplikasi DUCAD menampilkan teks galat dari server apa adanya di UI
//! (`AuthStatus::Error`), jadi inilah yang dibaca pengguna.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("Galat basis data")]
    Database(#[from] sqlx::Error),

    #[error("Otentikasi diperlukan")]
    Unauthorized,

    #[error("{0}")]
    NotFound(String),

    #[error("{0}")]
    BadRequest(String),

    /// Kegagalan di jalur OAuth yang layak dibaca pengguna, termasuk
    /// "provider belum dikonfigurasi".
    #[error("{0}")]
    OAuth(String),

    #[error("Token tidak valid atau kedaluwarsa")]
    Jwt(#[from] jsonwebtoken::errors::Error),

    #[error("Galat internal server")]
    Internal(#[from] anyhow::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        // Detail teknis masuk ke log, bukan ke respons: pesan galat basis
        // data bisa memuat nama host, nama tabel, dan fragmen kueri.
        let (status, message) = match &self {
            AppError::Database(e) => {
                tracing::error!("galat basis data: {e}");
                (StatusCode::INTERNAL_SERVER_ERROR, self.to_string())
            }
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, self.to_string()),
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, msg.clone()),
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            AppError::OAuth(msg) => {
                tracing::warn!("galat OAuth: {msg}");
                (StatusCode::BAD_GATEWAY, msg.clone())
            }
            AppError::Jwt(e) => {
                tracing::warn!("galat JWT: {e}");
                (StatusCode::UNAUTHORIZED, self.to_string())
            }
            AppError::Internal(e) => {
                tracing::error!("galat internal: {e:#}");
                (StatusCode::INTERNAL_SERVER_ERROR, self.to_string())
            }
        };

        (status, Json(json!({ "success": false, "error": message }))).into_response()
    }
}

pub type Result<T> = std::result::Result<T, AppError>;
