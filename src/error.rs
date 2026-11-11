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

use crate::models::CloudFile;

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

    /// Revisi dasar unggahan tidak cocok dengan server (409). `current`
    /// adalah keadaan berkas di server saat ini, atau `None` bila belum ada —
    /// klien memakainya untuk menawarkan pilihan simpan salinan/timpa.
    #[error("{message}")]
    Conflict {
        message: String,
        current: Option<Box<CloudFile>>,
    },

    /// Satu berkas melebihi batas ukuran (413, `code: file_too_large`).
    #[error("{0}")]
    PayloadTooLarge(String),

    /// Kuota byte atau jumlah berkas akun terlampaui (403,
    /// `code: quota_exceeded`).
    #[error("{0}")]
    QuotaExceeded(String),

    #[error("Galat internal server")]
    Internal(#[from] anyhow::Error),
}

impl AppError {
    /// Kode mesin untuk galat yang perlu dibedakan klien tanpa mem-parse
    /// teks pesan (teksnya bahasa Indonesia dan boleh berubah).
    fn code(&self) -> Option<&'static str> {
        match self {
            AppError::Conflict { .. } => Some("conflict"),
            AppError::PayloadTooLarge(_) => Some("file_too_large"),
            AppError::QuotaExceeded(_) => Some("quota_exceeded"),
            _ => None,
        }
    }

    /// Status dan body JSON galat. Dipisah dari `into_response` supaya
    /// bentuk amplopnya bisa diuji tanpa membaca body HTTP.
    fn status_and_body(&self) -> (StatusCode, serde_json::Value) {
        // Detail teknis masuk ke log, bukan ke respons: pesan galat basis
        // data bisa memuat nama host, nama tabel, dan fragmen kueri.
        let (status, message) = match self {
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
            AppError::Conflict { message, .. } => (StatusCode::CONFLICT, message.clone()),
            AppError::PayloadTooLarge(msg) => (StatusCode::PAYLOAD_TOO_LARGE, msg.clone()),
            AppError::QuotaExceeded(msg) => (StatusCode::FORBIDDEN, msg.clone()),
            AppError::Internal(e) => {
                tracing::error!("galat internal: {e:#}");
                (StatusCode::INTERNAL_SERVER_ERROR, self.to_string())
            }
        };

        let mut body = json!({ "success": false, "error": message });
        if let Some(code) = self.code() {
            body["code"] = json!(code);
        }
        // `current` selalu ada pada 409, bernilai `null` bila berkasnya
        // belum ada di server.
        if let AppError::Conflict { current, .. } = self {
            body["current"] = json!(current);
        }
        (status, body)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, body) = self.status_and_body();
        (status, Json(body)).into_response()
    }
}

pub type Result<T> = std::result::Result<T, AppError>;

#[cfg(test)]
mod tests {
    use super::*;

    fn berkas() -> CloudFile {
        CloudFile {
            id: "f-1".to_string(),
            name: "bracket.ducad".to_string(),
            size: 12,
            sha256: "ab".repeat(32),
            revision: 3,
            updated_at: "2026-10-20T10:00:00Z".to_string(),
        }
    }

    #[test]
    fn galat_biasa_tanpa_code() {
        let (status, body) = AppError::BadRequest("Nama tidak sah".to_string()).status_and_body();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, json!({ "success": false, "error": "Nama tidak sah" }));
    }

    #[test]
    fn konflik_membawa_code_dan_current() {
        let err = AppError::Conflict {
            message: "Berkas sudah berubah".to_string(),
            current: Some(Box::new(berkas())),
        };
        let (status, body) = err.status_and_body();
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["success"], false);
        assert_eq!(body["error"], "Berkas sudah berubah");
        assert_eq!(body["code"], "conflict");
        assert_eq!(body["current"]["revision"], 3);
        assert_eq!(body["current"]["name"], "bracket.ducad");
    }

    #[test]
    fn konflik_tanpa_berkas_current_null() {
        let err = AppError::Conflict {
            message: "Berkas sudah dihapus".to_string(),
            current: None,
        };
        let (status, body) = err.status_and_body();
        assert_eq!(status, StatusCode::CONFLICT);
        // `current` harus ADA dan bernilai null, bukan hilang.
        assert!(body.as_object().is_some_and(|o| o.contains_key("current")));
        assert!(body["current"].is_null());
    }

    #[test]
    fn terlalu_besar_dan_kuota() {
        let (s1, b1) = AppError::PayloadTooLarge("besar".to_string()).status_and_body();
        assert_eq!(s1, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(b1["code"], "file_too_large");
        assert!(b1.get("current").is_none());

        let (s2, b2) = AppError::QuotaExceeded("penuh".to_string()).status_and_body();
        assert_eq!(s2, StatusCode::FORBIDDEN);
        assert_eq!(b2["code"], "quota_exceeded");
        assert_eq!(b2["error"], "penuh");
    }
}
