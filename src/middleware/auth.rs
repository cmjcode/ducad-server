//! Extractor yang memvalidasi token Bearer.
//!
//! Dengan implementasi ini, handler yang butuh pengguna terotentikasi cukup
//! menuliskan `claims: JwtClaims` sebagai parameter — permintaan tanpa
//! header `Authorization` yang sah tidak akan pernah mencapai handler.

use axum::RequestPartsExt;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use axum_extra::TypedHeader;
use axum_extra::headers::{Authorization, authorization::Bearer};

use crate::AppState;
use crate::auth::jwt;
use crate::error::AppError;
use crate::models::JwtClaims;

impl FromRequestParts<AppState> for JwtClaims {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| AppError::Unauthorized.into_response())?;

        // Galat JWT yang spesifik (kedaluwarsa vs tanda tangan salah) tetap
        // masuk log lewat `AppError::Jwt`, tapi klien hanya menerima satu
        // pesan: perbedaannya tidak bisa ditindaklanjuti pengguna, dan
        // membocorkannya mempermudah menebak-nebak token.
        jwt::verify_access_token(bearer.token(), &state.config.jwt_secret)
            .map_err(|e| e.into_response())
    }
}
