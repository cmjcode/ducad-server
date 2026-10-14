//! Penerbitan dan verifikasi token akses DUCAD (HS256), serta pembuatan
//! refresh token dan nonce acak.

use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};

use crate::error::{AppError, Result};
use crate::models::JwtClaims;

pub fn generate_access_token(
    user_id: &str,
    email: &str,
    secret: &str,
    expiry_minutes: i64,
) -> Result<String> {
    let now = Utc::now();
    let claims = JwtClaims {
        sub: user_id.to_string(),
        email: email.to_string(),
        iat: now.timestamp() as usize,
        exp: (now + chrono::Duration::minutes(expiry_minutes)).timestamp() as usize,
    };

    let token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )?;
    Ok(token)
}

pub fn verify_access_token(token: &str, secret: &str) -> Result<JwtClaims> {
    let data = decode::<JwtClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::new(Algorithm::HS256),
    )?;
    Ok(data.claims)
}

/// Refresh token: 64 byte dari CSPRNG sistem dalam 128 karakter hex.
///
/// Ini kredensial pembawa berumur panjang, jadi kegagalan CSPRNG
/// MEMBATALKAN penerbitan token alih-alih jatuh ke sumber acak yang lebih
/// lemah — alasan yang sama dengan pembuatan ticket di sisi klien
/// (ADR 0003 §5).
pub fn generate_refresh_token() -> Result<String> {
    Ok(hex::encode(random_bytes::<64>()?))
}

/// Nonce `state` OAuth: 32 byte acak dalam 64 karakter hex, muat di kolom
/// `oauth_states.state`.
pub fn generate_state_nonce() -> Result<String> {
    Ok(hex::encode(random_bytes::<32>()?))
}

fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).map_err(|e| {
        AppError::Internal(anyhow::anyhow!(
            "CSPRNG sistem tidak bisa dibaca, penerbitan token dibatalkan: {e}"
        ))
    })?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "rahasia-uji-yang-cukup-panjang-untuk-hs256";

    #[test]
    fn token_akses_bisa_diverifikasi_kembali() {
        let token = generate_access_token("usr_1", "teknisi@ducad.app", SECRET, 60)
            .expect("penerbitan token");
        let claims = verify_access_token(&token, SECRET).expect("verifikasi token");
        assert_eq!(claims.sub, "usr_1");
        assert_eq!(claims.email, "teknisi@ducad.app");
        assert!(claims.exp > claims.iat);
    }

    #[test]
    fn token_dengan_secret_berbeda_ditolak() {
        let token = generate_access_token("usr_1", "a@b.c", SECRET, 60).expect("penerbitan token");
        assert!(verify_access_token(&token, "secret-lain").is_err());
    }

    #[test]
    fn token_kedaluwarsa_ditolak() {
        // Masa hidup negatif: `exp` sudah lewat saat token dibuat.
        let token = generate_access_token("usr_1", "a@b.c", SECRET, -10).expect("penerbitan token");
        assert!(verify_access_token(&token, SECRET).is_err());
    }

    #[test]
    fn refresh_token_128_hex_dan_tidak_berulang() {
        let a = generate_refresh_token().expect("CSPRNG tersedia di host tes");
        let b = generate_refresh_token().expect("CSPRNG tersedia di host tes");
        assert_eq!(a.len(), 128, "harus muat di kolom VARCHAR(128)");
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }

    #[test]
    fn state_nonce_64_hex_muat_di_kolom() {
        let state = generate_state_nonce().expect("CSPRNG tersedia di host tes");
        assert_eq!(state.len(), 64, "harus muat di kolom VARCHAR(64)");
        assert!(state.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
