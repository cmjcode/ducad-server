//! Handler alur otentikasi: login, callback, relai ticket, refresh, logout.

use axum::Json;
use axum::extract::{Form, Path, Query, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use chrono::{Duration, Utc};
use sqlx::MySqlPool;

use crate::AppState;
use crate::auth::providers::{self, Provider, ProviderIdentity};
use crate::auth::{jwt, success_page};
use crate::error::{AppError, Result};
use crate::models::{
    ApiResponse, AppleCallbackForm, CallbackQuery, LoginQuery, LogoutRequest, OAuthStateRow,
    PollTicketRequest, PollTicketResponse, RefreshRequest, TokenResponse, User, UserResponse,
};

/// Umur nonce `state` dan ticket sejak login dimulai. Cukup panjang untuk
/// mengisi formulir login provider, cukup pendek agar baris yang ditinggalkan
/// tidak menumpuk lama.
const LOGIN_WINDOW_MINUTES: i64 = 10;

/// Umur ticket setelah tokennya siap dijemput. Pendek: klien memolling tiap
/// 1,5 detik, jadi lima menit hanya jaring pengaman bila aplikasi sempat
/// tertahan.
const TICKET_READY_MINUTES: i64 = 5;

// ─── Login ──────────────────────────────────────────────────────────────────

/// `GET /api/v1/auth/login/{provider}?client=ducad&ticket=…[&port=…]`
pub async fn login(
    State(app): State<AppState>,
    Path(provider): Path<String>,
    Query(query): Query<LoginQuery>,
) -> Result<Redirect> {
    let provider = parse_provider(&provider)?;

    // Konfigurasi yang belum lengkap harus muncul sebagai pesan jelas di UI
    // aplikasi, bukan sebagai login yang menggantung sampai timeout. Karena
    // itu galatnya dituliskan ke ticket lebih dulu — klien sedang memolling
    // dan akan langsung membacanya.
    if let Err(e) = providers::ensure_configured(&app.config, provider) {
        if let Some(ticket) = &query.ticket {
            mark_ticket_error(&app.db, ticket, &e.to_string()).await;
        }
        return Err(e);
    }

    let state_token = jwt::generate_state_nonce()?;
    let expires_at = Utc::now() + Duration::minutes(LOGIN_WINDOW_MINUTES);

    sqlx::query(
        "INSERT INTO oauth_states (state, provider, redirect_port, ticket, expires_at)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&state_token)
    .bind(provider.as_str())
    .bind(query.port.map(i32::from))
    .bind(&query.ticket)
    .bind(expires_at)
    .execute(&app.db)
    .await?;

    if let Some(ticket) = &query.ticket {
        sqlx::query(
            "INSERT INTO auth_tickets (ticket, status, payload, expires_at)
             VALUES (?, 'pending', NULL, ?)
             ON DUPLICATE KEY UPDATE status = 'pending', payload = NULL,
                                     expires_at = VALUES(expires_at)",
        )
        .bind(ticket)
        .bind(expires_at)
        .execute(&app.db)
        .await?;
    }

    tracing::info!(provider = provider.as_str(), "login dimulai");
    Ok(Redirect::temporary(&providers::authorize_url(
        &app.config,
        provider,
        &state_token,
    )))
}

// ─── Callback ───────────────────────────────────────────────────────────────

/// `GET /api/v1/auth/callback/{provider}` — Google dan GitHub, yang
/// mengalihkan browser kembali dengan `code` dan `state` di query string.
pub async fn callback_redirect(
    State(app): State<AppState>,
    Path(provider): Path<String>,
    Query(query): Query<CallbackQuery>,
) -> Result<Response> {
    let provider = parse_provider(&provider)?;
    if provider == Provider::Apple {
        // Apple mem-POST callback-nya; permintaan GET ke path ini berarti
        // ada yang salah konfigurasi, bukan pengguna yang sedang login.
        return Err(AppError::BadRequest(
            "Callback Apple dikirim lewat POST, bukan GET".to_string(),
        ));
    }

    finish_login(&app, provider, &query.code, &query.state, None).await
}

/// `POST /api/v1/auth/callback/apple`
///
/// Apple mem-POST ke sini alih-alih mengalihkan, karena server meminta scope
/// `email`. Field `user` membawa nama pengguna dan **hanya dikirim pada
/// otorisasi pertama** — kalau dibuang di sini, tidak ada kesempatan kedua.
pub async fn callback_apple(
    State(app): State<AppState>,
    Path(provider): Path<String>,
    Form(form): Form<AppleCallbackForm>,
) -> Result<Response> {
    let provider = parse_provider(&provider)?;
    if provider != Provider::Apple {
        return Err(AppError::BadRequest(format!(
            "Callback {} tidak menerima POST",
            provider.as_str()
        )));
    }

    if let Some(pesan) = form.error.as_deref().filter(|e| !e.trim().is_empty()) {
        // Pengguna membatalkan, atau Apple menolak permintaannya. Beri tahu
        // aplikasi lewat ticket supaya tombol login tidak menggantung.
        let galat = AppError::OAuth(format!("Sign in with Apple gagal: {pesan}"));
        if let Some(ticket) = ticket_of_state(&app.db, Provider::Apple, &form.state).await {
            mark_ticket_error(&app.db, &ticket, &galat.to_string()).await;
        }
        return Err(galat);
    }

    let code = form
        .code
        .clone()
        .filter(|c| !c.trim().is_empty())
        .ok_or_else(|| AppError::BadRequest("Callback Apple tidak membawa `code`".to_string()))?;

    let name_hint = form
        .user
        .as_deref()
        .and_then(providers::parse_apple_user_name);

    finish_login(&app, Provider::Apple, &code, &form.state, name_hint).await
}

/// Bagian callback yang sama untuk ketiga provider.
async fn finish_login(
    app: &AppState,
    provider: Provider,
    code: &str,
    state_token: &str,
    name_hint: Option<String>,
) -> Result<Response> {
    let state_row = consume_state(&app.db, provider, state_token).await?;

    match issue_token(app, provider, code, name_hint).await {
        Ok(token) => {
            if let Some(ticket) = &state_row.ticket {
                store_ready_ticket(&app.db, ticket, &token).await?;
            }
            Ok(render_callback_response(&state_row, &token))
        }
        Err(e) => {
            // Kegagalan setelah pengguna kembali dari provider (kode
            // kedaluwarsa, provider tidak bisa dihubungi) juga harus sampai
            // ke UI; tanpa ini aplikasi hanya diam sampai timeout 3 menit.
            if let Some(ticket) = &state_row.ticket {
                mark_ticket_error(&app.db, ticket, &e.to_string()).await;
            }
            Err(e)
        }
    }
}

/// Menukar kode, meng-upsert pengguna, dan menerbitkan token DUCAD.
async fn issue_token(
    app: &AppState,
    provider: Provider,
    code: &str,
    name_hint: Option<String>,
) -> Result<TokenResponse> {
    let mut identity = providers::exchange_code(&app.http, &app.config, provider, code).await?;

    // Apple hanya mengirim nama sekali, lewat form POST; pakai itu bila
    // pertukaran kode tidak memberi nama apa pun.
    if identity.display_name.is_none() {
        identity.display_name = name_hint;
    }

    let user = upsert_user(
        &app.db,
        provider,
        &identity,
        &app.config.default_license_tier,
    )
    .await?;

    let access_token = jwt::generate_access_token(
        &user.id,
        &user.email,
        &app.config.jwt_secret,
        app.config.jwt_access_expiry_minutes,
    )?;
    let refresh_token = jwt::generate_refresh_token()?;

    sqlx::query(
        "INSERT INTO sessions (id, user_id, refresh_token, expires_at) VALUES (?, ?, ?, ?)",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(&user.id)
    .bind(&refresh_token)
    .bind(Utc::now() + Duration::days(app.config.jwt_refresh_expiry_days))
    .execute(&app.db)
    .await?;

    tracing::info!(
        provider = provider.as_str(),
        user_id = %user.id,
        "login berhasil"
    );

    Ok(TokenResponse {
        access_token,
        refresh_token,
        expires_in: app.config.jwt_access_expiry_minutes * 60,
        user: UserResponse::from(user),
    })
}

/// Halaman sukses untuk browser, atau JSON bila login tidak datang dari
/// aplikasi (tanpa ticket maupun port loopback).
fn render_callback_response(state_row: &OAuthStateRow, token: &TokenResponse) -> Response {
    if state_row.ticket.is_none() && state_row.redirect_port.is_none() {
        return Json(ApiResponse::ok(token)).into_response();
    }

    // Port di basis data bertipe INT; nilai di luar rentang port berarti
    // baris yang rusak, jadi jalur loopback-nya dilewati saja.
    let port = state_row
        .redirect_port
        .and_then(|p| u16::try_from(p).ok())
        .filter(|p| *p != 0);

    let token_json = serde_json::to_string(token).unwrap_or_else(|e| {
        // Serialisasi TokenResponse tidak bisa gagal (tidak ada map dengan
        // kunci non-string), tapi jangan pernah menyisipkan teks galat ke
        // dalam blok skrip: kirim objek kosong agar jalur loopback mati dan
        // klien tetap mendapat tokennya lewat polling.
        tracing::error!("serialisasi token untuk halaman sukses gagal: {e}");
        "{}".to_string()
    });

    Html(success_page::render(port, &token_json)).into_response()
}

// ─── Relai ticket ───────────────────────────────────────────────────────────

/// `POST /api/v1/auth/ticket/poll`
pub async fn poll_ticket(
    State(app): State<AppState>,
    Json(req): Json<PollTicketRequest>,
) -> Result<Json<ApiResponse<PollTicketResponse>>> {
    let row: Option<(String, Option<String>)> = sqlx::query_as(
        "SELECT status, payload FROM auth_tickets WHERE ticket = ? AND expires_at > NOW()",
    )
    .bind(&req.ticket)
    .fetch_optional(&app.db)
    .await?;

    // Ticket yang tidak dikenal atau sudah kedaluwarsa dijawab `pending`,
    // bukan `error`: klien memolling sebelum pengguna selesai login, dan
    // baris ticket bisa saja belum terbentuk saat poll pertama datang.
    let Some((status, payload)) = row else {
        return Ok(Json(ApiResponse::ok(PollTicketResponse::pending())));
    };

    match status.as_str() {
        "error" => {
            consume_ticket(&app.db, &req.ticket).await;
            let pesan = payload.unwrap_or_else(|| "Otentikasi gagal di server".to_string());
            Ok(Json(ApiResponse::ok(PollTicketResponse::failed(pesan))))
        }
        "ready" => {
            // Payload yang hilang atau tidak bisa dibaca dibiarkan sebagai
            // `pending` alih-alih galat: klien akan terus memolling sampai
            // ticket kedaluwarsa, dan tidak ada yang bisa ditindaklanjuti
            // pengguna dari pesan "payload rusak".
            let Some(token) = payload
                .as_deref()
                .and_then(|p| serde_json::from_str::<TokenResponse>(p).ok())
            else {
                tracing::warn!(ticket = %req.ticket, "ticket 'ready' tanpa payload yang bisa dibaca");
                return Ok(Json(ApiResponse::ok(PollTicketResponse::pending())));
            };

            consume_ticket(&app.db, &req.ticket).await;
            Ok(Json(ApiResponse::ok(PollTicketResponse::completed(token))))
        }
        _ => Ok(Json(ApiResponse::ok(PollTicketResponse::pending()))),
    }
}

// ─── Refresh & logout ───────────────────────────────────────────────────────

/// `POST /api/v1/auth/refresh`
///
/// Refresh token diputar setiap kali dipakai: token lama langsung tidak
/// berlaku, sehingga satu token yang bocor hanya bisa dipakai sekali.
pub async fn refresh(
    State(app): State<AppState>,
    Json(req): Json<RefreshRequest>,
) -> Result<Json<ApiResponse<TokenResponse>>> {
    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT id, user_id FROM sessions WHERE refresh_token = ? AND expires_at > NOW()",
    )
    .bind(&req.refresh_token)
    .fetch_optional(&app.db)
    .await?;

    let (session_id, user_id) = row.ok_or(AppError::Unauthorized)?;
    let user = fetch_user(&app.db, &user_id).await?;

    let new_refresh = jwt::generate_refresh_token()?;
    sqlx::query("UPDATE sessions SET refresh_token = ?, expires_at = ? WHERE id = ?")
        .bind(&new_refresh)
        .bind(Utc::now() + Duration::days(app.config.jwt_refresh_expiry_days))
        .bind(&session_id)
        .execute(&app.db)
        .await?;

    let access_token = jwt::generate_access_token(
        &user.id,
        &user.email,
        &app.config.jwt_secret,
        app.config.jwt_access_expiry_minutes,
    )?;

    Ok(Json(ApiResponse::ok(TokenResponse {
        access_token,
        refresh_token: new_refresh,
        expires_in: app.config.jwt_access_expiry_minutes * 60,
        user: UserResponse::from(user),
    })))
}

/// `POST /api/v1/auth/logout`
///
/// Selalu menjawab sukses: refresh token yang tidak ditemukan berarti sesi
/// itu memang sudah tidak ada, dan membedakan keduanya hanya memberi tahu
/// penebak token mana yang pernah sah.
pub async fn logout(
    State(app): State<AppState>,
    Json(req): Json<LogoutRequest>,
) -> Result<Json<serde_json::Value>> {
    sqlx::query("DELETE FROM sessions WHERE refresh_token = ?")
        .bind(&req.refresh_token)
        .execute(&app.db)
        .await?;

    Ok(Json(serde_json::json!({ "success": true })))
}

// ─── Pembantu ───────────────────────────────────────────────────────────────

fn parse_provider(raw: &str) -> Result<Provider> {
    Provider::parse(raw)
        .ok_or_else(|| AppError::BadRequest(format!("Provider login tidak dikenal: {raw}")))
}

/// Mengambil baris `state` sekaligus menghapusnya, sehingga satu callback
/// tidak bisa diputar ulang.
async fn consume_state(
    pool: &MySqlPool,
    provider: Provider,
    state_token: &str,
) -> Result<OAuthStateRow> {
    let row: Option<OAuthStateRow> = sqlx::query_as(
        "SELECT redirect_port, ticket FROM oauth_states
         WHERE state = ? AND provider = ? AND expires_at > NOW()",
    )
    .bind(state_token)
    .bind(provider.as_str())
    .fetch_optional(pool)
    .await?;

    let row = row.ok_or_else(|| {
        AppError::BadRequest("Sesi login tidak valid atau sudah kedaluwarsa".to_string())
    })?;

    sqlx::query("DELETE FROM oauth_states WHERE state = ?")
        .bind(state_token)
        .execute(pool)
        .await?;

    Ok(row)
}

/// Membaca ticket milik satu `state` tanpa menghapus barisnya — dipakai di
/// jalur galat, di mana `consume_state` belum (atau tidak akan) dipanggil.
async fn ticket_of_state(
    pool: &MySqlPool,
    provider: Provider,
    state_token: &str,
) -> Option<String> {
    sqlx::query_as::<_, (Option<String>,)>(
        "SELECT ticket FROM oauth_states WHERE state = ? AND provider = ?",
    )
    .bind(state_token)
    .bind(provider.as_str())
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
    .and_then(|(ticket,)| ticket)
}

async fn store_ready_ticket(pool: &MySqlPool, ticket: &str, token: &TokenResponse) -> Result<()> {
    let payload = serde_json::to_string(token)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("serialisasi token gagal: {e}")))?;

    sqlx::query(
        "INSERT INTO auth_tickets (ticket, status, payload, expires_at)
         VALUES (?, 'ready', ?, ?)
         ON DUPLICATE KEY UPDATE status = 'ready', payload = VALUES(payload),
                                 expires_at = VALUES(expires_at)",
    )
    .bind(ticket)
    .bind(&payload)
    .bind(Utc::now() + Duration::minutes(TICKET_READY_MINUTES))
    .execute(pool)
    .await?;

    Ok(())
}

/// Menuliskan pesan galat ke ticket. Best-effort: bila penulisannya sendiri
/// gagal, klien jatuh ke timeout-nya dan galat aslinya tetap dilaporkan.
async fn mark_ticket_error(pool: &MySqlPool, ticket: &str, message: &str) {
    let result = sqlx::query(
        "INSERT INTO auth_tickets (ticket, status, payload, expires_at)
         VALUES (?, 'error', ?, ?)
         ON DUPLICATE KEY UPDATE status = 'error', payload = VALUES(payload),
                                 expires_at = VALUES(expires_at)",
    )
    .bind(ticket)
    .bind(message)
    .bind(Utc::now() + Duration::minutes(TICKET_READY_MINUTES))
    .execute(pool)
    .await;

    if let Err(e) = result {
        tracing::warn!("gagal menuliskan galat ke ticket: {e}");
    }
}

/// Menandai ticket terpakai dan membuang payload-nya, supaya token tidak
/// bisa dijemput dua kali dan tidak tertinggal di basis data.
async fn consume_ticket(pool: &MySqlPool, ticket: &str) {
    let result =
        sqlx::query("UPDATE auth_tickets SET status = 'consumed', payload = NULL WHERE ticket = ?")
            .bind(ticket)
            .execute(pool)
            .await;

    if let Err(e) = result {
        tracing::warn!("gagal menandai ticket terpakai: {e}");
    }
}

/// Menyisipkan atau memperbarui pengguna, dikunci ke `(provider, provider_id)`.
///
/// Foto yang diunggah pengguna sendiri (`user_avatars`) selalu menang atas
/// foto provider, jadi `avatar_url` tidak disentuh selama barisnya ada.
///
/// `COALESCE` pada nama dan avatar menjaga nilai yang sudah tersimpan saat
/// provider tidak mengirim apa pun — penting untuk Apple, yang hanya
/// mengirim nama pada otorisasi pertama. `license_tier` sengaja tidak ikut
/// diperbarui agar tier yang sudah dinaikkan tidak kembali ke default setiap
/// kali pengguna login.
async fn upsert_user(
    pool: &MySqlPool,
    provider: Provider,
    identity: &ProviderIdentity,
    default_license_tier: &str,
) -> Result<User> {
    sqlx::query(
        "INSERT INTO users (id, provider, provider_id, email, display_name, avatar_url, license_tier)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE
             email = VALUES(email),
             display_name = COALESCE(VALUES(display_name), display_name),
             avatar_url = IF(
                 EXISTS (SELECT 1 FROM user_avatars ua WHERE ua.user_id = users.id),
                 avatar_url,
                 COALESCE(VALUES(avatar_url), avatar_url)
             ),
             updated_at = CURRENT_TIMESTAMP",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(provider.as_str())
    .bind(&identity.provider_id)
    .bind(&identity.email)
    .bind(&identity.display_name)
    .bind(&identity.avatar_url)
    .bind(default_license_tier)
    .execute(pool)
    .await?;

    sqlx::query_as(
        "SELECT id, email, display_name, avatar_url, license_tier
         FROM users WHERE provider = ? AND provider_id = ?",
    )
    .bind(provider.as_str())
    .bind(&identity.provider_id)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| {
        AppError::Internal(anyhow::anyhow!(
            "baris pengguna hilang tepat setelah upsert"
        ))
    })
}

pub async fn fetch_user(pool: &MySqlPool, user_id: &str) -> Result<User> {
    sqlx::query_as(
        "SELECT id, email, display_name, avatar_url, license_tier
         FROM users WHERE id = ?",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| AppError::NotFound("Akun tidak ditemukan".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token_uji() -> TokenResponse {
        TokenResponse {
            access_token: "akses".to_string(),
            refresh_token: "segar".to_string(),
            expires_in: 3600,
            user: UserResponse {
                id: "usr_1".to_string(),
                email: "teknisi@ducad.app".to_string(),
                display_name: None,
                avatar_url: None,
                license_tier: "Pro".to_string(),
            },
        }
    }

    #[test]
    fn provider_tak_dikenal_jadi_bad_request() {
        let err = parse_provider("facebook").expect_err("harus galat");
        assert!(matches!(err, AppError::BadRequest(_)));
        assert!(err.to_string().contains("facebook"));
    }

    #[test]
    fn tanpa_ticket_dan_port_callback_menjawab_json() {
        // Jalur ini dipakai saat URL login dibuka manual (mis. verifikasi
        // dengan curl), bukan oleh aplikasi.
        let row = OAuthStateRow {
            redirect_port: None,
            ticket: None,
        };
        let response = render_callback_response(&row, &token_uji());
        let content_type = response
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        assert!(
            content_type.contains("application/json"),
            "dapat: {content_type}"
        );
    }

    #[test]
    fn dengan_ticket_callback_menjawab_halaman_html() {
        let row = OAuthStateRow {
            redirect_port: None,
            ticket: Some("abc123".to_string()),
        };
        let response = render_callback_response(&row, &token_uji());
        let content_type = response
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        assert!(content_type.contains("text/html"), "dapat: {content_type}");
    }

    #[test]
    fn port_di_luar_rentang_tidak_mematikan_callback() {
        // Baris rusak: INT bisa memuat nilai yang bukan port yang sah.
        let row = OAuthStateRow {
            redirect_port: Some(999_999),
            ticket: Some("abc".to_string()),
        };
        let response = render_callback_response(&row, &token_uji());
        assert_eq!(response.status(), axum::http::StatusCode::OK);
    }
}
