//! `ducad-server` — server otentikasi untuk aplikasi DUCAD.
//!
//! Server ini hanya mengurus identitas: login Google/GitHub/Apple, sesi, dan
//! profil akun. Tidak ada sinkronisasi dokumen — berkas `.ducad` tetap di
//! perangkat pengguna.
//!
//! Instance ini memakai kredensial OAuth milik DUCAD sendiri, sehingga layar
//! consent yang dilihat pengguna menyebut DUCAD. Lihat `README.md` untuk
//! runbook variabel environment dan `docs/adr/0003-identitas-auth-ducad.md`
//! di `ducad-editor` untuk alasan bentuknya.
//!
//! Proses ini TIDAK meneminasi TLS. Ia dirancang berjalan di belakang
//! reverse proxy (nginx/Caddy) yang memegang sertifikat — Sign in with Apple
//! menolak Return URL non-HTTPS, jadi proxy itu bukan opsional di produksi.

mod auth;
mod config;
mod db;
mod error;
mod middleware;
mod models;
mod users;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::http::{HeaderValue, Method, header};
use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post, put};
use tower_http::cors::CorsLayer;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;

use crate::config::Config;

/// Batas waktu satu permintaan ke provider OAuth. Tanpa ini, provider yang
/// menggantung akan menahan koneksi sampai klien menyerah sendiri.
const OAUTH_HTTP_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone)]
pub struct AppState {
    pub db: sqlx::MySqlPool,
    pub config: Arc<Config>,
    pub http: reqwest::Client,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "ducad_server=info,tower_http=info".into()),
        )
        .init();

    let config = Arc::new(Config::from_env()?);

    let pool = db::create_pool(&config.database_url).await?;
    db::run_migrations(&pool).await?;
    db::spawn_sweeper(pool.clone());

    let http = reqwest::Client::builder()
        .user_agent(concat!("ducad-server/", env!("CARGO_PKG_VERSION")))
        .timeout(OAUTH_HTTP_TIMEOUT)
        .build()?;

    let state = AppState {
        db: pool,
        config: Arc::clone(&config),
        http,
    };

    let app = router(&config).with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], config.server_port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("ducad-server mendengarkan di http://{addr}");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

fn router(config: &Config) -> Router<AppState> {
    Router::new()
        .route("/health", get(health))
        // Satu route untuk ketiga provider; segmen path-nya divalidasi di
        // handler (`Provider::parse`).
        .route("/api/v1/auth/login/{provider}", get(auth::handler::login))
        // GET untuk Google/GitHub yang mengalihkan browser; POST untuk Apple,
        // yang memakai `response_mode=form_post` karena scope `email` diminta.
        .route(
            "/api/v1/auth/callback/{provider}",
            get(auth::handler::callback_redirect).post(auth::handler::callback_apple),
        )
        .route("/api/v1/auth/ticket/poll", post(auth::handler::poll_ticket))
        .route("/api/v1/auth/refresh", post(auth::handler::refresh))
        .route("/api/v1/auth/logout", post(auth::handler::logout))
        .route(
            "/api/v1/users/me",
            get(users::handler::get_me).delete(users::handler::delete_me),
        )
        // Batas body sedikit di atas batas handler supaya foto yang terlalu
        // besar dijawab dengan pesan yang jelas, bukan 413 kosong.
        .route(
            "/api/v1/users/me/avatar",
            put(users::handler::put_avatar).layer(DefaultBodyLimit::max(
                users::handler::MAX_AVATAR_BYTES + 64 * 1024,
            )),
        )
        .route("/api/v1/users/{id}/avatar", get(users::handler::get_avatar))
        .layer(cors_layer(config))
        .layer(hsts_layer())
        .layer(TraceLayer::new_for_http())
}

async fn health() -> &'static str {
    "ok"
}

/// CORS mengikuti daftar izin, bukan `Any`.
///
/// Aplikasi DUCAD sendiri tidak terpengaruh — ia bukan browser dan tidak
/// mengirim header `Origin`. Daftar ini untuk halaman web (landing page).
/// Daftar yang kosong berarti tidak ada origin yang diizinkan, bukan semua:
/// salah konfigurasi harus gagal menutup, bukan gagal membuka.
fn cors_layer(config: &Config) -> CorsLayer {
    let origins: Vec<HeaderValue> = config
        .allowed_origins
        .iter()
        .filter_map(|o| match HeaderValue::from_str(o) {
            Ok(value) => Some(value),
            Err(_) => {
                tracing::warn!("origin CORS diabaikan karena tidak valid: {o}");
                None
            }
        })
        .collect();

    CorsLayer::new()
        .allow_origin(origins)
        .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::OPTIONS])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
        .allow_credentials(false)
}

/// HSTS: memberi tahu browser agar hanya bicara HTTPS dengan origin ini.
///
/// Aman dikirim meski proses ini sendiri berbicara HTTP biasa di belakang
/// proxy yang meneminasi TLS — header ini menggambarkan origin publiknya,
/// bukan koneksi internal ke proxy.
fn hsts_layer() -> SetResponseHeaderLayer<HeaderValue> {
    SetResponseHeaderLayer::if_not_present(
        header::STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=63072000; includeSubDomains"),
    )
}

async fn shutdown_signal() {
    // Kegagalan memasang penangan sinyal tidak boleh memanggil `expect`:
    // itu akan mematikan server yang sebetulnya sehat, hanya karena ia tidak
    // bisa mendengarkan Ctrl+C.
    if let Err(e) = tokio::signal::ctrl_c().await {
        tracing::error!("penangan Ctrl+C gagal dipasang: {e}");
        return;
    }
    tracing::info!("sinyal shutdown diterima");
}
