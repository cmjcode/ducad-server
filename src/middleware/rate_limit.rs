//! Pembatasan laju permintaan per IP untuk endpoint otentikasi (`/api/v1/auth/*`).
//!
//! Server berjalan sebagai proses tunggal di belakang reverse proxy
//! (nginx/Caddy), sehingga penghitung jendela tetap (*fixed window*) di memori
//! sudah cukup menahan banjir permintaan login, tebakan `refresh_token`, atau
//! enumerasi `ticket` tanpa menambah ketergantungan Redis.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::header;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::error::AppError;

/// Batas ukuran tabel IP sebelum penyapuan baris kedaluwarsa dipicu paksa,
/// menjaga pemakaian memori tetap terbatas bila header IP dipalsukan.
const MAX_TRACKED_IPS: usize = 4096;

#[derive(Clone)]
pub struct RateLimiter {
    max_requests: u32,
    window: Duration,
    buckets: Arc<Mutex<HashMap<IpAddr, WindowBucket>>>,
}

struct WindowBucket {
    started_at: Instant,
    count: u32,
}

impl RateLimiter {
    pub fn new(max_requests: u32, window: Duration) -> Self {
        Self {
            max_requests: max_requests.max(1),
            window,
            buckets: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Memeriksa dan menambah hitungan untuk `ip`. Mengembalikan sisa waktu
    /// tunggu jendela aktif bila batas telah terlampaui.
    pub fn check(&self, ip: IpAddr) -> std::result::Result<(), Duration> {
        let now = Instant::now();
        let mut map = match self.buckets.lock() {
            Ok(guard) => guard,
            // Mutex yang keracunan tidak boleh menjatuhkan seluruh proses auth;
            // pulihkan isinya dan lanjutkan.
            Err(poisoned) => poisoned.into_inner(),
        };

        if map.len() >= MAX_TRACKED_IPS {
            map.retain(|_, b| now.saturating_duration_since(b.started_at) < self.window);
        }

        let entry = map.entry(ip).or_insert(WindowBucket {
            started_at: now,
            count: 0,
        });

        let elapsed = now.saturating_duration_since(entry.started_at);
        if elapsed >= self.window {
            entry.started_at = now;
            entry.count = 1;
            return Ok(());
        }

        if entry.count >= self.max_requests {
            let retry_after = self.window.saturating_sub(elapsed);
            return Err(retry_after);
        }

        entry.count += 1;
        Ok(())
    }
}

/// Middleware Axum: menolak permintaan dengan HTTP 429 + `Retry-After` bila
/// kuota IP habis.
pub async fn enforce(
    State(limiter): State<RateLimiter>,
    req: Request,
    next: Next,
) -> Response {
    let ip = extract_client_ip(&req);
    match limiter.check(ip) {
        Ok(()) => next.run(req).await,
        Err(retry_after) => rate_limited_response(retry_after),
    }
}

fn rate_limited_response(retry_after: Duration) -> Response {
    let secs = retry_after.as_secs().max(1);
    let mut resp = AppError::TooManyRequests(format!(
        "Terlalu banyak permintaan otentikasi. Coba lagi dalam {secs} detik."
    ))
    .into_response();
    if let Ok(val) = header::HeaderValue::from_str(&secs.to_string()) {
        resp.headers_mut().insert(header::RETRY_AFTER, val);
    }
    resp
}

/// Mengambil IP klien dari header reverse proxy (`X-Forwarded-For`,
/// `X-Real-Ip`) atau jatuh ke alamat soket langsung.
pub fn extract_client_ip<B>(req: &axum::http::Request<B>) -> IpAddr {
    if let Some(xff) = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
    {
        for part in xff.split(',') {
            if let Ok(ip) = part.trim().parse::<IpAddr>() {
                return ip;
            }
        }
    }

    if let Some(real_ip) = req
        .headers()
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<IpAddr>().ok())
    {
        return real_ip;
    }

    if let Some(ConnectInfo(addr)) = req.extensions().get::<ConnectInfo<SocketAddr>>() {
        return addr.ip();
    }

    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;

    #[test]
    fn izinkan_sampai_batas_lalu_tolak_429() {
        let limiter = RateLimiter::new(3, Duration::from_secs(60));
        let ip_a: IpAddr = "203.0.113.10".parse().expect("ip valid");
        let ip_b: IpAddr = "203.0.113.11".parse().expect("ip valid");

        assert!(limiter.check(ip_a).is_ok());
        assert!(limiter.check(ip_a).is_ok());
        assert!(limiter.check(ip_a).is_ok());
        let retry = limiter.check(ip_a).expect_err("permintaan ke-4 harus ditolak");
        assert!(retry <= Duration::from_secs(60));

        // IP lain tidak ikut terblokir.
        assert!(limiter.check(ip_b).is_ok());

        let resp = rate_limited_response(retry);
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(resp.headers().contains_key(header::RETRY_AFTER));
    }

    #[test]
    fn jendela_baru_membuka_kembali_kuota() {
        let limiter = RateLimiter::new(1, Duration::from_millis(15));
        let ip: IpAddr = "198.51.100.5".parse().expect("ip valid");

        assert!(limiter.check(ip).is_ok());
        assert!(limiter.check(ip).is_err());
        std::thread::sleep(Duration::from_millis(25));
        assert!(limiter.check(ip).is_ok());
    }

    #[test]
    fn ekstraksi_ip_dari_header_proxy_dan_fallback() {
        let req_xff = axum::http::Request::builder()
            .header("x-forwarded-for", "203.0.113.7, 10.0.0.1")
            .body(())
            .expect("request valid");
        assert_eq!(
            extract_client_ip(&req_xff),
            "203.0.113.7".parse::<IpAddr>().expect("ip")
        );

        let req_real = axum::http::Request::builder()
            .header("x-real-ip", "198.51.100.42")
            .body(())
            .expect("request valid");
        assert_eq!(
            extract_client_ip(&req_real),
            "198.51.100.42".parse::<IpAddr>().expect("ip")
        );

        let req_plain = axum::http::Request::builder()
            .body(())
            .expect("request valid");
        assert_eq!(extract_client_ip(&req_plain), IpAddr::V4(Ipv4Addr::LOCALHOST));
    }
}

