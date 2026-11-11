//! Endpoint `/api/v1/sync/*`: daftar, unduh, unggah, hapus berkas awan, dan
//! preferensi pengguna. Bentuk permintaan/balasan adalah kontrak dengan
//! klien DUCAD (lihat `models::CloudFile` dan kawan-kawannya).

use axum::Json;
use axum::body::Bytes;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{Path, Query, State};
use axum::http::header;
use axum::response::IntoResponse;
use sqlx::{MySql, Transaction};

use crate::AppState;
use crate::auth::handler::fetch_user;
use crate::error::{AppError, Result};
use crate::models::{
    ApiResponse, CloudFile, CloudFileRow, DeletedResponse, JwtClaims, PrefsResponse,
    PutPrefsRequest, SyncListResponse, UploadQuery, rfc3339_utc,
};
use crate::sync::{
    MAX_PREFS_BYTES, encode_header_name, revision_accepted, sha256_hex, validate_name,
};
use crate::tier::{QuotaViolation, Tier, TierLimits, check_upload};

const CLOUD_FILE_COLUMNS: &str = "id, name, size, sha256, revision, updated_at";

fn not_found() -> AppError {
    AppError::NotFound("Berkas tidak ditemukan".to_string())
}

/// Ukuran dari basis data (BIGINT bertanda) ke aritmetika kuota.
fn as_u64(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

fn mb(bytes: u64) -> u64 {
    bytes / crate::tier::MIB
}

fn quota_error(violation: QuotaViolation, limits: &TierLimits, tier: Tier) -> AppError {
    match violation {
        QuotaViolation::FileTooLarge => AppError::PayloadTooLarge(format!(
            "Berkas terlalu besar (maksimal {} MB)",
            mb(limits.max_file_bytes)
        )),
        QuotaViolation::BytesExceeded => AppError::QuotaExceeded(format!(
            "Kuota penyimpanan awan akun {tier} penuh ({} MB)",
            mb(limits.quota_bytes)
        )),
        QuotaViolation::TooManyFiles => AppError::QuotaExceeded(format!(
            "Jumlah berkas awan akun {tier} sudah mencapai batas ({} berkas)",
            limits.max_files
        )),
    }
}

// ─── Berkas ─────────────────────────────────────────────────────────────────

/// `GET /api/v1/sync/files`
///
/// Kolom `data` sengaja tidak di-SELECT: daftar dibuka setiap kali panel
/// sinkronisasi tampil, dan membaca blob di sini berarti membaca seluruh isi
/// akun dari disk hanya untuk menampilkan nama.
pub async fn list_files(
    claims: JwtClaims,
    State(app): State<AppState>,
) -> Result<Json<ApiResponse<SyncListResponse>>> {
    let user = fetch_user(&app.db, &claims.sub).await?;
    let tier = Tier::from_db(&user.license_tier);
    let limits = app.config.sync.for_tier(tier);

    let rows: Vec<CloudFileRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {CLOUD_FILE_COLUMNS} FROM cloud_files WHERE user_id = ?
         ORDER BY updated_at DESC, name ASC"
    )))
    .bind(&claims.sub)
    .fetch_all(&app.db)
    .await?;

    let used_bytes = rows.iter().map(|r| as_u64(r.size)).sum();

    Ok(Json(ApiResponse::ok(SyncListResponse {
        files: rows.into_iter().map(CloudFile::from).collect(),
        used_bytes,
        quota_bytes: limits.quota_bytes,
        max_file_bytes: limits.max_file_bytes,
        max_files: limits.max_files,
        tier: tier.as_str().to_string(),
    })))
}

/// `GET /api/v1/sync/files/{id}`
///
/// Body mentah, metadata di header. Berkas milik akun lain dijawab 404 yang
/// sama dengan berkas yang tidak ada, supaya id tidak bisa dipakai menebak
/// keberadaan berkas orang lain.
pub async fn download_file(
    claims: JwtClaims,
    State(app): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse> {
    let row: Option<(String, i64, String, Vec<u8>)> = sqlx::query_as(
        "SELECT name, revision, sha256, data FROM cloud_files WHERE id = ? AND user_id = ?",
    )
    .bind(&id)
    .bind(&claims.sub)
    .fetch_optional(&app.db)
    .await?;
    let (name, revision, sha256, data) = row.ok_or_else(not_found)?;

    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_string()),
            (header::CACHE_CONTROL, "private, no-store".to_string()),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_string()),
        ],
        [
            ("x-ducad-name", encode_header_name(&name)),
            ("x-ducad-revision", revision.to_string()),
            ("x-ducad-sha256", sha256),
        ],
        data,
    ))
}

/// `PUT /api/v1/sync/files?name=…&base_revision=n[&force=true]`
///
/// Upsert berdasarkan `(user_id, name)`. Seluruh pemeriksaan revisi dan
/// kuota terjadi di dalam SATU transaksi yang lebih dulu mengunci baris
/// `users` pemanggil (`FOR UPDATE`): unggahan paralel dari dua perangkat
/// untuk akun yang sama menjadi berurutan, sehingga keduanya tidak bisa
/// sama-sama lolos cek revisi atau sama-sama muat di sisa kuota.
pub async fn upload_file(
    claims: JwtClaims,
    State(app): State<AppState>,
    query: std::result::Result<Query<UploadQuery>, QueryRejection>,
    body: Bytes,
) -> Result<Json<ApiResponse<CloudFile>>> {
    let Query(query) =
        query.map_err(|_| AppError::BadRequest("Parameter unggahan tidak valid".to_string()))?;

    let name = query
        .name
        .ok_or_else(|| AppError::BadRequest("Parameter `name` wajib diisi".to_string()))?;
    validate_name(&name).map_err(|m| AppError::BadRequest(m.to_string()))?;

    let force = query.force.unwrap_or(false);
    let base_revision = match query.base_revision {
        Some(n) if n >= 0 => n,
        Some(_) => {
            return Err(AppError::BadRequest(
                "`base_revision` tidak boleh negatif".to_string(),
            ));
        }
        // Tanpa revisi dasar, satu-satunya maksud yang masuk akal adalah
        // menimpa — dan itu harus diminta eksplisit.
        None if force => 0,
        None => {
            return Err(AppError::BadRequest(
                "Parameter `base_revision` wajib diisi".to_string(),
            ));
        }
    };

    if body.is_empty() {
        return Err(AppError::BadRequest("Isi berkas kosong".to_string()));
    }
    let new_size = body.len() as u64;
    // Batas per berkas tidak bergantung tier: tolak sebelum menyentuh DB.
    if new_size > app.config.sync.max_file_bytes {
        let limits = app.config.sync.for_tier(Tier::Free);
        return Err(quota_error(
            QuotaViolation::FileTooLarge,
            &limits,
            Tier::Free,
        ));
    }

    let mut tx = app.db.begin().await?;

    let tier: Option<(String,)> =
        sqlx::query_as("SELECT license_tier FROM users WHERE id = ? FOR UPDATE")
            .bind(&claims.sub)
            .fetch_optional(&mut *tx)
            .await?;
    let tier = Tier::from_db(
        &tier
            .ok_or_else(|| AppError::NotFound("Akun tidak ditemukan".to_string()))?
            .0,
    );
    let limits = app.config.sync.for_tier(tier);

    let existing = select_file_by_name(&mut tx, &claims.sub, &name).await?;

    if !revision_accepted(existing.as_ref().map(|f| f.revision), base_revision, force) {
        let message = match &existing {
            Some(_) if base_revision == 0 => "Berkas dengan nama ini sudah ada di awan".to_string(),
            Some(_) => "Berkas di awan sudah diubah dari perangkat lain".to_string(),
            None => "Berkas sudah tidak ada di awan".to_string(),
        };
        // Transaksi di-drop → rollback otomatis.
        return Err(AppError::Conflict {
            message,
            current: existing.map(|r| Box::new(CloudFile::from(r))),
        });
    }

    let (used, count): (i64, i64) = sqlx::query_as(
        "SELECT CAST(COALESCE(SUM(size), 0) AS SIGNED), COUNT(*)
         FROM cloud_files WHERE user_id = ?",
    )
    .bind(&claims.sub)
    .fetch_one(&mut *tx)
    .await?;

    check_upload(
        &limits,
        as_u64(used),
        as_u64(count),
        existing.as_ref().map(|f| as_u64(f.size)),
        new_size,
    )
    .map_err(|v| quota_error(v, &limits, tier))?;

    let sha256 = sha256_hex(&body);
    let size = i64::try_from(new_size)
        .map_err(|_| AppError::Internal(anyhow::anyhow!("ukuran berkas melampaui i64")))?;

    let id = match &existing {
        // Nama yang tersimpan dipertahankan: pembanding nama tidak peka
        // huruf (collation), dan mengganti kapitalisasinya diam-diam akan
        // terlihat sebagai berkas lain di perangkat yang lain.
        Some(old) => {
            sqlx::query(
                "UPDATE cloud_files
                 SET size = ?, sha256 = ?, data = ?, revision = revision + 1,
                     updated_at = CURRENT_TIMESTAMP
                 WHERE id = ?",
            )
            .bind(size)
            .bind(&sha256)
            .bind(body.as_ref())
            .bind(&old.id)
            .execute(&mut *tx)
            .await?;
            old.id.clone()
        }
        None => {
            let id = uuid::Uuid::new_v4().to_string();
            sqlx::query(
                "INSERT INTO cloud_files (id, user_id, name, size, sha256, revision, data)
                 VALUES (?, ?, ?, ?, ?, 1, ?)",
            )
            .bind(&id)
            .bind(&claims.sub)
            .bind(&name)
            .bind(size)
            .bind(&sha256)
            .bind(body.as_ref())
            .execute(&mut *tx)
            .await?;
            id
        }
    };

    let saved: CloudFileRow = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {CLOUD_FILE_COLUMNS} FROM cloud_files WHERE id = ?"
    )))
    .bind(&id)
    .fetch_one(&mut *tx)
    .await?;

    tx.commit().await?;

    tracing::info!(
        user_id = %claims.sub,
        file_id = %saved.id,
        revision = saved.revision,
        bytes = new_size,
        "berkas awan disimpan"
    );

    Ok(Json(ApiResponse::ok(CloudFile::from(saved))))
}

/// Metadata berkas berdasarkan nama, dikunci untuk sisa transaksi.
async fn select_file_by_name(
    tx: &mut Transaction<'static, MySql>,
    user_id: &str,
    name: &str,
) -> Result<Option<CloudFileRow>> {
    Ok(sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {CLOUD_FILE_COLUMNS} FROM cloud_files
         WHERE user_id = ? AND name = ? FOR UPDATE"
    )))
    .bind(user_id)
    .bind(name)
    .fetch_optional(&mut **tx)
    .await?)
}

/// `DELETE /api/v1/sync/files/{id}`
pub async fn delete_file(
    claims: JwtClaims,
    State(app): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<DeletedResponse>>> {
    let result = sqlx::query("DELETE FROM cloud_files WHERE id = ? AND user_id = ?")
        .bind(&id)
        .bind(&claims.sub)
        .execute(&app.db)
        .await?;

    if result.rows_affected() == 0 {
        return Err(not_found());
    }

    tracing::info!(user_id = %claims.sub, file_id = %id, "berkas awan dihapus");
    Ok(Json(ApiResponse::ok(DeletedResponse { deleted: true })))
}

// ─── Preferensi ─────────────────────────────────────────────────────────────

/// `GET /api/v1/sync/prefs`
pub async fn get_prefs(
    claims: JwtClaims,
    State(app): State<AppState>,
) -> Result<Json<ApiResponse<PrefsResponse>>> {
    Ok(Json(ApiResponse::ok(
        read_prefs(&app.db, &claims.sub).await?,
    )))
}

/// `PUT /api/v1/sync/prefs`
///
/// Last-write-wins: preferensi kecil dan tidak bernilai seperti berkas
/// desain, jadi konflik tidak perlu ditanyakan ke pengguna.
pub async fn put_prefs(
    claims: JwtClaims,
    State(app): State<AppState>,
    body: std::result::Result<Json<PutPrefsRequest>, JsonRejection>,
) -> Result<Json<ApiResponse<PrefsResponse>>> {
    let Json(req) = body.map_err(|_| {
        AppError::BadRequest("Body harus JSON berbentuk {\"prefs\": {...}}".to_string())
    })?;
    if !req.prefs.is_object() {
        return Err(AppError::BadRequest(
            "`prefs` wajib berupa objek JSON".to_string(),
        ));
    }
    let serialized = serde_json::to_string(&req.prefs)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("serialisasi prefs: {e}")))?;
    if serialized.len() > MAX_PREFS_BYTES {
        return Err(AppError::BadRequest(
            "Preferensi terlalu besar (maksimal 64 KB)".to_string(),
        ));
    }

    // Memastikan akunnya masih ada: tanpa ini INSERT gagal di foreign key
    // dan pengguna melihat galat basis data.
    fetch_user(&app.db, &claims.sub).await?;

    sqlx::query(
        "INSERT INTO user_prefs (user_id, prefs, revision) VALUES (?, ?, 1)
         ON DUPLICATE KEY UPDATE
             prefs = VALUES(prefs),
             revision = revision + 1,
             updated_at = CURRENT_TIMESTAMP",
    )
    .bind(&claims.sub)
    .bind(&serialized)
    .execute(&app.db)
    .await?;

    tracing::info!(user_id = %claims.sub, bytes = serialized.len(), "preferensi disimpan");
    Ok(Json(ApiResponse::ok(
        read_prefs(&app.db, &claims.sub).await?,
    )))
}

async fn read_prefs(pool: &sqlx::MySqlPool, user_id: &str) -> Result<PrefsResponse> {
    let row: Option<(String, i64, chrono::NaiveDateTime)> =
        sqlx::query_as("SELECT prefs, revision, updated_at FROM user_prefs WHERE user_id = ?")
            .bind(user_id)
            .fetch_optional(pool)
            .await?;

    match row {
        None => Ok(PrefsResponse {
            prefs: None,
            revision: 0,
            updated_at: None,
        }),
        Some((prefs, revision, updated_at)) => {
            let prefs: serde_json::Value = serde_json::from_str(&prefs).map_err(|e| {
                AppError::Internal(anyhow::anyhow!("prefs tersimpan bukan JSON sah: {e}"))
            })?;
            Ok(PrefsResponse {
                prefs: Some(prefs),
                revision,
                updated_at: Some(rfc3339_utc(updated_at)),
            })
        }
    }
}
