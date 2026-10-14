//! Pool koneksi, migrasi skema, dan pembersihan baris kedaluwarsa.

use std::time::Duration;

use sqlx::MySqlPool;
use sqlx::mysql::MySqlPoolOptions;

const SCHEMA: &str = include_str!("schema.sql");

/// Jeda antar pembersihan `oauth_states`/`auth_tickets` kedaluwarsa.
const SWEEP_INTERVAL: Duration = Duration::from_secs(300);

pub async fn create_pool(database_url: &str) -> anyhow::Result<MySqlPool> {
    let pool = MySqlPoolOptions::new()
        .max_connections(10)
        .min_connections(1)
        .acquire_timeout(Duration::from_secs(10))
        .idle_timeout(Duration::from_secs(300))
        .connect(database_url)
        .await?;

    tracing::info!("pool koneksi MySQL siap");
    Ok(pool)
}

/// Menjalankan `schema.sql`. Seluruh pernyataannya `CREATE TABLE IF NOT
/// EXISTS`, jadi aman dipanggil di setiap start.
pub async fn run_migrations(pool: &MySqlPool) -> anyhow::Result<()> {
    tracing::info!("menjalankan migrasi skema");

    for statement in split_statements(SCHEMA) {
        sqlx::query(sqlx::AssertSqlSafe(statement.clone()))
            .execute(pool)
            .await
            .map_err(|e| {
                let cuplikan: String = statement.chars().take(60).collect();
                anyhow::anyhow!("migrasi gagal pada pernyataan `{cuplikan}…`: {e}")
            })?;
    }

    tracing::info!("migrasi skema selesai");
    Ok(())
}

/// Memecah berkas SQL menjadi pernyataan-pernyataan.
///
/// Komentar `--` dibuang PER BARIS lebih dulu, baru dipecah dengan `;`.
/// Urutan itu penting: memeriksa apakah satu potongan pernyataan diawali
/// `--` tidak bekerja, karena setiap `CREATE TABLE` di `schema.sql` didahului
/// blok komentar — seluruh potongannya akan terlihat sebagai komentar dan
/// pernyataannya hilang diam-diam.
fn split_statements(sql: &str) -> Vec<String> {
    let tanpa_komentar: String = sql
        .lines()
        .filter(|line| !line.trim_start().starts_with("--"))
        .collect::<Vec<_>>()
        .join("\n");

    tanpa_komentar
        .split(';')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Menyalakan tugas latar yang membuang nonce dan ticket kedaluwarsa.
///
/// Tanpa ini kedua tabel hanya bertambah: setiap percobaan login menyisakan
/// satu baris `oauth_states` (bila pengguna menutup tab sebelum callback) dan
/// satu baris `auth_tickets`. Yang sudah `consumed` juga ikut dibuang setelah
/// kedaluwarsa, sehingga tidak ada payload token yang tersimpan lebih lama
/// dari yang dibutuhkan.
pub fn spawn_sweeper(pool: MySqlPool) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(SWEEP_INTERVAL);
        loop {
            tick.tick().await;

            match sweep_once(&pool).await {
                Ok((states, tickets)) if states + tickets > 0 => {
                    tracing::debug!("pembersihan: {states} state, {tickets} ticket kedaluwarsa");
                }
                Ok(_) => {}
                // Kegagalan pembersihan tidak boleh mematikan tugasnya:
                // basis data yang sedang tidak bisa dihubungi akan pulih,
                // dan putaran berikutnya mencoba lagi.
                Err(e) => tracing::warn!("pembersihan baris kedaluwarsa gagal: {e}"),
            }
        }
    });
}

async fn sweep_once(pool: &MySqlPool) -> sqlx::Result<(u64, u64)> {
    let states = sqlx::query("DELETE FROM oauth_states WHERE expires_at < NOW()")
        .execute(pool)
        .await?
        .rows_affected();

    let tickets = sqlx::query("DELETE FROM auth_tickets WHERE expires_at < NOW()")
        .execute(pool)
        .await?
        .rows_affected();

    Ok((states, tickets))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skema_terpecah_menjadi_lima_pernyataan() {
        let statements = split_statements(SCHEMA);
        assert_eq!(
            statements.len(),
            5,
            "schema.sql harus menghasilkan tepat 5 CREATE TABLE, dapat: {}",
            statements.len()
        );
        for s in &statements {
            assert!(
                s.starts_with("CREATE TABLE IF NOT EXISTS"),
                "pernyataan tidak idempotent: {s}"
            );
        }
    }

    #[test]
    fn skema_memuat_tabel_yang_dibutuhkan() {
        for tabel in ["users", "sessions", "oauth_states", "auth_tickets", "user_avatars"] {
            assert!(
                SCHEMA.contains(&format!("CREATE TABLE IF NOT EXISTS {tabel}")),
                "tabel {tabel} tidak ada di skema"
            );
        }
    }

    #[test]
    fn komentar_tidak_ikut_menelan_pernyataan() {
        // Regresi: pemecah yang memeriksa awalan "--" per-potongan akan
        // membuang CREATE TABLE yang didahului komentar.
        let sql = "-- komentar\nCREATE TABLE a (x INT);\n-- komentar lain\nCREATE TABLE b (y INT);";
        let statements = split_statements(sql);
        assert_eq!(statements.len(), 2);
        assert!(statements[0].starts_with("CREATE TABLE a"));
        assert!(statements[1].starts_with("CREATE TABLE b"));
    }
}
