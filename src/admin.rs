//! Subcommand admin biner: mengubah tier dan melihat daftar pengguna.
//!
//! Sengaja bukan endpoint HTTP: belum ada pembayaran, Pro diberikan manual,
//! dan endpoint admin berarti satu permukaan serangan dan satu mekanisme
//! otorisasi tambahan untuk operasi yang dijalankan beberapa kali sebulan.
//! Siapa pun yang bisa menjalankan biner ini dengan `DATABASE_URL` produksi
//! memang sudah memegang basis datanya.
//!
//! ```text
//! ducad-server set-tier <user_id|email> <Free|Pro>
//! ducad-server list-users [--email <email>]
//! ```

use sqlx::MySqlPool;

use crate::tier::Tier;

pub const USAGE: &str = "Penggunaan:
  ducad-server                                   jalankan server HTTP
  ducad-server set-tier <user_id|email> <Free|Pro>
  ducad-server list-users [--email <email>]";

#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    SetTier { target: String, tier: Tier },
    ListUsers { email: Option<String> },
}

/// Mem-parse argumen SETELAH nama biner. `Ok(None)` = tidak ada subcommand
/// (jalankan server). Galat berisi pesan + `USAGE` siap cetak.
pub fn parse_args(args: &[String]) -> Result<Option<Command>, String> {
    let Some(first) = args.first() else {
        return Ok(None);
    };
    let usage = |msg: &str| format!("{msg}\n\n{USAGE}");

    match first.as_str() {
        "set-tier" => match args {
            [_, target, tier] => {
                let tier = Tier::parse(tier).ok_or_else(|| {
                    usage(&format!("Tier tidak dikenal: '{tier}' (Free atau Pro)"))
                })?;
                let target = target.trim();
                if target.is_empty() {
                    return Err(usage("user_id/email kosong"));
                }
                Ok(Some(Command::SetTier {
                    target: target.to_string(),
                    tier,
                }))
            }
            _ => Err(usage("set-tier butuh tepat dua argumen")),
        },
        "list-users" => match args {
            [_] => Ok(Some(Command::ListUsers { email: None })),
            [_, flag, email] if flag == "--email" && !email.trim().is_empty() => {
                Ok(Some(Command::ListUsers {
                    email: Some(email.trim().to_string()),
                }))
            }
            _ => Err(usage("list-users hanya menerima --email <email>")),
        },
        "-h" | "--help" | "help" => Err(USAGE.to_string()),
        other => Err(usage(&format!("Subcommand tidak dikenal: '{other}'"))),
    }
}

pub async fn run(pool: &MySqlPool, command: Command) -> anyhow::Result<()> {
    match command {
        Command::SetTier { target, tier } => set_tier(pool, &target, tier).await,
        Command::ListUsers { email } => list_users(pool, email.as_deref()).await,
    }
}

/// Target dicari sebagai id lebih dulu, lalu sebagai email. Email TIDAK
/// unik (satu alamat bisa punya akun Google dan GitHub terpisah, lihat
/// `schema.sql`), jadi kecocokan ganda ditolak sambil mencetak id-nya —
/// admin lalu mengulang dengan id yang dimaksud.
async fn set_tier(pool: &MySqlPool, target: &str, tier: Tier) -> anyhow::Result<()> {
    let mut matches: Vec<(String, String, String, String)> =
        sqlx::query_as("SELECT id, provider, email, license_tier FROM users WHERE id = ?")
            .bind(target)
            .fetch_all(pool)
            .await?;

    if matches.is_empty() {
        matches = sqlx::query_as(
            "SELECT id, provider, email, license_tier FROM users WHERE email = ?
             ORDER BY created_at",
        )
        .bind(target)
        .fetch_all(pool)
        .await?;
    }

    let (id, provider, email, old_tier) = match matches.len() {
        0 => anyhow::bail!("Tidak ada pengguna dengan id/email '{target}'"),
        1 => matches.remove(0),
        n => {
            let daftar: Vec<String> = matches
                .iter()
                .map(|(id, provider, _, t)| format!("  {id}  ({provider}, {t})"))
                .collect();
            anyhow::bail!(
                "Email '{target}' dimiliki {n} akun — ulangi dengan user_id:\n{}",
                daftar.join("\n")
            );
        }
    };

    sqlx::query("UPDATE users SET license_tier = ? WHERE id = ?")
        .bind(tier.as_str())
        .bind(&id)
        .execute(pool)
        .await?;

    println!("{id} ({provider}, {email}): {old_tier} -> {tier}");
    Ok(())
}

async fn list_users(pool: &MySqlPool, email: Option<&str>) -> anyhow::Result<()> {
    // Satu kueri dengan pemakaian sinkronisasi supaya admin bisa melihat
    // siapa yang mendekati kuota sebelum menaikkan tier. Kolom `data` tidak
    // disentuh.
    let base = "SELECT u.id, u.provider, u.email, u.license_tier,
                       CAST(COUNT(cf.id) AS SIGNED),
                       CAST(COALESCE(SUM(cf.size), 0) AS SIGNED)
                FROM users u
                LEFT JOIN cloud_files cf ON cf.user_id = u.id";
    let rows: Vec<(String, String, String, String, i64, i64)> = match email {
        Some(e) => {
            sqlx::query_as(sqlx::AssertSqlSafe(format!(
                "{base} WHERE u.email = ? GROUP BY u.id ORDER BY u.created_at"
            )))
            .bind(e)
            .fetch_all(pool)
            .await?
        }
        None => {
            sqlx::query_as(sqlx::AssertSqlSafe(format!(
                "{base} GROUP BY u.id ORDER BY u.created_at"
            )))
            .fetch_all(pool)
            .await?
        }
    };

    println!(
        "{:<36}  {:<8}  {:<5}  {:>6}  {:>12}  email",
        "id", "provider", "tier", "berkas", "byte"
    );
    for (id, provider, email, tier, files, bytes) in &rows {
        println!("{id:<36}  {provider:<8}  {tier:<5}  {files:>6}  {bytes:>12}  {email}");
    }
    println!("{} pengguna", rows.len());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn tanpa_argumen_menjalankan_server() {
        assert_eq!(parse_args(&[]), Ok(None));
    }

    #[test]
    fn set_tier_menormalkan_tier() {
        assert_eq!(
            parse_args(&args(&["set-tier", "a@b.c", "pro"])),
            Ok(Some(Command::SetTier {
                target: "a@b.c".to_string(),
                tier: Tier::Pro
            }))
        );
    }

    #[test]
    fn set_tier_menolak_tier_atau_jumlah_argumen_salah() {
        assert!(parse_args(&args(&["set-tier", "a@b.c", "gold"])).is_err());
        assert!(parse_args(&args(&["set-tier", "a@b.c"])).is_err());
        assert!(parse_args(&args(&["set-tier", "a", "Pro", "x"])).is_err());
    }

    #[test]
    fn list_users_dengan_dan_tanpa_email() {
        assert_eq!(
            parse_args(&args(&["list-users"])),
            Ok(Some(Command::ListUsers { email: None }))
        );
        assert_eq!(
            parse_args(&args(&["list-users", "--email", "a@b.c"])),
            Ok(Some(Command::ListUsers {
                email: Some("a@b.c".to_string())
            }))
        );
        assert!(parse_args(&args(&["list-users", "--mail", "a@b.c"])).is_err());
    }

    #[test]
    fn subcommand_tak_dikenal_ditolak() {
        assert!(parse_args(&args(&["serve"])).is_err());
    }
}
