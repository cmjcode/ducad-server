//! Tier lisensi (Free/Pro) dan kuota sinkronisasi yang melekat padanya.
//!
//! Kuota adalah satu-satunya bagian tier yang ditegakkan SERVER: fitur lain
//! yang dibedakan per tier diputuskan klien dari `license_tier`. Karena itu
//! seluruh aritmetikanya ada di sini sebagai fungsi murni yang bisa diuji
//! tanpa basis data.

use std::fmt;

/// Tier lisensi yang sah. Disimpan di `users.license_tier` persis sebagai
/// `as_str()` (case-sensitive) dan ditampilkan klien sebagai
/// "Ducad {tier} Tier".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    Free,
    Pro,
}

impl Tier {
    /// Parser masukan manusia (env var, subcommand admin): tidak peka huruf
    /// besar-kecil dan mengabaikan spasi di tepi. Nilai lain ditolak — tier
    /// yang salah ketik akan tersimpan permanen di baris pengguna.
    pub fn parse(value: &str) -> Option<Tier> {
        match value.trim().to_ascii_lowercase().as_str() {
            "free" => Some(Tier::Free),
            "pro" => Some(Tier::Pro),
            _ => None,
        }
    }

    /// Tafsiran nilai yang SUDAH ada di basis data. Nilai tak dikenal
    /// diperlakukan sebagai Free: gagal menutup, supaya baris yang diubah
    /// manual dengan salah ketik tidak tiba-tiba mendapat kuota Pro.
    pub fn from_db(value: &str) -> Tier {
        Tier::parse(value).unwrap_or(Tier::Free)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Tier::Free => "Free",
            Tier::Pro => "Pro",
        }
    }
}

impl fmt::Display for Tier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Satu MiB. Env var kuota ditulis dalam "MB" tapi dihitung biner, sesuai
/// contoh kontrak (50 MB = 52428800 byte).
pub const MIB: u64 = 1024 * 1024;

/// Batas sinkronisasi dari environment (lihat `Config`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncLimits {
    pub quota_free_bytes: u64,
    pub quota_pro_bytes: u64,
    /// Batas satu berkas, sama untuk semua tier.
    pub max_file_bytes: u64,
    pub max_files_free: u64,
    pub max_files_pro: u64,
}

impl SyncLimits {
    /// Nilai default kontrak: Free 50 MB/20 berkas, Pro 5120 MB/2000 berkas,
    /// 32 MB per berkas.
    pub fn from_mb(
        quota_free_mb: u64,
        quota_pro_mb: u64,
        max_file_mb: u64,
        max_files_free: u64,
        max_files_pro: u64,
    ) -> Self {
        SyncLimits {
            quota_free_bytes: quota_free_mb.saturating_mul(MIB),
            quota_pro_bytes: quota_pro_mb.saturating_mul(MIB),
            max_file_bytes: max_file_mb.saturating_mul(MIB),
            max_files_free,
            max_files_pro,
        }
    }

    pub fn for_tier(&self, tier: Tier) -> TierLimits {
        match tier {
            Tier::Free => TierLimits {
                quota_bytes: self.quota_free_bytes,
                max_files: self.max_files_free,
                max_file_bytes: self.max_file_bytes,
            },
            Tier::Pro => TierLimits {
                quota_bytes: self.quota_pro_bytes,
                max_files: self.max_files_pro,
                max_file_bytes: self.max_file_bytes,
            },
        }
    }

    /// Batas body router untuk PUT berkas: sedikit di atas `max_file_bytes`
    /// supaya berkas yang sedikit kebesaran dijawab handler dengan JSON
    /// `file_too_large`, bukan 413 kosong dari axum.
    pub fn body_limit(&self) -> usize {
        usize::try_from(self.max_file_bytes)
            .unwrap_or(usize::MAX)
            .saturating_add(64 * 1024)
    }
}

impl Default for SyncLimits {
    fn default() -> Self {
        SyncLimits::from_mb(50, 5120, 32, 20, 2000)
    }
}

/// Batas efektif satu akun.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TierLimits {
    pub quota_bytes: u64,
    pub max_files: u64,
    pub max_file_bytes: u64,
}

/// Alasan unggahan ditolak oleh kuota.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaViolation {
    /// Satu berkas melebihi `max_file_bytes` → 413.
    FileTooLarge,
    /// Total byte akun akan melebihi kuota → 403.
    BytesExceeded,
    /// Jumlah berkas akun akan melebihi batas → 403.
    TooManyFiles,
}

/// Memeriksa satu unggahan terhadap batas akun.
///
/// `used_bytes`/`file_count` adalah keadaan SEBELUM unggahan, termasuk
/// berkas yang akan ditimpa. `old_size` = ukuran berkas lama bila unggahan
/// menimpa (`None` untuk berkas baru): ukuran lama diganti, bukan
/// dijumlahkan, dan jumlah berkas tidak bertambah.
pub fn check_upload(
    limits: &TierLimits,
    used_bytes: u64,
    file_count: u64,
    old_size: Option<u64>,
    new_size: u64,
) -> Result<(), QuotaViolation> {
    if new_size > limits.max_file_bytes {
        return Err(QuotaViolation::FileTooLarge);
    }

    let used_after = used_bytes
        .saturating_sub(old_size.unwrap_or(0))
        .saturating_add(new_size);
    if used_after > limits.quota_bytes {
        return Err(QuotaViolation::BytesExceeded);
    }

    let count_after = if old_size.is_some() {
        file_count
    } else {
        file_count.saturating_add(1)
    };
    if count_after > limits.max_files {
        return Err(QuotaViolation::TooManyFiles);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn batas() -> TierLimits {
        TierLimits {
            quota_bytes: 100,
            max_files: 2,
            max_file_bytes: 60,
        }
    }

    #[test]
    fn tier_diparse_tanpa_peka_huruf() {
        assert_eq!(Tier::parse("free"), Some(Tier::Free));
        assert_eq!(Tier::parse("FREE"), Some(Tier::Free));
        assert_eq!(Tier::parse(" Pro "), Some(Tier::Pro));
        assert_eq!(Tier::parse("pRo"), Some(Tier::Pro));
        assert_eq!(Tier::parse("Enterprise"), None);
        assert_eq!(Tier::parse(""), None);
    }

    #[test]
    fn tier_dinormalkan_ke_bentuk_kanonik() {
        assert_eq!(Tier::parse("pro").map(Tier::as_str), Some("Pro"));
        assert_eq!(Tier::parse("FREE").map(Tier::as_str), Some("Free"));
    }

    #[test]
    fn tier_tak_dikenal_di_db_dianggap_free() {
        assert_eq!(Tier::from_db("Pro"), Tier::Pro);
        assert_eq!(Tier::from_db("Gold"), Tier::Free);
        assert_eq!(Tier::from_db(""), Tier::Free);
    }

    #[test]
    fn default_sesuai_kontrak() {
        let l = SyncLimits::default();
        assert_eq!(l.quota_free_bytes, 52_428_800);
        assert_eq!(l.quota_pro_bytes, 5120 * MIB);
        assert_eq!(l.max_file_bytes, 33_554_432);
        assert_eq!(l.for_tier(Tier::Free).max_files, 20);
        assert_eq!(l.for_tier(Tier::Pro).max_files, 2000);
        assert_eq!(l.body_limit(), 33_554_432 + 65_536);
    }

    #[test]
    fn berkas_baru_dalam_batas_diterima() {
        assert_eq!(check_upload(&batas(), 0, 0, None, 60), Ok(()));
        assert_eq!(check_upload(&batas(), 40, 1, None, 60), Ok(()));
    }

    #[test]
    fn berkas_terlalu_besar_ditolak_lebih_dulu() {
        assert_eq!(
            check_upload(&batas(), 0, 0, None, 61),
            Err(QuotaViolation::FileTooLarge)
        );
    }

    #[test]
    fn kuota_byte_menghitung_total_setelah_unggah() {
        assert_eq!(
            check_upload(&batas(), 41, 1, None, 60),
            Err(QuotaViolation::BytesExceeded)
        );
    }

    #[test]
    fn menimpa_mengganti_ukuran_lama() {
        // 90 terpakai, 50 di antaranya berkas yang ditimpa: 90 - 50 + 60 = 100.
        assert_eq!(check_upload(&batas(), 90, 2, Some(50), 60), Ok(()));
        // Tanpa penggantian akan menjadi 150 > 100.
        assert_eq!(
            check_upload(&batas(), 90, 2, Some(49), 60),
            Err(QuotaViolation::BytesExceeded)
        );
    }

    #[test]
    fn jumlah_berkas_hanya_naik_untuk_berkas_baru() {
        assert_eq!(
            check_upload(&batas(), 10, 2, None, 1),
            Err(QuotaViolation::TooManyFiles)
        );
        // Menimpa salah satu dari dua berkas yang ada tetap boleh.
        assert_eq!(check_upload(&batas(), 10, 2, Some(5), 1), Ok(()));
    }
}
