//! Sinkronisasi berkas `.ducad` dan preferensi antar perangkat.
//!
//! Sinkronisasi bersifat MANUAL: klien memutuskan kapan mengunggah/mengunduh,
//! server hanya menyimpan blob dan menjaga konsistensi lewat `revision`.
//! Setiap unggahan membawa revisi yang terakhir dilihat klien; bila revisi di
//! server sudah berbeda, unggahan ditolak 409 alih-alih diam-diam menimpa
//! hasil kerja perangkat lain.
//!
//! Logika yang bisa diuji tanpa basis data (validasi nama, aturan revisi,
//! encoding header) ada di modul ini sebagai fungsi murni. Kuota ada di
//! `crate::tier`.

pub mod handler;

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use sha2::{Digest, Sha256};

/// Panjang nama maksimum dalam karakter (bukan byte). Kolomnya VARCHAR(255);
/// 200 menyisakan ruang tanpa harus menghitung ulang di sisi klien.
pub const MAX_NAME_CHARS: usize = 200;

/// Batas `prefs` setelah serialisasi.
pub const MAX_PREFS_BYTES: usize = 64 * 1024;

const EXTENSION: &str = ".ducad";

/// Memvalidasi nama berkas awan. Galat berupa pesan untuk pengguna.
///
/// Nama bukan path: `/` dan `\` ditolak supaya klien tidak pernah tergoda
/// menggabungkannya ke path lokal tanpa sanitasi, dan awalan `.` ditolak
/// supaya tidak menghasilkan berkas tersembunyi di perangkat tujuan.
pub fn validate_name(name: &str) -> Result<(), &'static str> {
    let chars = name.chars().count();
    if chars == 0 {
        return Err("Nama berkas kosong");
    }
    if chars > MAX_NAME_CHARS {
        return Err("Nama berkas terlalu panjang (maksimal 200 karakter)");
    }
    if name.starts_with('.') {
        return Err("Nama berkas tidak boleh diawali titik");
    }
    if name
        .chars()
        .any(|c| c == '/' || c == '\\' || c.is_control())
    {
        return Err("Nama berkas tidak boleh memuat '/', '\\', atau karakter kontrol");
    }
    let lower = name.to_lowercase();
    if !lower.ends_with(EXTENSION) {
        return Err("Nama berkas harus berakhiran .ducad");
    }
    Ok(())
}

/// Aturan revisi unggahan. `current` = revisi di server (`None` bila berkas
/// belum ada).
///
/// - `force` → selalu boleh (timpa).
/// - `base_revision == 0` → berkas belum boleh ada.
/// - `base_revision > 0` → revisi server harus sama persis.
pub fn revision_accepted(current: Option<i64>, base_revision: i64, force: bool) -> bool {
    if force {
        return true;
    }
    match current {
        None => base_revision == 0,
        Some(rev) => base_revision > 0 && rev == base_revision,
    }
}

/// Karakter yang TIDAK di-encode: unreserved RFC 3986. Selebihnya (termasuk
/// spasi dan seluruh byte UTF-8 non-ASCII) di-percent-encode, sehingga nilai
/// header selalu ASCII yang sah.
const HEADER_ENCODE: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// Nilai header `X-Ducad-Name`: nama UTF-8 yang di-percent-encode.
pub fn encode_header_name(name: &str) -> String {
    utf8_percent_encode(name, HEADER_ENCODE).to_string()
}

/// SHA-256 isi berkas dalam hex huruf kecil (64 karakter).
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nama_sah_diterima() {
        assert_eq!(validate_name("bracket.ducad"), Ok(()));
        assert_eq!(validate_name("Bracket Utama.DUCAD"), Ok(()));
        assert_eq!(validate_name("flensa ø20 – rev B.ducad"), Ok(()));
        assert_eq!(validate_name("a.ducad"), Ok(()));
    }

    #[test]
    fn nama_tanpa_ekstensi_ditolak() {
        assert!(validate_name("bracket").is_err());
        assert!(validate_name("bracket.step").is_err());
        assert!(validate_name("bracket.ducad.bak").is_err());
    }

    #[test]
    fn nama_kosong_atau_diawali_titik_ditolak() {
        assert!(validate_name("").is_err());
        assert!(validate_name(".ducad").is_err());
        assert!(validate_name(".rahasia.ducad").is_err());
    }

    #[test]
    fn pemisah_path_dan_kontrol_ditolak() {
        assert!(validate_name("folder/bracket.ducad").is_err());
        assert!(validate_name("folder\\bracket.ducad").is_err());
        assert!(validate_name("../bracket.ducad").is_err());
        assert!(validate_name("brac\nket.ducad").is_err());
        assert!(validate_name("brac\u{0}ket.ducad").is_err());
        assert!(validate_name("brac\u{7f}ket.ducad").is_err());
    }

    #[test]
    fn panjang_dihitung_per_karakter() {
        // 194 karakter + ".ducad" = 200 → sah, walau tiap "é" dua byte.
        let pas = format!("{}.ducad", "é".repeat(194));
        assert_eq!(pas.chars().count(), 200);
        assert_eq!(validate_name(&pas), Ok(()));

        let lebih = format!("{}.ducad", "é".repeat(195));
        assert!(validate_name(&lebih).is_err());
    }

    #[test]
    fn aturan_revisi() {
        // Berkas baru.
        assert!(revision_accepted(None, 0, false));
        assert!(!revision_accepted(None, 3, false));
        // Berkas ada.
        assert!(revision_accepted(Some(3), 3, false));
        assert!(!revision_accepted(Some(3), 2, false));
        assert!(!revision_accepted(Some(3), 0, false));
        // force mengabaikan semuanya.
        assert!(revision_accepted(Some(3), 0, true));
        assert!(revision_accepted(None, 7, true));
    }

    #[test]
    fn header_nama_di_percent_encode() {
        assert_eq!(encode_header_name("bracket.ducad"), "bracket.ducad");
        assert_eq!(encode_header_name("rev B.ducad"), "rev%20B.ducad");
        assert_eq!(encode_header_name("ø.ducad"), "%C3%B8.ducad");
        assert!(encode_header_name("a\"b;c.ducad").is_ascii());
    }

    #[test]
    fn sha256_hex_64_karakter() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(sha256_hex(b"").len(), 64);
    }
}
