//! Halaman yang dilihat pengguna di browser setelah login berhasil.
//!
//! Selalu bermerek DUCAD dan berbahasa Indonesia: server ini hanya melayani
//! satu aplikasi, jadi tidak ada percabangan merek berdasarkan query
//! `client` seperti pada server bersama.

/// Merender halaman sukses.
///
/// Bila `loopback_port` ada, halaman ini juga menembakkan token ke listener
/// loopback klien sebagai jalur cepat. Itu **best-effort**: token yang sama
/// sudah tersedia lewat ticket polling HTTPS, dan
///
/// - Safari memblokir `fetch` lintas-origin dari HTTPS ke `127.0.0.1`;
/// - App Sandbox macOS dan iPadOS tidak mengizinkan listener loopback sama
///   sekali, sehingga port-nya memang sering tidak ada.
///
/// Karena itu kegagalan `fetch` DIABAIKAN tanpa `window.location` — versi
/// yang mengalihkan halaman saat gagal justru menghancurkan halaman sukses
/// ini dan memunculkan galat "tidak bisa terhubung ke 127.0.0.1" di Safari.
pub fn render(loopback_port: Option<u16>, token_json: &str) -> String {
    let script = match loopback_port {
        Some(port) => format!(
            r#"    <script>
      const tokens = {token};
      fetch('http://127.0.0.1:{port}/callback', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify(tokens)
      }}).catch(() => {{
        /* Diabaikan: aplikasi menjemput token lewat ticket polling HTTPS. */
      }});
    </script>"#,
            token = escape_for_script(token_json),
            port = port,
        ),
        None => String::new(),
    };

    format!(
        r#"<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>DUCAD — Login Berhasil</title>
  <style>
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: #0f172a; color: #f8fafc;
      display: flex; align-items: center; justify-content: center;
      min-height: 100vh; margin: 0; padding: 24px; box-sizing: border-box;
    }}
    .kartu {{
      background: #1e293b; border: 1px solid #334155; border-radius: 16px;
      padding: 2.5rem; max-width: 440px; text-align: center;
      box-shadow: 0 10px 25px rgba(0,0,0,0.5);
    }}
    .ikon {{ font-size: 48px; margin-bottom: 12px; }}
    h1 {{ color: #38bdf8; font-size: 24px; margin: 0 0 8px; }}
    p {{ color: #94a3b8; font-size: 15px; line-height: 1.5; margin: 0 0 16px; }}
    .status {{
      font-size: 13px; color: #4ade80; background: rgba(74,222,128,0.1);
      padding: 8px 12px; border-radius: 8px; display: inline-block;
    }}
  </style>
</head>
<body>
  <div class="kartu">
    <div class="ikon">📐✨</div>
    <h1>Login DUCAD Berhasil</h1>
    <p>Akun Anda sudah terotentikasi. Tutup tab ini dan kembali ke aplikasi DUCAD.</p>
    <div class="status">DUCAD Cloud Aktif</div>
  </div>
{script}
</body>
</html>"#,
        script = script
    )
}

/// Menyiapkan JSON untuk disisipkan ke dalam blok `<script>`.
///
/// `serde_json` tidak meng-escape `<`, jadi nama tampilan dari provider yang
/// memuat `</script>` akan menutup blok skrip lebih awal dan sisanya
/// dieksekusi sebagai HTML — XSS dengan data yang dikendalikan orang lain.
/// `\u003c` dan kawan-kawannya tetap JSON dan JavaScript yang sah, dan
/// ketiga karakter ini hanya bisa muncul di dalam nilai string.
fn escape_for_script(json: &str) -> String {
    json.replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tanpa_port_tidak_ada_skrip_loopback() {
        let html = render(None, r#"{"access_token":"a"}"#);
        assert!(!html.contains("<script"));
        assert!(!html.contains("127.0.0.1"));
        assert!(html.contains("Login DUCAD Berhasil"));
    }

    #[test]
    fn dengan_port_menembak_loopback_tanpa_mengalihkan_halaman() {
        let html = render(Some(49152), r#"{"access_token":"a"}"#);
        assert!(html.contains("http://127.0.0.1:49152/callback"));
        assert!(html.contains(r#"{"access_token":"a"}"#));
        // Regresi: mengalihkan halaman saat fetch gagal menghancurkan
        // halaman sukses di Safari.
        assert!(!html.contains("window.location"));
    }

    #[test]
    fn nama_tampilan_berbahaya_tidak_bisa_menutup_blok_skrip() {
        let token = r#"{"user":{"display_name":"</script><img src=x onerror=alert(1)>"}}"#;
        let html = render(Some(49152), token);
        assert!(
            !html.contains("</script><img"),
            "blok skrip bisa ditutup oleh data provider: {html}"
        );
        assert!(html.contains("\\u003c/script\\u003e"));
    }

    #[test]
    fn halaman_selalu_bermerek_ducad() {
        let html = render(None, "{}");
        assert!(html.contains("DUCAD"));
        assert!(html.contains(r#"lang="id""#));
        // Tidak ada sisa merek dari server bersama.
        assert!(!html.to_lowercase().contains("tabular"));
        assert!(!html.to_lowercase().contains("cmjcode"));
    }
}
