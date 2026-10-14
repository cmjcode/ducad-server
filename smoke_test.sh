#!/usr/bin/env bash
# ==============================================================================
# smoke_test.sh — memeriksa ducad-server yang SUDAH berjalan.
#
# Penggunaan:
#   ./smoke_test.sh                        # http://127.0.0.1:8430
#   ./smoke_test.sh https://api.ducad.app  # server lain
#
# Yang diperiksa hanyalah perilaku yang tidak butuh akun: health, penolakan
# tanpa token, penanganan provider tak dikenal, dan apakah ketiga provider
# sudah dikonfigurasi. Alur login penuh butuh interaksi browser sungguhan —
# itu ada di `ducad-editor/docs/CEKLIS_UJI_GUI.md`.
#
# Tidak ada akun yang dibuat dan tidak ada data yang dihapus, jadi skrip ini
# aman dijalankan terhadap produksi.
# ==============================================================================

set -uo pipefail

BASE_URL="${1:-${DUCAD_SERVER_URL:-http://127.0.0.1:8430}}"
BASE_URL="${BASE_URL%/}"

GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

LULUS=0
GAGAL=0

lulus() { printf "%b\n" "${GREEN}[LULUS]${NC} $1"; LULUS=$((LULUS + 1)); }
gagal() { printf "%b\n" "${RED}[GAGAL]${NC} $1"; GAGAL=$((GAGAL + 1)); }
info()  { printf "%b\n" "${BLUE}[INFO]${NC} $1"; }
warn()  { printf "%b\n" "${YELLOW}[CATATAN]${NC} $1"; }

if ! command -v curl >/dev/null 2>&1; then
    printf "%b\n" "${RED}curl tidak ditemukan.${NC}"
    exit 1
fi

info "Menguji $BASE_URL"
echo

# ─── 1. Health ────────────────────────────────────────────────────────────────
if [[ "$(curl -sf --max-time 5 "$BASE_URL/health" 2>/dev/null)" == "ok" ]]; then
    lulus "GET /health menjawab 'ok'"
else
    gagal "GET /health tidak menjawab 'ok' — server mati atau URL salah?"
    echo
    info "Tidak melanjutkan: sisa pemeriksaan butuh server yang hidup."
    exit 1
fi

# ─── 2. Poll ticket yang tidak dikenal ────────────────────────────────────────
# Harus `pending`, BUKAN `error`: klien mulai memolling sebelum pengguna
# selesai login, jadi ticket yang belum ada bukan kegagalan.
POLL=$(curl -s --max-time 5 -X POST "$BASE_URL/api/v1/auth/ticket/poll" \
    -H 'Content-Type: application/json' \
    -d '{"ticket":"ticket-yang-tidak-pernah-ada-0000"}' 2>/dev/null)
if [[ "$POLL" == *'"status":"pending"'* ]]; then
    lulus "POST /auth/ticket/poll menjawab 'pending' untuk ticket tak dikenal"
else
    gagal "POST /auth/ticket/poll menjawab tak terduga: $POLL"
fi

# ─── 3. Endpoint berautentikasi menolak tanpa token ───────────────────────────
for metode in GET DELETE; do
    KODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
        -X "$metode" "$BASE_URL/api/v1/users/me" 2>/dev/null)
    if [[ "$KODE" == "401" ]]; then
        lulus "$metode /users/me tanpa token → 401"
    else
        gagal "$metode /users/me tanpa token → $KODE (harusnya 401)"
    fi
done

# Token yang bentuknya sah tapi tanda tangannya bukan milik server ini.
KODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
    -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJwYWxzdSJ9.tandatanganpalsu" \
    "$BASE_URL/api/v1/users/me" 2>/dev/null)
if [[ "$KODE" == "401" ]]; then
    lulus "GET /users/me dengan token palsu → 401"
else
    gagal "GET /users/me dengan token palsu → $KODE (harusnya 401)"
fi

# ─── 4. Provider tak dikenal ──────────────────────────────────────────────────
KODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
    "$BASE_URL/api/v1/auth/login/facebook?client=ducad&ticket=uji" 2>/dev/null)
if [[ "$KODE" == "400" ]]; then
    lulus "GET /auth/login/facebook → 400"
else
    gagal "GET /auth/login/facebook → $KODE (harusnya 400)"
fi

# ─── 5. Konfigurasi ketiga provider ───────────────────────────────────────────
# `Redirect::temporary` menghasilkan 307. Provider yang belum dikonfigurasi
# menjawab 502 dengan pesan yang menyebut env var yang kurang — itu bukan
# kegagalan server, jadi dilaporkan sebagai catatan.
echo
for provider in apple google github; do
    RESP=$(curl -s -i --max-time 8 \
        "$BASE_URL/api/v1/auth/login/$provider?client=ducad&ticket=smoke-$provider" 2>/dev/null)
    KODE=$(printf '%s' "$RESP" | head -1 | awk '{print $2}')

    case "$KODE" in
        307|302)
            LOKASI=$(printf '%s' "$RESP" | grep -i '^location:' | head -1 | tr -d '\r')
            if [[ "$provider" == "apple"  && "$LOKASI" == *appleid.apple.com* ]] || \
               [[ "$provider" == "google" && "$LOKASI" == *accounts.google.com* ]] || \
               [[ "$provider" == "github" && "$LOKASI" == *github.com* ]]; then
                lulus "login/$provider mengalihkan ke provider ($KODE)"
            else
                gagal "login/$provider mengalihkan ke tempat tak terduga: $LOKASI"
            fi
            ;;
        502)
            warn "login/$provider belum dikonfigurasi di server ini:"
            printf '%s' "$RESP" | tail -1 | sed 's/^/           /'
            ;;
        *)
            gagal "login/$provider → $KODE (harusnya 307, atau 502 bila belum dikonfigurasi)"
            ;;
    esac
done

# ─── Ringkasan ────────────────────────────────────────────────────────────────
echo
info "Lulus: $LULUS   Gagal: $GAGAL"
[[ "$GAGAL" -eq 0 ]] || exit 1
