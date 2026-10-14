#!/usr/bin/env bash
# ==============================================================================
# deploy.sh — membangun ulang dan menjalankan ducad-server lewat Docker Compose
#
# Penggunaan: ./deploy.sh
# ==============================================================================

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log_info()    { printf "%b\n" "${BLUE}[INFO]${NC} $1"; }
log_success() { printf "%b\n" "${GREEN}[OK]${NC} $1"; }
log_warn()    { printf "%b\n" "${YELLOW}[PERINGATAN]${NC} $1"; }
log_error()   { printf "%b\n" "${RED}[GALAT]${NC} $1"; }

if docker compose version >/dev/null 2>&1; then
    COMPOSE_CMD="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE_CMD="docker-compose"
else
    log_error "docker compose maupun docker-compose tidak ditemukan."
    exit 1
fi

cd "$ROOT_DIR"

if [[ ! -f "Dockerfile" || ! -f "docker-compose.yaml" ]]; then
    log_error "Dockerfile atau docker-compose.yaml tidak ada di $ROOT_DIR."
    exit 1
fi

# `.env` TIDAK dibuat otomatis dari env.example. Menyalinnya akan menjalankan
# server dengan JWT_SECRET contoh yang bisa ditebak siapa pun, dan tanpa
# kredensial OAuth — login akan gagal dengan cara yang membingungkan. Lebih
# baik berhenti di sini dengan pesan jelas.
if [[ ! -f ".env" ]]; then
    log_error "Berkas .env belum ada. Salin env.example menjadi .env lalu isi kredensialnya:"
    log_error "  cp env.example .env && \$EDITOR .env"
    exit 1
fi

for kunci in DATABASE_URL JWT_SECRET; do
    if ! grep -qE "^${kunci}=.+" .env; then
        log_error "${kunci} belum diisi di .env — server tidak akan bisa start."
        exit 1
    fi
done

log_info "--> [1/4] Membangun image ducad-server..."
$COMPOSE_CMD build

log_info "--> [2/4] Menjalankan ulang container..."
$COMPOSE_CMD up -d --remove-orphans

log_info "--> [3/4] Membersihkan image dangling..."
docker image prune -f || true

log_info "--> [4/4] Memeriksa status dan health check..."
sleep 3
docker ps --filter "name=ducad-server" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

SERVER_PORT=$(grep -E '^SERVER_PORT=' .env 2>/dev/null | cut -d '=' -f2 | tr -d ' "' || true)
SERVER_PORT=${SERVER_PORT:-8430}

if command -v curl >/dev/null 2>&1; then
    log_info "Menguji http://127.0.0.1:${SERVER_PORT}/health ..."
    for _ in {1..6}; do
        if curl -sf "http://127.0.0.1:${SERVER_PORT}/health" >/dev/null 2>&1; then
            log_success "Health check berhasil: ducad-server merespons."
            exit 0
        fi
        sleep 2
    done
    log_warn "Health check belum merespons dalam 12 detik. Periksa: docker logs ducad-server"
fi
