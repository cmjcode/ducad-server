# ─── Tahap build ──────────────────────────────────────────────────────────────
FROM rust:1.96 AS builder

WORKDIR /usr/src/ducad-server

# sqlx memakai native-tls, yang menuntut OpenSSL saat build.
RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY src ./src

# `--locked`: build container harus memakai versi yang sama dengan yang diuji
# di CI, bukan me-resolve ulang dependensi saat deploy.
RUN cargo build --release --locked

# ─── Tahap runtime ────────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        libssl3 \
        curl \
        tzdata \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/ducad-server/target/release/ducad-server /app/ducad-server
COPY .env /app/.env

ENV SERVER_PORT=8430
EXPOSE 8430

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${SERVER_PORT}/health" || exit 1

ENTRYPOINT ["/app/ducad-server"]
