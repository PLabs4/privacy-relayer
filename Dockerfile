# syntax=docker/dockerfile:1
# ── Build stage ───────────────────────────────────────────────────────────────
FROM rust:1-bookworm AS builder
WORKDIR /app

# reqwest uses native-tls → needs OpenSSL headers at build time.
RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Cache dependencies first: copy manifests and the pinned Git fetch policy,
# build a stub, then the real source.
COPY Cargo.toml Cargo.lock ./
COPY .cargo ./.cargo
RUN mkdir -p src && echo 'fn main() {}' > src/main.rs \
    && cargo build --release --locked \
    && rm -rf src

COPY . .
RUN touch src/main.rs && cargo build --release --locked

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libssl3 wget \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --system --create-home --uid 10001 appuser
USER appuser
WORKDIR /home/appuser

COPY --from=builder /app/target/release/privacy-relayer /usr/local/bin/privacy-relayer

EXPOSE 8790
# `serve` reads all config from env (see .env.example).
ENTRYPOINT ["privacy-relayer"]
CMD ["serve"]
