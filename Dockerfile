# syntax=docker/dockerfile:1
# ── Build stage ───────────────────────────────────────────────────────────────
# Multi-arch OCI index digests verified from Docker Hub on 2026-07-30.
FROM rust:1-bookworm@sha256:77fac8b98f9f46062bb680b6d25d5bcaabfc400143952ebc572e924bcbedc3fa AS builder
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
FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818 AS runtime
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
