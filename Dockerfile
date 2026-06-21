FROM rust:1.89-bookworm AS builder

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release --locked --bin sniproxy-ng

FROM debian:bookworm-slim AS runtime

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/sniproxy-ng /usr/local/bin/sniproxy-ng
COPY config.toml.example /app/config.toml

EXPOSE 80/tcp 443/tcp 443/udp

ENTRYPOINT ["sniproxy-ng"]
