# syntax=docker/dockerfile:1

FROM rust:1-bookworm AS builder

WORKDIR /build

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        build-essential \
        cmake \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release --locked --bin p256-index-server


FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        ca-certificates \
        curl \
    && groupadd --gid 10001 p256 \
    && useradd --uid 10001 --gid p256 --create-home --shell /usr/sbin/nologin p256 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/p256-index-server /usr/local/bin/p256-index-server

USER p256

ENV PORT=11256

EXPOSE 11256

HEALTHCHECK --interval=15s --timeout=3s --start-period=15s --retries=3 \
    CMD curl --fail --silent http://127.0.0.1:11256/api/health || exit 1

ENTRYPOINT ["/usr/local/bin/p256-index-server"]
