# syntax=docker/dockerfile:1

FROM rust:1-bookworm AS builder

WORKDIR /build

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        build-essential \
        cmake \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Build context is the repository root (see docker-compose.yaml). Cargo loads
# the manifest of EVERY workspace member before it builds anything, so all
# three members must be copied even though only the server is built — a
# missing one fails the build with "failed to load manifest for workspace
# member". Keep this list in step with `members` in the root Cargo.toml.
COPY Cargo.toml Cargo.lock ./
COPY p256-registrar ./p256-registrar
COPY p256-index-server ./p256-index-server
COPY p256-replay ./p256-replay

RUN cargo build --release --locked -p p256-index-server


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
