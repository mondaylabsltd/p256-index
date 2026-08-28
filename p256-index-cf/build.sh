#!/bin/sh
# Self-bootstrapping build, invoked by `wrangler deploy` / `wrangler dev`
# via [build] in wrangler.toml. Locally (Rust already installed) the
# bootstrap is a no-op; in CI images without Rust (e.g. Workers Builds,
# whose runtimes are Go/Node/Python/Ruby only) it installs a minimal
# toolchain first — so the dashboard's Build command stays empty and the
# whole build recipe lives in the repo.
set -eu

if ! command -v cargo >/dev/null 2>&1; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --profile minimal --default-toolchain stable \
            --target wasm32-unknown-unknown
fi
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
# No-op when the target is already present; harmless on non-rustup installs.
rustup target add wasm32-unknown-unknown >/dev/null 2>&1 || true

# Pinned: worker-build must match the `worker` crate line in Cargo.toml.
cargo install -q worker-build --version 0.8.5
worker-build --release
