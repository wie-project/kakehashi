# syntax=docker/dockerfile:1
FROM rust:1.97-bookworm AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

COPY Cargo.toml Cargo.lock ./
COPY .cargo ./.cargo
COPY crates ./crates
COPY tests ./tests
COPY scripts ./scripts

RUN rustup component add clippy

# `kh-libsystem` is a guest aarch64-apple-darwin dylib; exclude from Linux CI.
RUN cargo clippy --workspace --exclude kh-libsystem --all-targets -- -D warnings \
    && cargo test --workspace --exclude kh-libsystem \
    && cargo build -p kh-cli --release

FROM debian:bookworm-slim

WORKDIR /app

COPY --from=builder /src/target/release/kh /usr/local/bin/kh

COPY --from=builder /src/tests/fixtures /app/tests/fixtures
COPY --from=builder /src/tests/clang-probe /app/tests/clang-probe

RUN kh --help

ENTRYPOINT ["kh"]
CMD ["run", "--dry-load", "tests/fixtures/minimal_arm64_execute.macho"]
