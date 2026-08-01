FROM rust:1.88-bookworm AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    build-essential \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

RUN rustup component add clippy

COPY Cargo.toml Cargo.lock ./
COPY .cargo ./.cargo

COPY crates ./crates
COPY tests ./tests
COPY scripts ./scripts

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo clippy --workspace --exclude kh-libsystem --all-targets -- -D warnings \
    && cargo test --workspace --exclude kh-libsystem \
    && cargo build -p kakehashi --release \
    && cp /src/target/release/kh /src/kh

FROM debian:bookworm-slim

WORKDIR /app

COPY --from=builder /src/kh /usr/local/bin/kh

COPY --from=builder /src/tests/fixtures /app/tests/fixtures
COPY --from=builder /src/tests/clang-probe /app/tests/clang-probe

RUN kh --help

ENTRYPOINT ["kh"]
CMD ["run", "--dry-load", "tests/fixtures/minimal_arm64_execute.macho"]
