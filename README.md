# Kakehashi

Userspace **macOS ARM64 → Linux aarch64** translation layer (CLI-first, no JIT).

Load Darwin Mach-O on Linux aarch64, map a freestanding `libSystem`, translate
BSD syscalls, and run real guests (clang probes, **7-Zip `7zz`**, threads).

Live execution needs **Linux aarch64** (bare metal, VM, or Colima/Docker).  
`kh inspect` and `kh run --dry-load` work on any host (including macOS).

## Crates

| Crate          | Role                                                            |
| -------------- | --------------------------------------------------------------- |
| `kh-cli`       | Binary `kh` — inspect / run / trace / bottle                    |
| `kh-loader`    | Mach-O parse, image plan, map session, micro execute            |
| `kh-runtime`   | Page geometry, guest `mmap`, stack, traps, BSD table, bottle    |
| `kh-libsystem` | Freestanding guest `libSystem.B.dylib` (build on Apple Darwin)  |

## Requirements

- Rust 1.97+
- **Linux aarch64** for live `kh run` / `kh trace`
- Page sizes: **4 KiB** (containers) and **16 KiB** (Asahi-class)

## Quick start (Docker / Colima on Apple Silicon)

```bash
# Dev image + unit tests
docker build -t kakehashi:dev -f Dockerfile.dev .
docker run --rm -v "$PWD":/src -w /src kakehashi:dev \
  cargo test --workspace --exclude kh-libsystem

# Full smoke image (build + clippy + test + micro run)
docker build -t kakehashi:smoke -f Dockerfile .
docker run --rm kakehashi:smoke
```

## Build

```bash
# Host CLI + runtime (on Linux aarch64, or inside the Docker image above)
cargo build -p kh-cli --release
cargo test --workspace --exclude kh-libsystem
cargo clippy --workspace --exclude kh-libsystem --all-targets -- -D warnings

# Guest libSystem (on macOS arm64, or with the apple-darwin target available)
cargo build -p kh-libsystem --release --target aarch64-apple-darwin
./scripts/stage-libsystem.sh   # → dist/guest/libSystem.B.dylib
```

### Bottle (macOS-like root for the guest)

```bash
./target/release/kh bottle ensure     # create/refresh managed bottle + libSystem
./target/release/kh bottle status
./target/release/kh bottle destroy --yes
```

Discovery for `libSystem`: `--libsystem` → `KAKEHASHI_LIBSYSTEM` → paths next
to `kh` → `target/.../libkh_libsystem.dylib` → `dist/guest/libSystem.B.dylib`.

## Try it

```bash
# Any host — map only
./target/release/kh run --dry-load tests/fixtures/minimal_arm64_execute.macho

# Linux aarch64 live (fixtures + clang probes)
./target/release/kh run --expect-code 0 tests/fixtures/minimal_arm64_execute.macho
./target/release/kh run --expect-code 42 tests/fixtures/call_dylib.macho
./target/release/kh run --expect-code 0 tests/fixtures/bsdthread_create_join.macho
./target/release/kh run --expect-code 0 --root tests/fixtures/bottle \
  tests/clang-probe/puts_hello

# Real guest: 7zz (Darwin binary under tests/clang-probe/7zz.bin)
./scripts/stage-libsystem.sh
./scripts/docker-7zz.sh --help
./scripts/docker-7zz.sh a /Volumes/linux/tmp/t.7z /Volumes/linux/src/README.md
```

Regenerate synthetic fixtures:

```bash
cargo run -p kh-loader --example write_fixture
```

## Performance notes

- Freestanding **hypercall** is on by default (no `SIGTRAP` on the hot path).
  Opt out with `KAKEHASHI_HYPERCALL=0`.
- After the first guest `pthread_create`, freestanding switches remaining
  syscalls to patched `svc`→`brk` (MT-safe). Single-thread keeps hypercall.
- Fair CPU check (one large blob in container-local `/tmp`, not a virtiofs
  tree of tiny files):

```bash
./scripts/bench-fair-local.sh
SIZE_MB=64 MMT=1 ./scripts/bench-fair-local.sh
KAKEHASHI_HYPERCALL=0 ./scripts/bench-fair-local.sh
```

Guest Darwin `7zz` and a Linux `7zz` are **different binaries** — compare
hyper vs brk for path overhead, not absolute “native × N” across versions.

## Test on a free Linux arm64 machine

You need a real **aarch64 Linux** shell (not x86_64) with Rust, git, and a
staged `libSystem` (build the dylib on a Mac first, commit is not required —
copy `dist/guest/libSystem.B.dylib` or build with a Darwin cross toolchain).

### Option A — Oracle Cloud Always Free (recommended)

1. Sign up: [Oracle Cloud Free Tier](https://www.oracle.com/cloud/free/)  
   (credit card for verification; Always Free Ampere A1 is free ongoing).
2. Create a VM: **Ampere A1** (aarch64), Ubuntu 22.04/24.04, ≥2 OCPU / 12 GB
   (free allowance is shared across A1 shapes).
3. SSH in, then:

```bash
sudo apt update && sudo apt install -y build-essential git curl
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"

git clone <your-fork-or-repo-url> kakehashi && cd kakehashi
# Copy dist/guest/libSystem.B.dylib from your Mac if you did not build it here:
#   scp dist/guest/libSystem.B.dylib user@vm:~/kakehashi/dist/guest/

cargo build -p kh-cli --release
./target/release/kh bottle ensure
./target/release/kh run --expect-code 0 tests/fixtures/minimal_arm64_execute.macho
./target/release/kh run --expect-code 0 --root tests/fixtures/bottle \
  tests/clang-probe/puts_hello
./target/release/kh run tests/clang-probe/7zz.bin -- --help
```

### Option B — GitHub Codespaces / other free aarch64

- Prefer a host that reports `uname -m` → `aarch64` / `arm64`.
- x86_64 free VMs (most Fly.io / Railway free tiers) **cannot** run live
  `kh run` (wrong ISA). Use them only for `dry-load` / inspect.

### Option C — Scaleway / Hetzner / AWS (paid or trial)

Any **arm64** instance works the same as Option A once Rust and the bottle
libSystem are in place.

### Minimal checklist on the VM

```bash
uname -m                    # must be aarch64
cargo test --workspace --exclude kh-libsystem
./target/release/kh bottle ensure
./target/release/kh run --expect-code 0 tests/fixtures/bsdthread_create_join.macho
./target/release/kh run tests/clang-probe/7zz.bin -- \
  a -t7z -mx=1 -mmt=2 /tmp/t.7z README.md
```

## License

LGPL-3.0-only. See `LICENSE.txt` and `NOTICE`.

This project is **not** derived from Darling. Do not vendor proprietary Apple SDKs or blobs.
