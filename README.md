# Kakehashi

Userspace **macOS ARM64 → Linux aarch64** translation layer (CLI-first, no JIT).

Load Darwin Mach-O on Linux aarch64, map a freestanding `libSystem`, translate
BSD syscalls, and run real guests (clang probes, **7-Zip `7zz`**, threads).

Live execution needs **Linux aarch64** (bare metal, VM, or Colima/Docker).  
`kh inspect` and `kh run --dry-load` work on any host (including macOS).

## Crates

| Crate          | Role                                                           |
| -------------- | -------------------------------------------------------------- |
| `kh-cli`       | Binary `kh` — inspect / run / trace / bottle                   |
| `kh-loader`    | Mach-O parse, image plan, map session, micro execute           |
| `kh-runtime`   | Page geometry, guest `mmap`, stack, traps, BSD table, bottle   |
| `kh-libsystem` | Freestanding guest `libSystem.B.dylib` (build on Apple Darwin) |

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
# or: ./scripts/docker-smoke.sh
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

---

## Testing map (what to run, where results land)

| Goal | Command | Where to look |
| ---- | ------- | ------------- |
| Unit tests | `cargo test --workspace --exclude kh-libsystem` | terminal pass/fail |
| Full Docker smoke | `./scripts/docker-smoke.sh` | terminal; ends with `smoke ok` |
| Synthetic fixtures | `kh run --expect-code … tests/fixtures/…` | stdout + exit code (see `tests/fixtures/README.md`) |
| Clang probes | `kh run --root tests/fixtures/bottle tests/clang-probe/puts_hello` | stdout `hello` (see `tests/clang-probe/README.md`) |
| Real guest `7zz` | `./scripts/docker-7zz.sh …` | **host** `.tmp/kh-out/` (default) |
| Fair CPU bench | `./scripts/bench-fair-local.sh` | **host** `.tmp/kh-bench-fair/` |

All of `.tmp/`, `.kh/`, and `target/` are gitignored. Nothing important is
hidden only inside a throwaway container without a copy-out step.

### Guest path ↔ host path (Docker helpers)

When `kh` runs in Docker, the bottle bridges the Linux filesystem as
`/Volumes/linux/…`:

| You pass to the guest | Actually on the host |
| --------------------- | -------------------- |
| `/Volumes/linux/src/README.md` | `<repo>/README.md` (repo bind-mount) |
| `/Volumes/linux/out/demo.7z` | `<repo>/.tmp/kh-out/demo.7z` (**durable**, default for `docker-7zz.sh`) |
| `/Volumes/linux/src/.tmp/foo.7z` | `<repo>/.tmp/foo.7z` (also durable) |
| `/Volumes/linux/tmp/….7z` | container `/tmp/…` — **gone** after `docker run --rm` |

---

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
```

### Real guest: 7-Zip (`7zz`)

Darwin universal binary: `tests/clang-probe/7zz.bin`.

```bash
./scripts/stage-libsystem.sh

# Help text from the guest
./scripts/docker-7zz.sh --help

# Compress README → host file .tmp/kh-out/demo.7z  (open it yourself after)
./scripts/docker-7zz.sh a /Volumes/linux/out/demo.7z \
  /Volumes/linux/src/README.md

ls -lh .tmp/kh-out/demo.7z
# On macOS (if you have 7z/7zz), or with the Linux binary from a prior bench:
#   7zz t .tmp/kh-out/demo.7z
```

Regenerate synthetic fixtures:

```bash
cargo run -p kh-loader --example write_fixture
```

---

## Fair bench (native Linux 7zz vs kh + Darwin 7zz)

One random blob on **container-local** `/tmp` (not Virtio-FS), then both
compressors write archives that are **copied to the host** so you can inspect
them.

```bash
./scripts/stage-libsystem.sh
./scripts/bench-fair-local.sh                 # 200 MiB, mx=5, mmt=2
SIZE_MB=64 MMT=1 ./scripts/bench-fair-local.sh
KAKEHASHI_HYPERCALL=0 ./scripts/bench-fair-local.sh
```

### Where the files are (host)

```
.tmp/kh-bench-fair/                 ← override with KH_BENCH_OUT=
  README.txt                        how to re-check without re-running
  summary.txt                       timings, ratio, archive=ok lines
  native.log  kh.log                compressor stdout
  bin/7zz                           Linux aarch64 7zz (downloaded once)
  artifacts/
    native.7z                       from host Linux 7zz
    kh.7z                           from Darwin 7zz under kh
    *.sha256  sizes.txt             checksums + byte sizes
    verify-native.txt  verify-kh.txt  full `7zz t` output
    run-meta.txt                    size / mx / mmt / hypercall / nproc
```

### Re-verify yourself

```bash
cat .tmp/kh-bench-fair/summary.txt
ls -lh .tmp/kh-bench-fair/artifacts/*.7z

cd .tmp/kh-bench-fair/artifacts
shasum -a 256 -c native.7z.sha256 kh.7z.sha256   # works on macOS too
```

Test archive integrity with any 7-Zip:

```bash
# macOS: brew install sevenzip   →  7zz
7zz t .tmp/kh-bench-fair/artifacts/native.7z
7zz t .tmp/kh-bench-fair/artifacts/kh.7z

# or reuse the Linux binary the bench downloaded (Linux aarch64 host / same Docker image):
docker run --rm -v "$PWD/.tmp/kh-bench-fair:/r" -w /r kakehashi:dev \
  /r/bin/7zz t /r/artifacts/kh.7z
```

Guest Darwin `7zz` and Linux `7zz` are **different binaries** — compare
hypercall vs `KAKEHASHI_HYPERCALL=0` for path overhead, not absolute
“native × N” across product versions.

### Performance knobs

- Freestanding **hypercall** is on by default (no `SIGTRAP` on the hot path).
  Opt out with `KAKEHASHI_HYPERCALL=0`.
- After the first guest `pthread_create`, freestanding switches remaining
  syscalls to patched `svc`→`brk` (MT-safe). Single-thread keeps hypercall.

---

## Scripts

| Script | Purpose |
| ------ | ------- |
| `scripts/stage-libsystem.sh` | Copy built guest dylib → `dist/guest/libSystem.B.dylib` |
| `scripts/docker-smoke.sh` | Reproducible smoke suite inside `Dockerfile` image |
| `scripts/docker-7zz.sh` | Interactive/ad-hoc Darwin `7zz` under `kh` (outputs → `.tmp/kh-out`) |
| `scripts/bench-fair-local.sh` | Timed native vs kh compress; artifacts → `.tmp/kh-bench-fair` |

## License

LGPL-3.0-only. See `LICENSE.txt` and `NOTICE`.

This project is **not** derived from Darling. Do not vendor proprietary Apple SDKs or blobs.
