# Kakehashi

Userspace **macOS ARM64 → Linux aarch64** translation layer (CLI-first, no JIT).

Load Darwin Mach-O on Linux aarch64, map a freestanding `libSystem`, translate
BSD syscalls, and run real guests (clang probes, **7-Zip `7zz`**, threads).

Live execution needs **Linux aarch64** (bare metal, VM, or Colima/Docker).  
`kh inspect` and `kh run --dry-load` work on any host (including macOS).

## Crates (crates.io)

| Crate        | Role |
| ------------ | ---- |
| **`kakehashi`** | Binary `kh` (install this) |
| `kh-loader`  | Mach-O parse, map session, execute |
| `kh-runtime` | Memory, traps, BSD syscalls, bottle |
| `kh-libsystem` | Freestanding guest `libSystem.B.dylib` (**not** published as a host crate; build for `aarch64-apple-darwin`) |

## Requirements

- Rust 1.97+
- **Linux aarch64** for live `kh run` / `kh trace`
- Page sizes: **4 KiB** (containers) and **16 KiB** (Asahi-class)
- Optional: `curl`/`wget` + `tar` for `kh install 7zip`

## Install (global, updatable)

```bash
# Once packages are on crates.io:
cargo install kakehashi

# From a git checkout (dev):
cargo install --path crates/kh-cli

# Update later:
cargo install kakehashi --force
```

Then prepare a bottle (macOS-like root) and optional tools:

```bash
# Freestanding libSystem (build on macOS / cross target, ship with your release):
cargo build -p kh-libsystem --release --target aarch64-apple-darwin
./scripts/stage-libsystem.sh   # → dist/guest/libSystem.B.dylib

kh bottle ensure --libsystem dist/guest/libSystem.B.dylib

# Optional: install Darwin 7-Zip into the bottle at a *real* macOS path
kh install 7zip
# → guest /usr/local/bin/7zz  =  {bottle}/usr/local/bin/7zz

kh run 7zz -- a /tmp/demo.7z ./README.md
# same as:
kh run /usr/local/bin/7zz -- a /tmp/demo.7z ./README.md
```

Bottle layout mirrors macOS (`/usr/local/bin`, `/usr/lib`, `/Volumes/linux` → host `/`, …).
Paths under the bottle are guest absolute paths after translation.

| Host (default) | Guest |
| -------------- | ----- |
| `~/.local/share/kakehashi/bottle/` | `/` |
| `…/bottle/usr/local/bin/7zz` | `/usr/local/bin/7zz` |
| `…/bottle/usr/lib/libSystem.B.dylib` | `/usr/lib/libSystem.B.dylib` |
| `…/bottle/Volumes/linux/…` | `/Volumes/linux/…` → host FS |

Override with `KAKEHASHI_DATA_DIR` / `KAKEHASHI_CONFIG_DIR` / `KAKEHASHI_ROOT`.

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
cargo build -p kakehashi --release
cargo test --workspace --exclude kh-libsystem
cargo clippy --workspace --exclude kh-libsystem --all-targets -- -D warnings

# Guest libSystem (on macOS arm64, or with the apple-darwin target available)
cargo build -p kh-libsystem --release --target aarch64-apple-darwin
./scripts/stage-libsystem.sh   # → dist/guest/libSystem.B.dylib
```

### Bottle (macOS-like root for the guest)

```bash
kh bottle ensure --libsystem dist/guest/libSystem.B.dylib
kh bottle status
kh bottle destroy --yes
```

Discovery for `libSystem`: `--libsystem` → `KAKEHASHI_LIBSYSTEM` → paths next
to `kh` → `target/.../libkh_libsystem.dylib` → `dist/guest/libSystem.B.dylib`.

### Guest tools (`kh install`)

Packages are installed **into the bottle** at conventional macOS locations
(not into a random host cache). List: `kh install list`.

```bash
kh install 7zip          # → /usr/local/bin/7zz in the bottle
kh run 7zz -- …          # PATH-style bare name under the bottle
```

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

### Example guest: 7-Zip

7-Zip is only an **optional** installed tool (first real-world target), not the
product focus.

```bash
kh bottle ensure --libsystem dist/guest/libSystem.B.dylib
kh install 7zip
kh run 7zz -- a /tmp/demo.7z ./README.md
```

**Docker helper** (dev loop):

```bash
./scripts/stage-libsystem.sh
./scripts/docker-7zz.sh a /Volumes/linux/out/demo.7z \
  /Volumes/linux/src/README.md
ls -lh .tmp/kh-out/demo.7z
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

- Freestanding **hypercall** is on by default for the **main** guest thread
  (no `SIGTRAP` on the I/O hot path). Opt out with `KAKEHASHI_HYPERCALL=0`.
- Guest **worker** threads use `svc`→`brk` by default (7zz MT NEON compression
  is green there). Experimental full-worker hypercall:
  `KAKEHASHI_HYPERCALL_WORKERS=1` (still SEGV under `-mmt>1 -mx>0`).
- Worker `pthread_join` completion is published from the **host** stack after
  `bsdthread_terminate`.

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
