# Kakehashi

Userspace **macOS ARM64 → Linux aarch64** translation layer. CLI-first, no JIT,
no instruction emulator.

It loads Darwin Mach-O binaries on Linux, maps a freestanding `libSystem`,
translates BSD syscalls at the guest–host boundary, and runs real tools
natively on aarch64.

| | |
| --- | --- |
| Live execution (`kh run`) | **Linux aarch64** only (bare metal, UTM, Colima/Docker) |
| Dry-load / inspect | Any host (including macOS) |
| Design docs | [`docs/`](docs/README.md) |

## Quick start

```bash
cargo install kakehashi
# or from a checkout:
cargo install --path crates/kh-cli --force

kh bottle ensure
kh install 7zip          # Darwin 7zz
kh install curl          # Darwin curl
kh install xcode-tools   # Apple CLT (git, clang, SDK; public swscan, no Apple ID)
```

Relative paths use the **host CWD** of `kh`. Guest `/Volumes/linux/…` maps to
the host root (`/` → host `/`).

## What works

Verified on **Docker/Colima** and **UTM** (Linux aarch64). Guest code runs as
native ARM64; the runtime only intervenes at syscalls, threads, and faults.

### 7-Zip

```bash
kh run 7zz -- a demo.7z README.md
kh run 7zz -- t demo.7z
# Multi-thread correctness gate:
kh run 7zz -- a -t7z -m0=lzma2 -mx=5 -mmt=4 mt.7z README.md
kh run 7zz -- t mt.7z   # Everything is Ok, exit 0
```

### curl

```bash
kh run curl -- --version
kh run curl -- -sS -o body http://example.com/
kh run curl -- -sS -o https-body https://example.com/
```

Details: [`docs/curl.md`](docs/curl.md).

### Apple git (CLT)

Milestone met (G0–G8): local repos, HTTPS/SSH clone and push, large remotes
(Wine full history, llvm shallow, …).

```bash
kh install xcode-tools
kh run git -- --version
kh run git -- clone --depth 1 https://github.com/octocat/Hello-World.git hw
```

Details: [`docs/git.md`](docs/git.md).

### Apple clang (CLT)

Milestone met (G0–G5 + LTO): `--version`, compile, multi-file link with modern
`ld`, `-flto`, and run of the produced Mach-O under `kh`.

```bash
kh run clang -- --version
kh run clang -- -c hello.c -o hello.o
# Multi-file driver link + run product under kh (see docs/clang.md)
```

Same install as git: `kh install xcode-tools`. Details: [`docs/clang.md`](docs/clang.md).

### Not claimed yet

Full curl feature surface, real Apple Security.framework, git LFS/svn, GUI,
codesign, full macOS app stack. Multi‑GiB monorepo clones under a fixed wall
budget are best-effort. Nested `clang`/`ld` processes still pay a start tax
(process model), not a correctness gap.

## How it works (short)

1. Resolve the **bottle** (guest FS root + freestanding `libSystem.B.dylib`).
2. Load Mach-O + dylibs; bind symbols; wire the BSD hypercall into the runtime.
3. Jump to `LC_MAIN`; guest ARM64 runs natively.
4. Syscalls / helpers / pthread create-exit cross into `kh-runtime` and back.

Not derived from Darling. No proprietary Apple blobs in-tree. Clean-room process:
[`docs/legal-method.md`](docs/legal-method.md).

## Crates

| Crate | Role |
| --- | --- |
| **`kakehashi`** | Binary `kh` (install this) |
| `kh-loader` | Mach-O parse, map, bind, execute |
| `kh-runtime` | Memory, traps, BSD syscalls, bottle, threads; embeds `libSystem.B.dylib` |
| `kh-libsystem` | Freestanding dylib source (`aarch64-apple-darwin` only) |
| `kh-xcrun` | Clean-room guest `xcrun` (CLT helper) |

### `kh-libsystem` layout

Source mirrors Darwin surfaces (single product dylib, not multi-dylib link):

```text
crates/kh-libsystem/src/
  core/           # syscalls, errno, heap, process, host helpers
  dylib/          # libsystem_c, pthread, libcurl, libc++, libz, …
  frameworks/     # CoreFoundation, Security, CoreServices (soft)
```

After freestanding ABI changes:

```bash
cargo build -p kh-libsystem --release --target aarch64-apple-darwin
./scripts/stage-libsystem.sh   # → crates/kh-runtime/resources/libSystem.B.dylib
```

## Requirements

- Rust 1.88+
- **Linux aarch64** for live `kh run` / `kh trace`
- Page sizes: **4 KiB** (containers) and **16 KiB** (Asahi-class)

## Performance (honest)

Guest code runs **natively**. Cost is boundary × crossings (TLS, alt stack,
NEON, dispatch), not an emulator.

Multi-file `7zz` (`mx=5 mmt=4`, ~14.5k files / ~309 MiB) on bare-metal aarch64:
about **×1.24** vs native Linux `7zz`. Nested Apple clang still pays process-start
tax per `-cc1`/`ld` hop; load path has been optimized, wall is not macOS parity.

CI goal is correctness on cheap Linux arm64, not wall-clock parity with macOS.
See [`docs/roadmap.md`](docs/roadmap.md).

## Develop / test

```bash
cargo test --workspace --exclude kh-libsystem
cargo clippy --workspace --exclude kh-libsystem --all-targets -- -D warnings
./scripts/docker-smoke.sh
```

| Goal | Command |
| --- | --- |
| Unit + clippy | `cargo test` / `clippy` (exclude `kh-libsystem`) |
| Docker smoke | `./scripts/docker-smoke.sh` |
| Darwin tools | `./scripts/docker-kh.sh 7zz\|curl\|git\|clang -- …` |
| Stage libSystem | `./scripts/stage-libsystem.sh` |

Artifacts under host `.tmp/` (gitignored). Guest `/Volumes/linux/out/…` maps to
`.tmp/kh-out/` via Docker helpers.

## License

Apache-2.0 — [`LICENSE.txt`](LICENSE.txt), [`NOTICE`](NOTICE).

Contributing: [`CONTRIBUTING.md`](CONTRIBUTING.md). Architecture and milestones:
[`docs/`](docs/README.md).
