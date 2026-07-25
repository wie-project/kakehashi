# Kakehashi

Userspace **macOS ARM64 → Linux aarch64** translation layer (CLI-first, no JIT).

> Phase 12 (clang ladder): bottle `libSystem` (`_write` / `__exit` / `_puts` /
> minimal `_printf` / `_kh_bottle_mark`); dyld-like `return` from `main`; real
> Apple-clang probes print **hello** under Docker. Phase 11: chained fixups.
> Phase 10: classic bind. Phase 9: DATA rebase. Phase 8: bottle mark (**77**).
> Phase 7: constructors. Phase 6: multi-image. Live on **Linux aarch64**.

## Crates

| Crate        | Role                                                               |
| ------------ | ------------------------------------------------------------------ |
| `kh-cli`       | Binary `kh` — inspect / run / trace / bottle                     |
| `kh-loader`    | Mach-O parse, image plan, map session, micro execute             |
| `kh-runtime`   | Page geometry, guest `mmap`, stack, traps, BSD table, bottle     |
| `kh-libsystem` | Freestanding guest `libSystem.B.dylib` stubs (Apple Darwin only) |

## Requirements

- Rust 1.97+
- **Linux aarch64** (or Colima/Docker aarch64) for live `kh run` / `kh trace`
- `kh inspect` and `kh run --dry-load` work on any host (including macOS)
- Page sizes: **4 KiB** (typical containers) and **16 KiB** (Asahi-class hosts)

## Build

```bash
cargo build -p kh-cli
# Default members only (Linux host / aarch64). Guest libSystem is separate:
cargo test --workspace --exclude kh-libsystem
cargo clippy --workspace --exclude kh-libsystem --all-targets -- -D warnings

# Guest libSystem stubs (macOS arm64 dylib → bottle usr/lib/libSystem.B.dylib):
cargo build -p kh-libsystem --release --target aarch64-apple-darwin
# Optional: stage as libSystem.B.dylib for release trees / explicit --libsystem:
./scripts/stage-libsystem.sh
```

### Bottle + libSystem (two install paths)

`kh bottle create` builds the macOS-like skeleton and, when a source dylib is
found, copies it to `{bottle}/usr/lib/libSystem.B.dylib` (rewriting `LC_ID_DYLIB`
to `/usr/lib/libSystem.B.dylib` if needed — no `install_name_tool` on Linux).

| Path | What you have | What create does |
| ---- | ------------- | ---------------- |
| **From source** | Built `target/.../libkh_libsystem.dylib` + `kh` | Auto-finds Cargo `target/` (cwd) or pass `--libsystem` |
| **From release** | Unpacked `bin/kh` + `lib/kakehashi/libSystem.B.dylib` | Auto-finds dylib next to / relative to `kh` |

Discovery order: `--libsystem` → `KAKEHASHI_LIBSYSTEM` → paths next to the
binary → `target/{release,debug,...}/libkh_libsystem.dylib`. Use
`--skip-libsystem` for a skeleton-only bottle.

```bash
# From source (after both cargo builds):
cargo build -p kh-cli --release          # on Linux aarch64
cargo build -p kh-libsystem --release    # on macOS / apple-darwin target
./target/release/kh bottle create        # picks up target/release/libkh_libsystem.dylib

# From a release tarball layout:
#   bin/kh
#   lib/kakehashi/libSystem.B.dylib
./bin/kh bottle create

# Explicit path (either workflow):
./target/debug/kh bottle create --libsystem dist/guest/libSystem.B.dylib
./target/debug/kh bottle create --libsystem tests/fixtures/bottle/usr/lib/libSystem.B.dylib
```

```bash
./target/debug/kh --help
./target/debug/kh inspect --host-page-size
./target/debug/kh inspect tests/fixtures/minimal_arm64_execute.macho
./target/debug/kh inspect tests/fixtures/minimal_arm64_execute.macho --sections --imports --image
./target/debug/kh --json inspect tests/fixtures/minimal_arm64_execute.macho --load-commands

# Map-only (no jump) — any host:
./target/debug/kh run --dry-load tests/fixtures/minimal_arm64_execute.macho
./target/debug/kh --json run --dry-load tests/fixtures/minimal_arm64_execute.macho
# Multi-image dry-load (main + sibling dylib mapped; libSystem skipped:no_bottle):
./target/debug/kh run --dry-load tests/fixtures/call_dylib.macho

# Live micro execution (Linux aarch64 only) — prints "kh" then exits 0:
./target/debug/kh run --expect-code 0 tests/fixtures/minimal_arm64_execute.macho
# Linked call into sibling dylib via GOT — exits 42:
./target/debug/kh run --expect-code 42 tests/fixtures/call_dylib.macho
# Same via chained fixups (modern link layout):
./target/debug/kh run --expect-code 42 tests/fixtures/call_dylib_chained.macho
# Dylib constructor runs before main (prints "ctor"):
./target/debug/kh run --expect-code 0 tests/fixtures/ctor_main.macho
# Guest worker thread (bsdthread_create) writes "T" then main joins (Linux aarch64):
./target/debug/kh run --expect-code 0 tests/fixtures/bsdthread_create_join.macho
# Absolute libSystem via synthetic bottle (maps + GOT call → exit 77):
./target/debug/kh run --dry-load --root tests/fixtures/bottle \
  tests/fixtures/call_libsystem.macho
./target/debug/kh run --expect-code 77 --root tests/fixtures/bottle \
  tests/fixtures/call_libsystem.macho
# Real Apple clang guests via bottle libSystem (Linux aarch64 / Docker for live):
./target/debug/kh run --expect-code 0 --root tests/fixtures/bottle \
  tests/clang-probe/write_exit      # write + _exit → "hello"
./target/debug/kh run --expect-code 0 --root tests/fixtures/bottle \
  tests/clang-probe/return_zero     # return 0 from main (no _exit)
./target/debug/kh run --expect-code 0 --root tests/fixtures/bottle \
  tests/clang-probe/puts_hello      # puts("hello") → "hello"
./target/debug/kh run --expect-code 0 --root tests/fixtures/bottle \
  tests/clang-probe/printf_hello    # printf("hello\n") → "hello"
./target/debug/kh trace --max-events 16 tests/fixtures/minimal_arm64_execute.macho

# Bottle root for path-taking syscalls (open/access) and absolute dylib resolve:
./target/debug/kh run --root /path/to/bottle tests/fixtures/minimal_arm64_execute.macho

# Single managed bottle (skeleton + Volumes/linux → host / + optional libSystem):
./target/debug/kh bottle create                    # default: $XDG_DATA_HOME/kakehashi/bottle
./target/debug/kh bottle create --path /opt/my-b   # custom path (name is free to rename)
./target/debug/kh bottle status
./target/debug/kh bottle destroy                   # interactive y/N
./target/debug/kh bottle destroy --yes             # scripts / CI
# Root resolution for run/trace: --root > KAKEHASHI_ROOT > registered bottle

# Real-world guest: 7-Zip `7zz` (default host path /tmp/7zz, override KAKEHASHI_7ZZ).
# Bottle materialize creates usr/lib/libc++.1.dylib → libSystem.B.dylib so both
# LC_LOAD_DYLIB edges map to the freestanding guest dylib (no separate libc++ crate).
# ./target/debug/kh bottle create
# ./target/debug/kh run --dry-load /tmp/7zz          # map/bind probe (any host)
# ./target/debug/kh trace --max-events 64 /tmp/7zz   # live: Linux aarch64
```

Text `dry-load` output is multi-image (per-image mapped/skipped lines). Prefer
`--json` / `images[]` for scripts.

Regenerate synthetic Mach-O fixtures (`minimal` / `errno` / `mmap` / `roundtrip` / `dylib`):

```bash
cargo run -p kh-loader --example write_fixture
```

## Docker / Colima (4 KiB smoke)

```bash
# Reproducible image (build + clippy + test + dry-load + micro run inside Linux)
docker build -t kakehashi:smoke -f Dockerfile .
docker run --rm kakehashi:smoke
docker run --rm --entrypoint getconf kakehashi:smoke PAGE_SIZE

# Or:
./scripts/docker-smoke.sh

# Dev mount (toolchain only)
docker build -t kakehashi:dev -f Dockerfile.dev .
docker run --rm -v "$PWD":/src -w /src kakehashi:dev \
  cargo test --workspace --exclude kh-libsystem
```

## License

LGPL-3.0-only. See `LICENSE.txt` and `NOTICE`.

This project is **not** derived from Darling. Do not vendor proprietary Apple SDKs or blobs.
