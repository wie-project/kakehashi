# Architecture

## Overview

Kakehashi is a **userspace** translator that runs **Darwin Mach-O arm64** guests
on **Linux aarch64**. Guest code executes **natively** on the CPU (no JIT, no
instruction emulator). The runtime intervenes only at defined boundaries:
syscalls, helpers, thread create/terminate, and faults.

Primary product surface is the CLI binary `kh` (`kakehashi` crate). Live
execution requires Linux aarch64 (bare metal, VM, or Colima/Docker). Parse and
dry-load work on other hosts.

## Design goals

| Goal | Implication |
| ---- | ----------- |
| Native execution | Guest ARM64 runs as ordinary user code in the host process address space |
| CLI-first | Blocking I/O and process-attached main thread are acceptable |
| 1:1 threads | One guest pthread maps to one host OS thread |
| Freestanding libSystem | Bottle ships a clean-room dylib, not Apple’s proprietary libraries |
| No Darling GPL | Spec from public Darwin interfaces; no GPL-3.0 Darling code |

## Crate graph

```
kh-cli (kakehashi)     CLI: run, trace, bottle, install, inspect
        │
        ├── kh-loader  Mach-O parse, map, bind, LC_MAIN entry
        │
        └── kh-runtime Memory, traps, BSD syscalls, bottle, threads
                    │
                    └── resources/libSystem.B.dylib  (embedded; staged from kh-libsystem)

kh-libsystem           Freestanding Darwin-facing C ABI (build: aarch64-apple-darwin only)
```

| Crate | Responsibility |
| ----- | ---------------- |
| `kakehashi` / `kh-cli` | User commands; process lifecycle |
| `kh-loader` | Image load, fixups, symbol bind, execute session |
| `kh-runtime` | Guest memory registry, trap/hypercall, syscall table, bottle FS, threads/TLS |
| `kh-libsystem` | Guest-visible `libSystem.B.dylib` sources (pthread, errno, heap, thin syscalls) |

**Dependency rule:** `kh-runtime` MUST NOT depend on `kh-loader` or `kh-cli`.

## Execution pipeline

```
kh run <program> [-- args…]
  1. Resolve bottle root; ensure freestanding libSystem in bottle
  2. Load Mach-O + dependent dylibs into identity-mapped guest VA space
  3. Bind symbols; wire `_kh_bsd_hypercall` → `kh_hypercall_entry` (default)
  4. Install SIGTRAP / fault handlers (fallback / diagnostics)
  5. Prepare main-thread HostMeta + guest TLS (`TPIDR_EL0`)
  6. jump_to_guest(LC_MAIN)   // noreturn on success
       ⇄ hypercall / trap  →  BSD syscall handlers  →  return to guest
       → bsdthread_create    →  N host workers (same boundary)
       → exit / terminate
  7. Teardown maps; process exit code from guest `exit` or fault
```

## Address space

Guest virtual addresses are **identity-mapped** to host pointers: a guest
buffer pointer is a valid host `*mut u8` after range checks.

| Component | Role |
| --------- | ---- |
| `mem::registry` | Process-wide region set; TLS last-hit cache for `check_range` |
| `mem::map` | Host `mmap` / `mprotect` with Darwin prot bits translated |
| Bottle paths | Guest absolute paths under bottle; `/Volumes/linux` → host FS |

I/O hot paths (`read` / `write` / `pread` / `pwrite`) use lock-free FD tables
and direct host libc I/O into checked guest buffers. Global `ProcessState`
locks MUST NOT sit on those hot paths.

## Freestanding libSystem

Source: `crates/kh-libsystem`. Product artifact:

```
crates/kh-runtime/resources/libSystem.B.dylib
```

Staged by `./scripts/stage-libsystem.sh` after:

```bash
cargo build -p kh-libsystem --release --target aarch64-apple-darwin
```

The dylib is **embedded** into `kh-runtime` (`include_bytes!`) for crates.io.
There is no production dependency on a `dist/guest` tree; bottle ensure copies
from embed / resources / optional override.

Guest `svc #0x80` is not used when hypercall is wired: freestanding
`syscall7` calls `kh_bsd_hypercall` (thin AAPCS call into host entry).

## Syscall path (summary)

| Mode | Mechanism | Use |
| ---- | --------- | --- |
| Hypercall (default) | Guest `bl` → `kh_hypercall_entry` → host alt stack → dispatch | Production, all threads |
| Residual `svc`→`brk` | Patched leftovers + SIGTRAP handler | Fixtures / debug (`KAKEHASHI_HYPERCALL=0`) |

See [Guest–host boundary](guest-host-boundary.md) for the full protocol.

## Bottle layout

A bottle is a macOS-like root on the host filesystem.

| Host (default) | Guest |
| -------------- | ----- |
| `~/.local/share/kakehashi/bottle/` | `/` |
| `…/usr/lib/libSystem.B.dylib` | `/usr/lib/libSystem.B.dylib` |
| `…/usr/local/bin/7zz` | `/usr/local/bin/7zz` |
| `…/Volumes/linux/…` | `/Volumes/linux/…` → host `/…` |

Config: `KAKEHASHI_DATA_DIR`, `KAKEHASHI_CONFIG_DIR`, `KAKEHASHI_ROOT`.

## Safety and `unsafe`

Workspace lint: `unsafe` denied by default. Allowed only in scoped
`kh-runtime` modules (`cpu`, `host`, `host_slot`, `mem/*`, `trap`, `entry`,
`thread`, `tls`, …). Every block requires a `// SAFETY:` invariant comment.

Register and stack discipline is documented in [Invariants](invariants.md).

## Testing map

| Gate | Command / note |
| ---- | -------------- |
| Unit + clippy | `cargo test/clippy --workspace --exclude kh-libsystem` |
| libSystem | Rebuild + `stage-libsystem.sh` after ABI changes |
| Docker smoke | `./scripts/docker-smoke.sh` |
| 7zz multi-thread | `./scripts/docker-7zz.sh` with `-mmt>1` (see [Threading](threading.md)) |

Bench and durable guest output should land under host `.tmp/` (or
`KH_OUT` → guest `/Volumes/linux/out`), not ephemeral container `/tmp`.
