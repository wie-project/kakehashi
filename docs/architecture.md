# Architecture

Kakehashi is a userspace translator: Darwin Mach-O **arm64 / arm64e** guests run **natively** on Linux aarch64 (no JIT). The runtime intervenes at syscalls, helpers, thread create/exit, and faults. Live `kh run` requires Linux aarch64. Parse and dry-load work on other hosts.

Clean-room: public Darwin headers, man pages, and traces only. No Darling, no XNU copy, no comment scrape from Apple headers. Rules: root [`AGENTS.md`](../AGENTS.md), [`CONTRIBUTING.md`](../CONTRIBUTING.md).

## Crate graph

```
kh-cli (kakehashi)     run, bottle, install
        │
        ├── kh-loader  Mach-O parse, map, bind, LC_MAIN
        │
        └── kh-runtime memory, traps, BSD, bottle, threads
                    │
                    └── resources/libSystem.B.dylib  (embed; staged from kh-libsystem)

kh-libsystem           Freestanding Darwin C ABI (build: aarch64-apple-darwin)
```

`kh-runtime` MUST NOT depend on `kh-loader` or `kh-cli`.

| Crate | Role |
| --- | --- |
| `kakehashi` / `kh-cli` | CLI and process lifecycle |
| `kh-loader` | Load, fixups, bind, execute |
| `kh-runtime` | Maps, hypercall, syscall table, bottle FS, threads/TLS |
| `kh-libsystem` | Guest `libSystem.B.dylib` (pthread, errno, heap, thin sys) |

## Pipeline

```
kh run <program> [-- args…]
  1. Resolve bottle; ensure freestanding libSystem
  2. Map Mach-O + dylibs (identity guest VA)
  3. Bind; wire `_kh_bsd_hypercall` → `kh_hypercall_entry`
  4. SIGTRAP / fault handlers (fallback / diagnostics)
  5. Main-thread HostMeta + guest TLS (`TPIDR_EL0`)
  6. jump_to_guest(LC_MAIN)
       ⇄ hypercall → BSD handlers → guest
       → bsdthread_create → host workers
       → exit
  7. Process status from guest `exit` or fault
```

Guest VA is identity-mapped to host pointers after `check_range`.

| Component | Role |
| --- | --- |
| `mem::registry` | Regions + last-hit `check_range` |
| `mem::map` | `mmap` / `mprotect`; Darwin prot → host |
| Bottle | Guest `/` under bottle; `/Volumes/linux` → host FS |

`read` / `write` / `pread` / `pwrite` are lock-free on the FD table and write directly into checked guest buffers.

## libSystem

Product: `crates/kh-runtime/resources/libSystem.B.dylib`.

```bash
cargo build -p kh-libsystem --release --target aarch64-apple-darwin
./scripts/stage-libsystem.sh
```

Tree mirrors Darwin dylib names (one product dylib):

```text
crates/kh-libsystem/src/
  core/                 sys, errno, heap, helpers
  dylib/                libsystem_c, pthread, libcurl, libcxx, …
  frameworks/           CoreFoundation, Security, …
```

`syscall7` calls `kh_bsd_hypercall`, not `svc #0x80`. Residual `svc` in fixtures is rewritten to `brk`.

## Bottle

| Host (default) | Guest |
| --- | --- |
| `~/.local/share/kakehashi/bottle/` | `/` |
| `…/usr/lib/libSystem.B.dylib` | `/usr/lib/libSystem.B.dylib` |
| `…/Volumes/linux/…` | `/Volumes/linux/…` → host `/…` |

`KAKEHASHI_DATA_DIR`, `KAKEHASHI_CONFIG_DIR`, `KAKEHASHI_ROOT`. Absolute guest paths use `openat` against a bottle dirfd.

## Guest–host boundary

Darwin and Linux both use `TPIDR_EL0`. Guest TLS and host glibc TLS cannot share it. Host Rust/libc MUST NOT run with guest `TPIDR_EL0`.

Production BSD entry: **`kh_hypercall_entry`** — AAPCS64, host alt stack, host TLS, full SIMD save, dispatch, return.

### Guest TLS

| Offset | Content |
| --- | --- |
| 0 | `magic` = `0x4B48_544C_5301` |
| 8 | `errno` (`___error`) |
| 16 | `pthread_self` |
| 24 | `host_tpidr` (host-owned) |
| 32 | `alt_top` (host-owned) |

`___error` is per-thread. Mirrors are written only with host TPIDR live. Fast enter checks `magic` before offsets 24/32.

`prepare_host_meta` captures host `TPIDR_EL0` before any guest `msr`. Storage: `host_slot` (gettid) plus TLS mirrors. Not `thread_local!` under guest TPIDR.

### Hypercall

Guest: `x0…x6` args, `x7` Darwin number, `blr _kh_bsd_hypercall` → `{retval:x0, error:x1}`.

Host sequence:

1. Guest prolog: frame, args, **Q0–Q31**, FPCR/FPSR. No host `bl` before NEON save.
2. `kh_tls_enter_host`
3. Switch to host alt SP
4. Tramp → Rust dispatch
5. `kh_tls_leave_host`, restore guest SP/NEON, `ret`

Alt stack: 512 KiB per OS thread, mapped while host TLS is live. No “dispatch on guest stack” for MT.

`KAKEHASHI_HYPERCALL=0` is ignored.

### Faults

`SIGSEGV` / `SIGBUS`: host TLS, print PC/addr/SP/LR + `/proc/self/maps`, `_exit(128+signo)`. PC in host `libgcc_s` during worker exit means illegal `pthread_exit`.

| Variable | Meaning |
| --- | --- |
| `KAKEHASHI_HEAP_STATS` | Freestanding heap dump on exit |
| `KAKEHASHI_FUTEX_STATS` | Park/wake counters |
| `KAKEHASHI_BOUNDARY_STATS` | Dispatch counts (`ns`/`time` adds host ns) |
| `KAKEHASHI_LOAD_TIMING` | Load-phase times before entry |

## Threading (1:1)

One guest `pthread` = one host OS thread.

| | Path |
| --- | --- |
| Guest | `kh-libsystem` `libsystem_pthread` |
| Host | `kh-runtime` `thread/` |
| Syscalls | `syscall/thread_sys.rs` |

### Create / join

`pthread_create` → mmap 4 MiB guest stack → `bsdthread_create` → `std::thread` named `kh-guest`.

Worker: `prepare_host_meta` → alt stack → record host exit frame → `jump_to_guest_args`.

Trampoline: `result = func(arg)` (not `done`) → `bsdthread_terminate`.

`KhThread`: `done` at +8 is **host-only**, after leaving the guest stack. Order: store result → terminate → host stack/TLS → `done=1` + wake → join may unmap.

### Worker teardown

```text
bsdthread_terminate
  → host_exit_sp, x29=0, br host_thread_exit
  → publish done, drop alt stack, SYS_exit (this thread)
```

**MUST NOT** `pthread_exit`: glibc `_Unwind_ForcedUnwind` walks guest `x29` and faults in `libgcc_s`. **MUST** raw `SYS_exit` and clear `x29`.

Main thread does not use worker exit. Guest `exit` ends the process.

Guest mutex/cond: `KH_HELPER_PARK` / `WAKE`. Mutex 0/1/2 (wake if contended). Cond: generation + waiter count.

## Invariants

Violations have caused MT SEGV / host corruption. Gate: `7zz a -mx=5 -mmt=4` and `t`.

1. 1:1 guest pthread ↔ host thread.
2. Publish `KhThread.done` only from the host, after leaving the guest stack.
3. Do not set `done` in the guest trampoline before terminate returns to host teardown.
4. No host join-publish, `munmap`, or thread exit on a guest stack join may reclaim.
5. Workers end with `SYS_exit`, not `pthread_exit`.
6. Clear `x29` on the host worker-exit frame (and in SIGTRAP `ucontext`).
7. One production BSD path: hypercall. No dual main/worker entries.
8. Capture host `TPIDR_EL0` before any guest `msr` on that thread.
9. Restore host TPIDR before host Rust, glibc, panic, or `tracing`.
10. No `thread_local!` (or host-TLS alloc) under guest TPIDR; use `host_slot`.
11. Per-thread `___error` via guest TLS.
11b. Guest TPIDR only at `call_guest` / `jump_to_guest`; restore host on return.
12. Single production entry: `kh_hypercall_entry`.
13. Full Q0–Q31 + FPCR/FPSR before any host `bl`.
14. Host dispatch on the host alt stack.
15. Pre-map alt stack while host TPIDR is live.
16. No “dispatch on guest stack” as an MT fallback.
17. Guest VA is a host pointer only after `check_range`.
18. No process-global lock on `read`/`write`/`pread`/`pwrite`.
19. Product libSystem is `resources/libSystem.B.dylib`; do not revive `dist/guest`.
20. `unsafe` only in allowlisted `kh-runtime` modules with `// SAFETY:`.
21. Do not widen `unsafe` into CLI/loader for registers/TPIDR.

| Symptom | Actual root |
| --- | --- |
| SEGV in host `libgcc_s` under MT | `pthread_exit` unwind over guest `x29` |
| SEGV after join | `done` too early; join unmaps live stack |
| errno races | process-global `___error` |
| Crash only `-mmt>1 -mx>0` | boundary/teardown, not “compression math” |

## Testing

| Gate | Command |
| --- | --- |
| Unit + clippy | `cargo test/clippy --workspace --exclude kh-libsystem` |
| libSystem | `clippy`/`build` `--target aarch64-apple-darwin`; `stage-libsystem.sh` |
| Docker smoke | `./scripts/docker-smoke.sh` |
| Multi-thread | `./scripts/docker-kh.sh 7zz --` `-mmt=4 -mx=5` then `t` |

Guest output: host `.tmp/` or `KH_OUT` → `/Volumes/linux/out`.

## Code map

| Location | Role |
| --- | --- |
| `kh-runtime/src/thread/` | Host worker spawn / exit |
| `kh-runtime/src/cpu/trap.rs` | Hypercall entry, residual `svc`→`brk` |
| `kh-runtime/src/thread/tls.rs`, `cpu/host_slot.rs` | TLS boundary |
| `kh-libsystem/src/core/sys.rs` | Guest hypercall thin + `SYS_*` |
| `kh-libsystem/src/dylib/libsystem_pthread/` | Guest pthread |
| `kh-loader/src/execute.rs` | Wire hypercall; `dlopen`; arm64e `dlsym` PAC |
