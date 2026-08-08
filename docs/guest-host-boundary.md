# Guest–host boundary

## Overview

Darwin and Linux both use **`TPIDR_EL0`** as the userspace thread pointer.
Guest freestanding TLS and host glibc TLS **cannot share** the register.
Host Rust and libc MUST NOT run with guest `TPIDR_EL0`.

Production BSD entry: **`kh_hypercall_entry`** — fixed AAPCS64 entry that
switches to a host alt stack, restores host TLS, dispatches, then returns to
guest with SIMD restored.

## Roles of the register

| Context | `TPIDR_EL0` | Stack |
| --- | --- | --- |
| Guest user code | Guest TSD base (`GUEST_TLS_MAGIC` block) | Guest mmap stack |
| Host Rust / glibc | Host glibc TLS (captured at prepare) | Host stack or hypercall alt stack |
| Hypercall entry (asm) | Switches guest → host before any host `bl` | Guest prolog, then host alt SP |

## Guest TLS layout

ABI between `kh-libsystem` and `kh-runtime::tls`:

| Offset | Content |
| --- | --- |
| 0 | `magic` = `0x4B48_544C_5301` (`"KHTLS\x01"`) |
| 8 | `errno: i32` (`___error` target) |
| 16 | `pthread_self: u64` (optional guest `pthread_t` VA) |
| 24 | `host_tpidr: u64` (**host-owned** hot-path mirror) |
| 32 | `alt_top: u64` (**host-owned** hot-path mirror) |

`___error` MUST return a **per-thread** cell via this block, never a
process-global static. Host mirrors MUST only be written while host TPIDR is
live (or with raw stores that do not use host TLS). Fast enter MUST validate
`magic` before reading offsets 24/32.

## Host meta and `host_slot`

`prepare_host_meta` captures host `TPIDR_EL0` **before** any guest `msr`.
Storage: **`host_slot`** (gettid-keyed map) for prepare / slow path, **plus**
mirrors in the guest TLS block for the hypercall hot path. **Not** host
`thread_local!` under guest TPIDR.

| Symbol | Role |
| --- | --- |
| `kh_tls_enter_host` | restore host TPIDR; return `{alt_top:x0, guest_tpidr:x1}` |
| `kh_tls_leave_host` | `x0` = guest TPIDR to restore (`0` → map fallback) |
| `kh_host_alt_sp` | alt top only (cold paths / tests) |

Hot enter reads guest-TLS mirrors (no gettid). Leave restores the parked guest
VA from the hypercall frame. Slow path uses gettid+map. Full NEON
save/restore remains on every production enter.

## Hypercall ABI

### Guest thin call (`kh-libsystem`)

```text
x0…x6 = args
x7    = Darwin BSD syscall number
blr   _kh_bsd_hypercall   // patched to kh_hypercall_entry
→ HyperRet { retval: x0, error: x1 }
```

Loader always patches `_kh_bsd_hypercall` / `kh_bsd_hypercall` to
`hypercall_entry_addr()` on Linux aarch64 (sole production BSD entry).

### Host entry (`kh_hypercall_entry`)

Normative sequence:

1. **Guest prolog** on guest SP: save frame (`x29`/`x30`), args, **full Q0–Q31**,
   FPCR/FPSR. No host `bl` before NEON save.
2. `bl kh_tls_enter_host` — host TPIDR before any host allocation.
3. Switch `sp` to host alt; keep guest frame pointer on host stack.
4. `bl kh_neon_tramp_entry` → mapped tramp (second full NEON save, `blr` Rust,
   restore, NZCV) → dispatch.
5. Preserve return values across `kh_tls_leave_host`.
6. Restore guest SP; restore NEON/FP from prolog; `ret` to guest.

One production path only. Freestanding `hypercall_thin` lists all NEON as
clobbered so guest LLVM never keeps live SIMD across `blr`.

### Host alt stack

| Property | Value |
| --- | --- |
| Size | 512 KiB per OS thread |
| Mapping | Anonymous private |
| Lifetime | Until worker exit / process end |
| Prealloc | Main: at main guest TLS install; Worker: before jump |

Fallback “dispatch on guest stack when alt map fails” is ST-only. For MT, alt
stack MUST be available before guest entry.

### NEON

Darwin `svc` preserves SIMD. Compression workers keep live NEON across
syscalls. The hypercall prolog MUST save/restore **all** Q0–Q31 and FPCR/FPSR.
Partial save is a correctness bug under `-mmt>1`.

## Residual `svc` / SIGTRAP

Leftover Darwin `svc` sites (fixtures, unpatched stubs — **not** freestanding
libSystem under `kh`) are rewritten to `brk #IMM`:

1. Kernel delivers `SIGTRAP` with full `ucontext`.
2. Handler restores host TLS, translates syscall, updates `ucontext`.
3. `bsdthread_terminate` redirects PC/SP/`x29` to the host worker-exit trampoline.

Production multi-thread path is freestanding hypercall only.
`KAKEHASHI_HYPERCALL=0` is ignored (legacy dig opt-out removed).

## Fault handling

`SIGSEGV` / `SIGBUS` handler:

1. Enter host TLS (may run under guest TPIDR).
2. Print PC, fault address, SP, LR, selected regs.
3. Best-effort `/proc/self/maps` for PC / addr / LR.
4. `_exit(128 + signo)`.

Fault PC inside **host** `libgcc_s` during worker exit signals illegal
`pthread_exit` / forced unwind (see [Threading](threading.md#worker-teardown)).

## Environment

| Variable | Default | Meaning |
| --- | --- | --- |
| `KAKEHASHI_HYPERCALL` | (ignored) | Always wired on Linux aarch64; `=0` logs a deprecation warning |
| `KAKEHASHI_HEAP_STATS` | off | Freestanding heap dump on exit when host env is truthy |
| `KAKEHASHI_FUTEX_STATS` | off | Print guest park/wake counters at exit |
| `KAKEHASHI_BOUNDARY_STATS` | off | Count BSD/helper dispatches at exit (`1`/`on` = counts; `ns`/`time` = counts + host-side ns in `syscall::dispatch`) |
| `KAKEHASHI_BOUNDARY_BENCH_ITERS` | (test default) | Iteration count for host dispatch class microbench (`boundary_bench` / `scripts/bench-boundary-classes.sh`) |
| `KAKEHASHI_LOAD_TIMING` | off | Dump load-path phase wall times to stderr before guest entry (`1`/`on`); see `kh-loader::load_timing` |

### Bottle dirfd

With a bottle root set, absolute guest paths use `openat`/`fstatat` against an
`O_DIRECTORY` bottle fd (relative suffix). Fallback: full `translate_path` for
relative paths, `..`, or missing dirfd.

## Related

- [Threading](threading.md)
- [Invariants](invariants.md)
- [Architecture](architecture.md)
- [Roadmap](roadmap.md) — multi-file ~×1.24 plateau; residual boundary tax
