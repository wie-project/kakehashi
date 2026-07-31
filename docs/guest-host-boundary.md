# Guest–host boundary

## Overview

Darwin and Linux both use **`TPIDR_EL0`** as the userspace thread pointer.
Guest freestanding TLS and host glibc TLS **cannot share** the register at the
same time. Host Rust and libc MUST NOT run with guest `TPIDR_EL0`.

The production crossing for BSD syscalls is **`kh_hypercall_entry`**: a fixed
AAPCS64 entry that switches to a host alt stack, restores host TLS, dispatches,
then returns to guest with SIMD state restored.

## Roles of the register

| Context | `TPIDR_EL0` | Stack |
| ------- | ----------- | ----- |
| Guest user code | Guest TSD base (`GUEST_TLS_MAGIC` block) | Guest mmap stack |
| Host Rust / glibc | Host glibc TLS (captured at thread prepare) | Host stack or hypercall alt stack |
| Hypercall entry (asm) | Switches guest → host before any host `bl` | Guest prolog frame, then host alt SP |

## Guest TLS layout

Freestanding block (ABI between `kh-libsystem` and `kh-runtime::tls`):

| Offset | Content |
| ------ | ------- |
| 0 | `magic` = `0x4B48_544C_5301` (`"KHTLS\x01"`) |
| 8 | `errno: i32` (`___error` target) |
| 16 | `pthread_self: u64` (optional guest `pthread_t` VA) |
| 24 | `host_tpidr: u64` (**host-owned** A1 mirror) |
| 32 | `alt_top: u64` (**host-owned** A1 mirror) |

`___error` MUST return a **per-thread** cell via this block, never a process-global
static (MT data race). Host mirrors MUST only be written while host TPIDR is live
(or with raw stores that do not use host TLS). Fast hypercall enter MUST validate
`magic` before reading offsets 24/32 — never treat host glibc TLS as a guest block.

## Host meta and `host_slot`

`prepare_host_meta` captures host `TPIDR_EL0` **before** any guest `msr`.
Storage is **`host_slot`** (gettid-keyed map) for prepare / slow path, **plus**
A1 mirrors in the guest TLS block for the hypercall hot path. **Not** host
`thread_local!` under guest TPIDR.

**Perf note:** hot enter reads guest-TLS mirrors (no gettid). Leave restores the
parked guest VA from the hypercall frame (no gettid). Slow path (no mirror /
bad magic) uses gettid+map (A2). Full NEON save/restore remains.
Ideas / order: [roadmap.md](roadmap.md).

Exported C entry points used from asm:

| Symbol | Role |
| ------ | ---- |
| `kh_tls_enter_host` | restore host TPIDR; return `{alt_top:x0, guest_tpidr:x1}` |
| `kh_tls_leave_host` | `x0` = guest TPIDR to restore (`0` → map fallback) |
| `kh_host_alt_sp` | alt top only (cold paths / tests) |

## Hypercall ABI

### Guest thin call (`kh-libsystem`)

```text
x0…x6 = args
x7    = Darwin BSD syscall number
blr   _kh_bsd_hypercall   // patched to kh_hypercall_entry
→ HyperRet { retval: x0, error: x1 }
```

Loader patches the freestanding export `_kh_bsd_hypercall` / `kh_bsd_hypercall`
to `hypercall_entry_addr()` when `KAKEHASHI_HYPERCALL` is enabled (default).

### Host entry (`kh_hypercall_entry`)

Normative sequence:

1. **Guest prolog** on guest SP: save frame (`x29`/`x30`), args, **full Q0–Q31**,
   FPCR/FPSR. No host `bl` before NEON save (AAPCS64 clobbers caller-saved SIMD).
2. `bl kh_tls_enter_host` — host TPIDR before any host allocation.
3. `bl kh_host_alt_sp` — host private stack top.
4. Switch `sp` to host alt; keep guest frame pointer on host stack.
5. Reload args; `bl kh_neon_tramp_entry` → mapped `TRAMP_BYTES` (second full NEON
   save, `blr` Rust, restore, NZCV carry) → dispatch.
6. Preserve `TrampRet` across `kh_tls_leave_host`.
7. Restore guest SP; restore NEON/FP from prolog; `ret` to guest.

A former opt-in "light" path (skip second NEON tramp) showed **no wall win** on
UTM 8k-file and was **removed** — one production path only. Freestanding
`hypercall_thin` still lists all NEON as clobbered so guest LLVM never keeps
live SIMD across `blr`.

### Host alt stack

| Property | Value |
| -------- | ----- |
| Size | 512 KiB per OS thread |
| Mapping | Anonymous private; prefer raw `SYS_mmap` when cold-mapping |
| Lifetime | Until worker exit / process end |
| Prealloc | Main: at main guest TLS install; Worker: in `guest_worker_main` before jump |

Fallback “dispatch on guest stack when alt map fails” is ST-only. For MT,
alt stack MUST be available before guest entry.

### NEON

Darwin `svc` preserves SIMD. Compression workers (7zz LZMA) keep live NEON
across syscalls. The hypercall prolog MUST save/restore **all** Q0–Q31 and
FPCR/FPSR. Partial save is a correctness bug under `-mmt>1`.

## SIGTRAP path

When hypercall is off or an `svc` site is patched to `brk`:

1. Kernel delivers `SIGTRAP` with full `ucontext` (register restore on return).
2. Handler restores host TLS, translates syscall, updates `ucontext`.
3. `bsdthread_terminate` redirects PC/SP/`x29` to the host worker-exit trampoline.

Use for debug and fallback. Production multi-thread path is hypercall.

## Fault handling

`SIGSEGV` / `SIGBUS` handler:

1. Enter host TLS (may run under guest TPIDR).
2. Print PC, fault address, SP, LR, selected regs.
3. Best-effort `/proc/self/maps` lines for PC / addr / LR.
4. `_exit(128 + signo)`.

A fault PC inside **host** `libgcc_s` during worker exit is a strong signal of
illegal `pthread_exit` / forced unwind (see [Threading](threading.md#worker-teardown)),
not of a random guest bug.

## Environment

| Variable | Default | Meaning |
| -------- | ------- | ------- |
| `KAKEHASHI_HYPERCALL` | on | Wire freestanding hypercall pointer |
| `KAKEHASHI_HYPERCALL=0` | — | Force SIGTRAP/svc path |
| `KAKEHASHI_FUTEX_STATS` | **off** | Print guest `KH_HELPER_PARK`/`WAKE` counters at exit |
| `KAKEHASHI_TRAMPOLINE` | off | Experimental svc→veneer rewrite (separate from freestanding hypercall) |

### B1 bottle dirfd (path walk)

When a bottle root is set, the host keeps an `O_DIRECTORY` fd and absolute guest
paths use `openat`/`fstatat`/`faccessat` with a **relative** suffix (no
`PathBuf` join of `{root}/{rel}` on the hot path). Fallback remains full
`translate_path` + `open` for relative paths, slow-path `..`, or missing dirfd.
UTM 8k: no measurable wall win vs post-F1c (boundary tax dominates PathBuf).

## Related documents

- [Threading](threading.md)
- [Invariants](invariants.md)
- [Architecture](architecture.md)
