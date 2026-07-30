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

`___error` MUST return a **per-thread** cell via this block, never a process-global
static (MT data race).

## Host meta and `host_slot`

`prepare_host_meta` captures host `TPIDR_EL0` **before** any guest `msr`.
Storage is **`host_slot`** (gettid-keyed map), **not** `thread_local!`, because
the first boundary instruction may already run under guest TPIDR.

Exported C entry points used from asm:

| Symbol | Role |
| ------ | ---- |
| `kh_tls_enter_host` | `mrs` guest; restore host TPIDR |
| `kh_tls_leave_host` | restore guest TPIDR |
| `kh_host_alt_sp` | return top of per-thread host alt stack |

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
5. Reload args; `bl kh_neon_tramp_entry` → mapped trampoline →
   `kh_trampoline_dispatch` (Rust syscall handlers).
6. Preserve `TrampRet` across `kh_tls_leave_host`.
7. Restore guest SP; restore NEON/FP from prolog; `ret` to guest.

Mapped trampoline (`TRAMP_BYTES`) also saves GPRs/NEON around the Rust call and
sets Darwin **carry** in NZCV from the error flag (belt-and-braces for paths
that observe NZCV). Freestanding libSystem primarily uses `HyperRet.error`.

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
| `KAKEHASHI_TRAMPOLINE` | off | Experimental svc→veneer rewrite (separate from freestanding hypercall) |

## Related documents

- [Threading](threading.md)
- [Invariants](invariants.md)
- [Architecture](architecture.md)
