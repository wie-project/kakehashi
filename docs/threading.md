# Threading

## Overview

Kakehashi uses a **1:1** threading model: each guest `pthread` is backed by one
host OS thread (`std::thread` → Linux pthread). There are no green threads and
no M:N scheduler.

Multi-thread guests (notably 7-Zip `7zz` with `-mmt>1`) depend on a strict
**join protocol** and a **worker teardown** path that never runs host
forced-unwind over guest stack frames.

Primary implementation:

| Side | Files |
| ---- | ----- |
| Guest | `crates/kh-libsystem/src/pthread.rs` |
| Host | `crates/kh-runtime/src/thread.rs` |
| Syscalls | `crates/kh-runtime/src/syscall/thread_sys.rs` |
| Boundary | `crates/kh-runtime/src/trap.rs`, `tls.rs`, `host_slot.rs` |

## Model

```
┌──────────────────────────────────────────────────────────────┐
│ Host OS thread (std::thread / pthread)                       │
│                                                              │
│  Host TLS (glibc)          Guest view                        │
│  TPIDR_EL0 = host          TPIDR_EL0 = guest TSD             │
│  stack: host / alt         stack: guest mmap (4 MiB)         │
│                                                              │
│  host_slot (keyed by gettid) — never Rust thread_local!      │
│    under guest TPIDR: host_tpidr, guest_tpidr, alt stack,    │
│    exit_pc/sp, guest_pthread, guest_tid                      │
└──────────────────────────────────────────────────────────────┘
```

| Concept | Definition |
| ------- | ---------- |
| Main thread | Host thread that enters `LC_MAIN`; not ended via worker exit |
| Worker | Host thread created by `bsdthread_create`; ends on `bsdthread_terminate` |
| Guest stack | Anonymous map owned by freestanding `KhThread`; may be unmapped after join |
| Host alt stack | Per-thread 512 KiB map for hypercall host Rust; not the guest stack |

## Lifecycle

### Registration

Guest `pthread_create` (once per process) calls:

```text
bsdthread_register(kh_pthread_start, …, tsd_offset, …)
```

Runtime stores the trampoline VA and layout hints (`BsdThreadReg`).

### Create

```text
guest pthread_create
  → mmap guest stack (4 MiB)
  → alloc KhThread + GuestTls
  → bsdthread_create(func, arg, stack, pthread, flags)
       host: std::thread::Builder::name("kh-guest").spawn(guest_worker_main)
  → return pthread_t
```

`guest_worker_main` (host):

1. `prepare_host_meta()` — capture host `TPIDR_EL0` into `host_slot`
2. `ensure_host_alt_stack()` — map hypercall stack while host TLS is live
3. Unblock `SIGTRAP` if inherited blocked from a trap context
4. Record **host exit frame** (`exit_pc` = `host_thread_exit`, `exit_sp` on host stack)
5. Optionally `enter_guest_tls` from `KhThread.tsd`
6. `jump_to_guest_args(entry, sp, pthread, port, func, arg)` — noreturn

### Guest trampoline (`kh_pthread_start`)

```text
result = user_func(arg)
store result into KhThread   // NOT done
bsdthread_terminate(…)
  → runtime: leave guest stack → publish done → end host thread
```

### Join protocol (ABI)

Shared layout (`KhThread`, freestanding ↔ host):

| Offset | Field | Writer |
| ------ | ----- | ------ |
| 0 | `magic` (`0x4B48_5054_4852_4401`) | guest create |
| 8 | `done: AtomicU32` | **host only**, after leaving guest stack |
| 12 | `detached` | guest |
| 16 | `result` | guest trampoline (before terminate) |
| 56 | `tsd` | guest create; host may install TPIDR |

**Order is mandatory:**

1. Guest stores `result`, then enters `bsdthread_terminate`.
2. Host switches to **host stack** (and host TLS).
3. Host stores `done = 1` and futex-wakes joiners.
4. Guest `pthread_join` observes `done`, then may free/munmap stack and control block.

Publishing `done` from the guest **before** terminate is a **data race** with
join’s stack reclaim while host code may still execute on that stack
(historically intermittent SEGV under `7zz -mmt>1` with freestanding hypercall).

## Worker teardown

### Required path

```text
bsdthread_terminate
  → TrapOutcome::ThreadExit / exit_current_guest_worker
  → exit_worker_now:
       mov sp, host_exit_sp
       mov x29, xzr          // clear guest FP chain
       br host_thread_exit
  → finish_worker_on_host:
       clear guest TLS (host TPIDR)
       publish done + futex wake
       drop host alt stack; clear host_slot
       LIVE_WORKERS--
       syscall(SYS_exit, 0)  // this thread only
```

SIGTRAP path: rewrite `ucontext` PC/SP (and `x29 = 0`) to the same host exit
trampoline, then return from the signal handler.

### Why not `pthread_exit`

glibc `pthread_exit` runs **`_Unwind_ForcedUnwind`** (libgcc / libunwind) to
invoke cleanup handlers. After a hypercall or guest jump, **frame pointer
`x29` still points into guest or hypercall frames**. The DWARF walker follows
that chain and faults inside host `libgcc_s.so.1` (historically stable PC
offset ~`0xe320`, LR ~`0xe2b8`, stack: `_Unwind_ForcedUnwind` ←
`__pthread_unwind` ← `pthread_exit` ← `finish_worker_on_host`).

**MUST** end the worker with raw Linux **`SYS_exit`** (exit *thread*, not
`exit_group` / process `exit`). That skips forced unwind.

**MUST** clear `x29` when switching to the host exit frame.

**MUST NOT** “fix” teardown by restoring `pthread_exit` without a proven
unwinder-safe host-only stack and CFI chain.

### Main thread

Main does **not** use worker exit. Guest `exit` ends the process
(`finish_with_exit_code` / `_exit`).

## Host-side state (`host_slot`)

Under guest `TPIDR_EL0`, Rust `thread_local!` and glibc TLS are unusable.
All per-OS-thread runtime state is stored in `host_slot`, keyed by
`gettid` (Linux) / `pthread_self` (elsewhere).

| Slot field | Purpose |
| ---------- | ------- |
| `host_tpidr` / `guest_tpidr` | Save/restore for boundary |
| `alt` | Hypercall host stack map |
| `exit_pc` / `exit_sp` / `has_exit` | Worker landing pad |
| `guest_pthread` / `guest_tid` | Join publish / `thread_selfid` |

Hot path under guest TPIDR MUST NOT allocate into the slot map (insert only
while host TPIDR is live).

## Synchronization (guest)

Guest mutex/cond use host futex helpers (`KH_HELPER_PARK` / `KH_HELPER_WAKE`)
with short spin then park. Mutex is a 0/1/2 futex word: unlock wakes only when
the lock was contended (`2`). Do not reintroduce yield-SVC storms for locks.

## Environment

| Variable | Effect |
| -------- | ------ |
| `KAKEHASHI_HYPERCALL=0` | Disable freestanding hypercall wire-up; workers use patched `brk`/SIGTRAP |
| (default) | Hypercall ON for all threads when `_kh_bsd_hypercall` is patched |

Hypercall is the production path for workers. Dual-path “workers only on
SIGTRAP” is legacy; do not reintroduce it as the default.

## Acceptance (multi-thread)

On Linux aarch64 (or `./scripts/docker-7zz.sh`):

```text
7zz a -t7z -m0=lzma2 -mx=5 -mmt=4 <archive> <inputs…>   → exit 0
7zz t <archive>                                          → Everything is Ok
7zz x -o<dir> <archive>                                  → bit-identical extract
```

Stress variants: `-mx=9 -mmt=4`, many small files, archive of a directory tree.

## Related documents

- [Guest–host boundary](guest-host-boundary.md) — hypercall, TPIDR, NEON
- [Invariants](invariants.md) — condensed MUST / MUST NOT list
- [Architecture](architecture.md) — crate and pipeline context
