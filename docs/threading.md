# Threading

## Overview

**1:1** model: each guest `pthread` is one host OS thread (`std::thread` →
Linux pthread). No green threads, no M:N scheduler.

Multi-thread guests (notably `7zz -mmt>1`) require a strict **join protocol**
and a **worker teardown** path that never runs host forced-unwind over guest
frames.

| Side | Files |
| --- | --- |
| Guest | `crates/kh-libsystem/src/dylib/libsystem_pthread/` |
| Host | `crates/kh-runtime/src/thread.rs` |
| Syscalls | `crates/kh-runtime/src/syscall/thread_sys.rs` |
| Boundary | `crates/kh-runtime/src/trap.rs`, `tls.rs`, `host_slot.rs` |

## Model

```
Host OS thread (std::thread / pthread)

  Host TLS (glibc)              Guest view
  TPIDR_EL0 = host              TPIDR_EL0 = guest TSD
  stack: host / alt             stack: guest mmap (4 MiB)

  host_slot (keyed by gettid) — never Rust thread_local! under guest TPIDR
```

| Concept | Definition |
| --- | --- |
| Main thread | Host thread that enters `LC_MAIN`; not ended via worker exit |
| Worker | Host thread from `bsdthread_create`; ends on `bsdthread_terminate` |
| Guest stack | Anonymous map owned by freestanding `KhThread`; unmapped after join |
| Host alt stack | Per-thread 512 KiB map for hypercall host Rust |

## Lifecycle

### Registration

Guest `pthread_create` (once per process) calls
`bsdthread_register(kh_pthread_start, …)`. Runtime stores trampoline VA and
layout hints.

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
2. `ensure_host_alt_stack()` — while host TLS is live
3. Unblock `SIGTRAP` if inherited blocked
4. Record host exit frame (`exit_pc` = `host_thread_exit`, `exit_sp` on host stack)
5. Optionally `enter_guest_tls` from `KhThread.tsd`
6. `jump_to_guest_args(…)` — noreturn

### Guest trampoline

```text
result = user_func(arg)
store result into KhThread   // NOT done
bsdthread_terminate(…)
  → leave guest stack → publish done → end host thread
```

### Join protocol

Shared `KhThread` layout (freestanding ↔ host):

| Offset | Field | Writer |
| --- | --- | --- |
| 0 | `magic` | guest create |
| 8 | `done: AtomicU32` | **host only**, after leaving guest stack |
| 12 | `detached` | guest |
| 16 | `result` | guest trampoline (before terminate) |
| 56 | `tsd` | guest create; host may install TPIDR |

**Order is mandatory:**

1. Guest stores `result`, then enters `bsdthread_terminate`.
2. Host switches to **host stack** (and host TLS).
3. Host stores `done = 1` and futex-wakes joiners.
4. Guest `pthread_join` observes `done`, then may free/munmap stack and control block.

Publishing `done` from the guest **before** terminate races join’s stack reclaim
while host code may still execute on that stack.

## Worker teardown

### Required path

```text
bsdthread_terminate
  → exit_worker_now:
       mov sp, host_exit_sp
       mov x29, xzr
       br host_thread_exit
  → finish_worker_on_host:
       clear guest TLS (host TPIDR)
       publish done + futex wake
       drop host alt stack; clear host_slot
       LIVE_WORKERS--
       syscall(SYS_exit, 0)   // this thread only
```

SIGTRAP path: rewrite `ucontext` PC/SP and `x29 = 0` to the same host exit
trampoline, then return from the signal handler.

### Why not `pthread_exit`

glibc `pthread_exit` runs **`_Unwind_ForcedUnwind`**. After hypercall or guest
jump, **`x29` still points into guest or hypercall frames**. The DWARF walker
faults inside host `libgcc_s.so.1`.

**MUST** end the worker with raw Linux **`SYS_exit`** (thread exit, not
`exit_group`). **MUST** clear `x29` when switching to the host exit frame.
**MUST NOT** restore `pthread_exit` without a proven unwinder-safe host-only
stack and CFI chain.

### Main thread

Main does not use worker exit. Guest `exit` ends the process.

## Host-side state (`host_slot`)

Under guest `TPIDR_EL0`, Rust `thread_local!` and glibc TLS are unusable.
Per-OS-thread state lives in `host_slot`, keyed by `gettid`.

| Slot field | Purpose |
| --- | --- |
| `host_tpidr` / `guest_tpidr` | Save/restore for boundary |
| `alt` | Hypercall host stack map |
| `exit_pc` / `exit_sp` / `has_exit` | Worker landing pad |
| `guest_pthread` / `guest_tid` | Join publish / `thread_selfid` |

Hot path under guest TPIDR MUST NOT allocate into the slot map (insert only
while host TPIDR is live).

## Synchronization (guest)

Guest mutex/cond use host futex helpers (`KH_HELPER_PARK` / `KH_HELPER_WAKE`):
short spin then park. Mutex is a 0/1/2 futex word (wake only if contended).
Cond is generation + waiter count: bump generation always; `FUTEX_WAKE` only
when waiters > 0; signal wakes one, broadcast wakes all.

Diagnose residual futex traffic:

```bash
KAKEHASHI_FUTEX_STATS=1 kh run 7zz -- a -t7z -m0=lzma2 -mx=5 -mmt=4 …
```

| Bucket | Meaning |
| --- | --- |
| `exp1` high | Bottle dylib pre-dates contended-bit mutex — restage libSystem |
| `exp2` high | Real mutex contention |
| `other` high | Cond park traffic |
| `woken0` ≈ wake total | Empty wakes (stale dylib or lost wake) |

## Environment

| Variable | Effect |
| --- | --- |
| (default) | Hypercall always wired for freestanding libSystem |
| `KAKEHASHI_HYPERCALL=0` | **Ignored** (legacy dig opt-out; residual `svc`→`brk` still for fixtures) |
| `KAKEHASHI_FUTEX_STATS=1` | Park/wake counters on process exit |
| `KAKEHASHI_HEAP_STATS=1` | Freestanding heap dump on exit (host env) |

Hypercall is the only production boundary for freestanding libSystem.

## Acceptance (multi-thread)

```text
7zz a -t7z -m0=lzma2 -mx=5 -mmt=4 <archive> <inputs…>   → exit 0
7zz t <archive>                                          → Everything is Ok
```

## Related

- [Guest–host boundary](guest-host-boundary.md)
- [Invariants](invariants.md)
- [Architecture](architecture.md)
