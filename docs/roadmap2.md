# Optimization options (roadmap2)

Catalog of ways to speed up **guest execution** under Kakehashi. Complements
[`roadmap.md`](roadmap.md) (what already shipped / failed) and does **not**
replace product work (git, surface expansion).

Safety rules: [`invariants.md`](invariants.md). Boundary model:
[`guest-host-boundary.md`](guest-host-boundary.md). Multi-thread gate:
`7zz a -t7z -m0=lzma2 -mx=5 -mmt=4` then `7zz t` with hypercall default.

## Context (why this list looks the way it does)

| Fact                                                                                                              | Implication                                                                                          |
| ----------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| Guest ARM64 runs **natively** (no instruction emulator / JIT)                                                     | Wall time is not “emulation tax”; it is **boundary × crossings** + real work (LZMA, crypto, network) |
| Production entry is freestanding **hypercall** (TLS switch, host alt stack, full Q0–Q31 twice, Rust dispatch)     | Each BSD syscall / helper pays a fixed floor of hundreds–thousands of ns                             |
| UTM multi-file `7zz` (~8k files / ~240 MiB, `mx=5 mmt=4`) ≈ **×5.2** vs native Linux `7zz`                        | Dominated by **path walk + per-syscall boundary**, not “wrong LZMA”                                  |
| Compression-heavy, few-file samples often ≈ **×1.1–1.2**                                                          | Micro-opts on the trampoline alone will not fix the multi-file gap                                   |
| Roadmap already forbids more micro-opts on 8k **without reducing crossings or cheapening the boundary by design** | Prefer **fewer hypercalls** over shaving a few stores off the entry asm                              |

### Already done (do not re-litigate)

| Item                                                         | Notes                                  |
| ------------------------------------------------------------ | -------------------------------------- |
| Hypercall for main + workers                                 | Default production path                |
| Full NEON save (prolog + tramp)                              | Light skip tried; no wall win; MT risk |
| A1/A2 TLS mirrors                                            | Hot enter without gettid               |
| Lock-free FD map; no process lock on read/write/pread/pwrite | Architecture invariant 18              |
| Direct host I/O into identity-mapped guest buffers           | No intermediate `Vec` copy             |
| Registry last-hit cache for `check_range`                    | Sequential I/O                         |
| Bottle dirfd + `openat` relative (B1)                        | Hygiene; little wall win after F1c     |
| Contended-bit futex mutex / cond (F1/F1c)                    | Large MT lock win already banked       |
| Batch bind/rebase mprotect (A5)                              | Load-time only                         |
| Release: LTO, `codegen-units=1`, strip                       | Host binary already tuned              |

### Failed / forbidden prototypes (do not re-land as production)

See [`roadmap.md`](roadmap.md#failed-prototypes-do-not-re-land). Especially:
light NEON skip, dual main/worker entry modes, `thread_local!` under guest
TPIDR, host dispatch on guest stack, `pthread_exit` worker end.

---

## Tier 1 — Safe, largest expected gain

Safe = preserves invariants, single production BSD entry, full NEON, host alt
stack, `check_range` on guest buffers, MT gate required. “Largest” means
**can cut multi-file / chatty workloads by a meaningful fraction of the ×5
gap** (often by **reducing crossing count**, not by 2% trampoline polish).

| ID     | Idea                                                       | Why large                                                                                                                                                                                                                                                                                                           | Touch points                                                                                                             | Risk notes (still “safe” if done carefully)                                                                                                                          |
| ------ | ---------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **S1** | **Bulk directory enumeration**                             | Today each guest `readdir` → one `KH_HELPER_READDIR` → full hypercall. An 8k-file tree is O(files) crossings for names alone, plus open/stat. Fill a guest buffer with **N** entries per helper (getdents-style / `readdir` batch)                                                                                  | `kh-libsystem` `posix.rs` (`readdir` / new `getdirentries`), `syscall/helpers.rs`, `process` dir streams, `host` readdir | ABI must stay Darwin-shaped for apps that use libc `readdir`; keep one-entry path as fallback                                                                        |
| **S2** | **Guest-side pure trivial syscalls**                       | `getpid` / `getppid` / `getuid` / `geteuid` / `getgid` / `getegid` / `issetugid` still cross into host Rust for values that are process-constant (or 0). Cache once at start in freestanding or guest TLS; **no hypercall** on the hot path                                                                         | `kh-libsystem` thin wrappers, seed from host once at load / first call                                                   | Fork/exec must refresh pid/ppid; document that values are host process IDs (current behavior)                                                                        |
| **S3** | **Path-walk amortisation for open/stat**                   | Multi-file archive pays path translate + CString + openat/stat per name. Cache last-hit **guest path → (dirfd, rel / host fd / inode meta)** with invalidation on chdir/unlink/rename; optional short-lived dentry cache for repeated prefix walks                                                                  | `bottle/path.rs`, `syscall/fd.rs`, `syscall/fs.rs`                                                                       | Must not violate bottle escape rules; invalidate on mutating FS ops; MT: prefer thread-local last-hit + careful shared prefix cache                                  |
| **S4** | **Batch / combine FS metadata helpers**                    | Guests often `stat` + `open` or `lstat` chains per file. A host helper that returns Darwin-shaped `stat` + optional open in **one** crossing (or `fstatat` bulk for a name list under one dirfd) cuts walk cost without changing guest app code if wired through freestanding libc                                  | `helpers.rs`, freestanding posix wrappers used by archive tools                                                          | Prefer freestanding-only APIs first so third-party binaries still work; optional interposition later                                                                 |
| **S5** | **Dedicated mini-entry for park/wake only (design-level)** | `KH_HELPER_PARK` / `WAKE` are extremely hot under MT locks/heap. Full hypercall (double NEON + Rust) is overkill for futex wait/wake. A **narrow asm path**: validate u32 addr, FUTEX_WAIT/WAKE, return — still host TPIDR + alt stack or proven-safe host stack, still full NEON if any host `bl` can clobber SIMD | New asm next to `kh_hypercall_entry`, freestanding `helper2` branch, `helpers` park/wake                                 | **Not** a second general BSD path (invariant 7). Measure wall on `7zz -mmt=4`; if NEON still required around any host call, keep full save. Gate: MT create+test ≥2× |

**Recommended order for Tier 1:** S1 → S3 → S2 → S4 → S5 (S5 last because boundary-adjacent).

**How to prove a win:** fair multi-file tree (not virtiofs noise); strace/`KAKEHASHI_FUTEX_STATS` / optional future `KAKEHASHI_BOUNDARY_STATS` counting hypercalls by number; wall ratio vs native Linux `7zz` on the same tree.

---

## Tier 2 — Safe, smaller expected gain

Useful hygiene and constant-factor wins. Unlikely alone to move ×5.2 → ×2 on
the 8k multi-file plateaus; still worth doing when touching adjacent code.

| ID      | Idea                                                                                    | Expected impact                                                                                                | Touch points                            |
| ------- | --------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------- |
| **S6**  | **Syscall dispatch jump table / denser hot numbers**                                    | Small CPU in Rust match; already partially hot-path first                                                      | `syscall/mod.rs`                        |
| **S7**  | **Cheaper `check_range` miss path**                                                     | Fewer Arc walks when last-hit misses; larger TL last-hit window; snap as denser structure                      | `mem/registry.rs`                       |
| **S8**  | **Avoid alloc on open/stat hot path**                                                   | Stack buffer / small-string path for short guest paths; reuse CString patterns                                 | `fd.rs`, `fs.rs`, `bottle/path.rs`      |
| **S9**  | **NEON/vector freestanding `memcpy` / `memcmp` / `memset` / `bzero`**                   | Guest-native only; helps compression/crypto buffer work slightly; no boundary                                  | `kh-libsystem` `string.rs` / `stdio.rs` |
| **S10** | **Heap freelist / size-class tuning**                                                   | Arena is already 64 MiB; size classes or segregate small chunks reduce free-list scans and park on `HEAP_LOCK` | `kh-libsystem` `heap.rs`                |
| **S11** | **Reduce process lock on readdir stream map**                                           | `readdir_next` uses `with_mut`; per-FD stream slots could be more concurrent                                   | `process.rs`, `helpers` readdir         |
| **S12** | **Quiet production tracing on I/O**                                                     | Ensure `debug!` on read/write never enabled in release default; avoid string format on failure-only paths      | `io.rs`, `fd.rs`                        |
| **S13** | **Loader: skip residual `svc`→`brk` scan when fully hypercall-wired freestanding-only** | Load-time only                                                                                                 | `trap.rs`, `execute.rs`                 |
| **S14** | **Larger/smarter guest stdio buffering**                                                | Fewer write/read syscalls for line-oriented CLI                                                                | `kh-libsystem` `stdio.rs`               |
| **S15** | **Clock: cache coarse time in guest with refresh period**                               | Cuts `gettimeofday` / `clock_gettime` chatter for apps that poll time                                          | freestanding + optional host seed       |
| **S16** | **Bench / counters infrastructure**                                                     | `KAKEHASHI_BOUNDARY_STATS` (count by syscall/helper); keeps future PRs honest                                  | `trap` / `dispatch`, README / scripts   |

Release profile (`lto`, single CGU, strip) is already applied — no further
profile knobs listed here unless measuring LTO thin vs fat on build times.

## Implementation process (if picking work from this doc)

### MAY

1. One logical change per PR; note `docker-7zz` / bare-metal `mmt=4` in the description.
2. Default-off counters for new paths (`KAKEHASHI_*_STATS`).
3. Optimize freely **while host TPIDR is live**.
4. Stage freestanding ABI into `crates/kh-runtime/resources/libSystem.B.dylib`.

### MUST NOT

1. Re-land failed prototypes from [`roadmap.md`](roadmap.md).
2. Land perf PRs that only pass `-mmt=1` or `7zz -- i`.
3. Claim wall wins without a comparable native baseline (same tree, same disk class).
4. Widen `unsafe` into CLI/loader for TPIDR/register control.

### Perf PR checklist

- [ ] `cargo test -p kh-runtime --lib` (workspace if loader/cli touched)
- [ ] `KAKEHASHI_HYPERCALL=1` `7zz a -mx=5 -mmt=4` → Ok; `7zz t` → Ok
- [ ] Repeat MT create ≥2 times
- [ ] Stage dylib if freestanding ABI changed
- [ ] Bare-metal note if only Docker was used
- [ ] strace/perf/boundary-stats snippet only if claiming a wall win

---

## Suggested first slice (after product priorities)

If performance is prioritized over new guest surface:

1. **S1 bulk readdir** + counter of helper calls before/after on an 8k tree.
2. **S3 path last-hit cache** on open/stat.
3. **S2 pure getpid/uid family** (small, easy win, unblocks measuring “true” FS-bound residual).
4. Only then design **S5** park/wake mini-entry with a full design note against invariants 12–16.

Product roadmap (curl done, git in progress) remains higher priority for
shipping value unless a specific CI job is boundary-bound; see root README
economics: ×5 on Linux arm64 can still beat macOS runner cost.

---

## References

- [`roadmap.md`](roadmap.md) — status, completed work, failed prototypes
- [`architecture.md`](architecture.md) — pipeline, memory, hypercall
- [`guest-host-boundary.md`](guest-host-boundary.md) — TPIDR, NEON, alt stack
- [`invariants.md`](invariants.md) — MUST / MUST NOT
- [`threading.md`](threading.md) — join and worker teardown
- Root [`README.md`](../README.md#performance-honest) — measured gap and CI framing
- Code: `crates/kh-runtime/src/trap.rs` (hypercall), `syscall/*`, `mem/registry.rs`,
  `bottle/path.rs`, `crates/kh-libsystem/src/{sys,posix,heap,pthread}.rs`
