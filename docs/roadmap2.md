# Optimization process (roadmap2)

Strict process for speeding up **guest execution** under Kakehashi. Complements
[`roadmap.md`](roadmap.md) (what already shipped / failed). Does **not** replace
product work (git, surface expansion).

| Normative | Document |
| --- | --- |
| Safety | [`invariants.md`](invariants.md) |
| Boundary | [`guest-host-boundary.md`](guest-host-boundary.md) |
| MT join / teardown | [`threading.md`](threading.md) |
| Status / product priority | [`roadmap.md`](roadmap.md) |

**MT correctness gate (always):**

```text
7zz a -t7z -m0=lzma2 -mx=5 -mmt=4   → Ok
7zz t                                 → Ok
hypercall default; create ≥2 times
```

---

## 0. Why this doc was rewritten

An earlier draft of this file ranked “safe large wins” (bulk readdir, path
caches, park/wake mini-entry, …) and suggested implementing them in a fixed
order. Implementing that stack **in aggregate** regressed wall time and
stability; the work was rolled back.

Root causes of that class of failure:

1. **No mandatory counters** — claims could not prove fewer crossings or a
   cheaper crossing; only “feels faster” or a noisy Docker wall.
2. **Several levers in one branch** — regressions could not be bisected.
3. **Shared caches under MT** — path/dentry maps often thrash on unique names
   and add lock/invalidation cost **above** a plain `openat`.
4. **Boundary-adjacent “mini-entry”** — second production paths have already
   failed (light NEON, dual main/worker entry).
5. **One mixed plate** — 8k-file `mx=5 mmt=4` blends FS chatter, LZMA, and
   park/wake; optimizing the wrong component is easy.

This rewrite is **process-first**. Ideas are secondary and gated.

---

## 1. Physics (do not re-argue)

| Fact | Implication |
| --- | --- |
| Guest ARM64 runs **natively** (no emulator / JIT) | Wall tax = **boundary × crossings** + real guest work |
| Production entry = freestanding **hypercall** (TLS switch, host alt stack, full Q0–Q31 prolog + tramp, Rust dispatch) | Every BSD syscall / helper has a high fixed floor |
| UTM multi-file `7zz` (~14.5k / ~309 MiB, `mx=5 mmt=4`) ≈ **×1.24** vs native Linux `7zz` | Residual ≈ boundary × crossings + real LZMA (post size-class freelist) |
| Historical multi-file was ≈ **×5.2** (~8k / ~240 MiB) | Freestanding first-fit freelist O(n²); **fixed** by size-class LIFO |
| Few-file compression often ≈ **×1.1–1.3** | Multi-file is no longer an outlier order-of-magnitude tax |
| I/O hot path already: lock-free FD, direct host I/O, `check_range` last-hit | Do not “optimize” read/write by adding locks or copies |

### Already banked (do not re-litigate)

| Item | Notes |
| --- | --- |
| Hypercall main + workers | Single production path |
| Full NEON (prolog + tramp) | Light skip: no wall win; MT risk |
| A1/A2 TLS mirrors | Hot enter without gettid |
| Lock-free FD; no process lock on read/write/pread/pwrite | Invariant 18 |
| Direct host I/O into identity-mapped guest buffers | No intermediate `Vec` |
| Registry last-hit for `check_range` | Sequential I/O |
| Bottle dirfd + relative `openat` (B1) | Hygiene; little wall after F1c |
| Contended-bit futex mutex / cond (F1/F1c) | Large MT lock win banked |
| Batch bind/rebase mprotect (A5) | Load-time only |
| Release LTO, `codegen-units=1`, strip | Host binary tuned |
| Freestanding size-class freelist | Multi-file wall ~×5.2 → ~×1.24; plate-A avg_walk ~3000 → ~1–2 |

### Forbidden prototypes (do not re-land)

See [`roadmap.md`](roadmap.md#failed-prototypes-do-not-re-land). Especially:

- light NEON skip / partial Q-save on production entry
- dual production paths (main=hypercall, workers=SIGTRAP, or any second general BSD entry)
- `thread_local!` / host TLS bookkeeping under guest `TPIDR_EL0`
- host dispatch, join-publish, or `munmap` on a guest worker stack
- worker end via `pthread_exit` / dirty `x29`
- shared process-global path/dentry caches without invalidation proof + MT gate

---

## 2. Hard rules (MUST / MUST NOT)

These apply to **every** perf change. Violating any rule is grounds for
**immediate revert**, even if a microbench looks good.

### 2.1 Process

| # | Rule |
| --- | --- |
| P1 | **MUST** land **one logical lever per PR** (one idea, one primary touch area). No “S1+S3+S5” bundles. |
| P2 | **MUST NOT** merge a perf PR without **before/after** numbers for the plate it claims to help (see §3). |
| P3 | **MUST** keep stats / new paths **default-off** unless the feature is pure freestanding guest code with no host map. |
| P4 | **MUST** pass the MT gate (§ top) with hypercall default; create **≥2** times. |
| P5 | **MUST** stage `resources/libSystem.B.dylib` if freestanding ABI changed. |
| P6 | **MUST NOT** claim a wall win without a **comparable native Linux baseline** on the same tree and similar disk class. Note Docker vs bare-metal. |
| P7 | If after merge plate wall **regresses beyond noise** or MT flaky → **revert first**, analyze second. No “fix forward” on boundary. |

### 2.2 Do not make crossings more expensive

A “win” that **reduces count** but **increases cost per remaining cross** often
loses on real trees. Therefore:

| # | Rule |
| --- | --- |
| C1 | **MUST NOT** add process-global locks on paths that were lock-free (read/write/pread/pwrite, and open/stat once they are contended-critical). |
| C2 | **MUST NOT** add a **shared** path → meta / dentry hash map as the first open amortization. Prefer **thread-local last-prefix / last-dirfd** only after M0 proves repeated prefix hits. |
| C3 | **MUST NOT** allocate on the success path of open/stat/readdir **more** than the pre-change path (no extra `PathBuf` clones, no unconditional `Vec` per call “for the cache”). |
| C4 | **MUST NOT** hold `ProcessState` / dir-stream locks across host I/O that can block long **unless** the same lock scope existed before and the PR’s plate still wins. |
| C5 | **MUST NOT** copy guest buffers through intermediate host `Vec` on I/O hot paths (invariant: direct identity-map I/O). |
| C6 | When stats are **disabled**, **MUST** keep the hot path to a single predictable branch (atomic load / `unlikely`) — no format strings, no hash inserts, no TLS that runs under guest TPIDR. |
| C7 | **MUST NOT** increase hypercall prolog work (extra saves, extra `bl`, extra gettid) on the production path. Cheapening the boundary is a separate, high-risk track (§6). |
| C8 | Cache / batch features **MUST** define invalidation (chdir, unlink, rename, close, bottle root change). Stale hits that break escape rules or wrong fd → **forbidden**. |

### 2.3 Boundary and ABI

| # | Rule |
| --- | --- |
| B1 | **MUST** keep a **single** production BSD entry: freestanding hypercall → `kh_hypercall_entry` (invariant 7, 12). |
| B2 | **MUST** full Q0–Q31 + FPCR/FPSR before any host `bl` (invariant 13). |
| B3 | **MUST** host TPIDR + host alt stack for host dispatch (invariants 11b, 14–16). |
| B4 | **MUST NOT** land a park/wake “mini-entry” or any second entry **until** M0+P1 microbenches show park/wake dominate the plate you care about **and** a written design note against invariants 12–16 is reviewed. |
| B5 | Guest-visible Darwin shapes (`dirent`, `stat`, errno/carry) **MUST** remain correct for third-party binaries; freestanding-only shortcuts are allowed only if non-freestanding paths stay correct. |
| B6 | **MUST NOT** drop `check_range` (or equivalent) on guest buffers (invariant 17). |

### 2.4 Definition of “win” (accept / reject)

A PR may claim a performance win only if **all** of the following hold for its
target plate(s):

1. **Wall** (same machine class): improved vs pre-change baseline beyond noise,
   **or** a documented intentional trade (e.g. load-time only) with no wall
   regression on plates A/B/C.
2. **Mechanism** matches the claim:
   - fewer crossings → **boundary stats count** for the targeted
     syscall/helper family decreases; **or**
   - cheaper same count → **host-side time in boundary/dispatch** decreases
     without count tricks; **or**
   - guest-only CPU → plate B improves with **flat** crossing counts.
3. **Stats off** path: wall of plates A/B within noise of pre-PR (no tax when
   counters disabled).
4. **MT gate** green (≥2 creates + test).
5. **No new flaky SEGV/hang** on repeated MT create.

If (1) fails but (2) “looks good” in a microbench → **do not merge**.
If (2) fails (counts up, or cost/cross up with flat wall “maybe”) → **do not merge**.

**Noise guidance:** treat sub‑2% wall on Docker virtiofs as noise unless
repeated ≥3 runs and confirmed bare-metal. Prefer median of ≥3 runs for claims.

---

## 3. Measurement plates (mandatory vocabulary)

Never optimize “the 8k archive” as a single anonymous wall without naming a
plate. Mixed 8k `mx=5 mmt=4` is a **smoke**, not a diagnostic.

| Plate | Intent | Example shape | Isolates |
| --- | --- | --- | --- |
| **A — chatty FS** | Many files, little/no compression | multi-file tree; store / `mx=0` / list+open heavy; or archive create with compression disabled if available | open/stat/readdir/path crossings |
| **B — CPU** | Few large files, compression on | 1–few files, `mx=5`, `mmt=1` | guest LZMA vs boundary |
| **C — MT sync** | Lock/park pressure | `mmt=4`, same as product gate; use `KAKEHASHI_FUTEX_STATS` | park/wake, not open |
| **S — smoke** | Product gate only | `mx=5 mmt=4` multi-file as today | “still works”; **not** sole proof of a lever |

### Native baseline

For any wall claim on A/B/S: run **native Linux `7zz`** (or the same tool) on
the **same tree**, same flags, same host class. Report ratio `kh / native`.

### Counters (M0 — first deliverable)

| Knob | Default | Purpose |
| --- | --- | --- |
| `KAKEHASHI_BOUNDARY_STATS` | **off** | Count hypercall dispatches by Darwin syscall # and `KH_HELPER_*`; dump on exit (stderr). Values: `1`/`on`/`true` = counts; `ns`/`time`/`2` = counts + host-side ns **inside** `syscall::dispatch` (after TLS enter; not full hypercall prolog) |
| `KAKEHASHI_FUTEX_STATS` | off | Already exists; required for plate C claims |

**Implementation:** `crates/kh-runtime/src/syscall/boundary_stats.rs`, hooked from
`dispatch` + `finish_with_exit_code`. Off path: one atomic mode load per
dispatch.

**M0 acceptance:**

- [x] Default off: single mode load; no format/hash on hot path
- [x] When on: ranked dump of top buckets; guest results unchanged
- [x] No `thread_local!` under guest TPIDR; atomics / host-only storage only
- [x] Documented in [`guest-host-boundary.md`](guest-host-boundary.md) env table + this file

**No further perf PR from this roadmap merges until M0 is on the target
branch,** except pure doc fixes. (M0 code lives with this process doc.)

---

## 4. Ordered work (strict sequence)

Do **not** skip ahead because an idea “should be big.” Advance only when the
previous step’s acceptance is met.

### Phase 0 — Observe (blockers)

| ID | Work | Acceptance |
| --- | --- | --- |
| **M0** | `KAKEHASHI_BOUNDARY_STATS` (+ optional ns) | §3 M0 checklist — **implemented** (`boundary_stats.rs`) |
| **P1** | Host **microbench**: N× getpid, open+close, readdir, uncontended park | **implemented** (`boundary_bench.rs`); ranks **dispatch** cost only |
| **P2** | One `perf`/sampling pass on plate A (host `kh`) | % time: hypercall entry vs `openat` vs path translate vs Rust match — written note in PR |

**P1 how to run**

```bash
# Preferred: Linux aarch64 Docker (same image path as docker-kh 7zz)
./scripts/bench-boundary-classes.sh
RELEASE=1 KAKEHASHI_BOUNDARY_BENCH_ITERS=200000 ./scripts/bench-boundary-classes.sh
# Phase A = dispatch ranking; Phase B = real guest + KAKEHASHI_BOUNDARY_STATS dump
GUEST_STATS=0 ./scripts/bench-boundary-classes.sh   # ranking only

# Host-only (no Docker; guest/hypercall may be unavailable off Linux aarch64)
LOCAL=1 ./scripts/bench-boundary-classes.sh
cargo test -p kh-runtime --lib boundary_class_microbench_smoke -- --nocapture
```

Report columns: `ns/iter` and `total_ms` per class, sorted slowest-first.
Phase A **does not** include hypercall prolog (NEON/TLS/alt stack). Phase B
proves M0 dump on the production path; use multi-file plates for real top-N.

**Gate to Phase 1:** M0 + P1 present; record a P1 ranking (or M0 top-N from a
real plate) in the PR that starts Phase 1.

### Phase 1 — Guest-only, zero shared host cache

Low risk. Host syscall handlers unchanged except optional one-shot seed.

| ID | Work | When | Constraints |
| --- | --- | --- | --- |
| **G1** | Cache `getpid` / `getppid` / uid / gid / `issetugid` in guest TLS (seed once) | After M0; always useful to quiet counters | Document host-pid semantics; refresh if fork ever lands |
| **G2** | Coarse guest clock TTL for `gettimeofday` / `clock_gettime` | Only if M0 shows material time chatter | TTL documented; correctness: monotonic coarse OK for non-security apps |
| **G3** | NEON freestanding `memcpy` / `memset` / `memcmp` / `bzero` | Optional; plate B | No boundary change; correctness tests |
| **G4** | Larger guest stdio buffers | Only if M0 shows write/read chatty CLI noise | Do not break 7zz binary semantics |

Phase 1 PRs still need plate smoke + MT gate if freestanding staged; wall claim
optional if goal is counter hygiene only (state so in PR).

### Phase 2 — Fewer FS crossings (one lever)

Pick **exactly one** primary target from M0 top-N on plate A.

| ID | Work | Allowed only if | Hard limits |
| --- | --- | --- | --- |
| **F4** | Avoid alloc on open/stat success path (stack / small buffer) | Always after Phase 0; good warm-up | C3: no extra alloc vs baseline success path |
| **F1\*** | **Thread-local** last-dir / last-prefix → host dirfd | M0 shows repeated **directory** prefix walks | **No** process-wide dentry hash; invalidate on chdir / bottle change / that fd close; miss = old path |
| **F3** | Batch `readdir` / getdents-style: N entries per helper (fixed N ∈ {8,16,32}) | M0 shows `KH_HELPER_READDIR` (or equivalent) in top cost on plate A | Fixed guest layout; **fallback N=1**; short lock; Darwin `readdir` single-entry ABI for apps preserved via freestanding drain; MT gate ×3 creates |
| **F2** | Host-only readdir readahead **without** reducing guest hypercalls | **Do not do** for wall — crossings unchanged; only if profiling shows host `readdir` dominated *inside* one helper | Prefer F3 if crossings dominate |

**Forbidden in Phase 2:**

- shared multi-thread dentry / full-path → inode maps (old S3-style)
- combining F3 + F1\* in one PR
- park/wake mini-entry
- “bulk open+stat for name lists” (old S4) until F3 or F1\* has a measured win and a separate design

**Phase 2 accept:** plate A wall ↓ and targeted helper/syscall counts ↓; plate B
not regressed beyond noise; plate C / MT gate green; stats-off tax ~0.

### Phase 3 — Boundary cheapening (optional, high risk)

| ID | Work | Preconditions |
| --- | --- | --- |
| **S5** | Narrow park/wake entry (or proven equivalent) | (1) Phase 0–2 done or consciously deferred; (2) plate C + futex + boundary stats show park/wake dominate **product** wall; (3) design note vs invariants 12–16; (4) still host TPIDR; full NEON if any host `bl` can clobber SIMD; (5) **not** a second general BSD path |
| **D1** | Dispatch jump table / denser hot numbers | Only with host-side ns or plate proof; never alone as “close ×1.2→×1.0” |
| **D2** | `check_range` miss-path structure | Only if P2 shows miss walks hot |

**Default recommendation:** do **not** start Phase 3 until plate A residual is
understood after Phase 2. Multi-file residual after the freelist fix is usually
**count × boundary floor** + guest work, not park.

### Explicitly deferred / rejected as first moves

| Old roadmap2 ID | Disposition |
| --- | --- |
| S1 bulk readdir | Replaced by **F3** under Phase 2 gates |
| S2 getpid family | **G1** in Phase 1 |
| S3 path cache | **Rejected** as shared map; only **F1\*** TL last-dir |
| S4 batch open+stat | Deferred until after F3/F1\* win |
| S5 mini-entry | Phase 3 only |
| S6–S15 grab-bag | Allowed only as named Phase 1–3 items with plates; no drive-by |

---

## 5. Perf PR checklist (copy into PR body)

```markdown
## Plate
- [ ] Named plate: A / B / C / S (which?)
- [ ] Native baseline (if wall claim): command + wall + ratio

## Process
- [ ] Single logical lever (name: M0 / G1 / F3 / …)
- [ ] Before/after boundary stats (top lines) **or** explicit “guest-only, counts flat”
- [ ] Stats default-off; stats-off wall within noise
- [ ] `cargo test -p kh-runtime --lib` (workspace if loader/cli)
- [ ] MT: `7zz a -mx=5 -mmt=4` Ok; `7zz t` Ok; create ≥2×
- [ ] Staged `libSystem.B.dylib` if freestanding changed
- [ ] Bare-metal note if only Docker measured

## Cost discipline
- [ ] No new process lock on former lock-free I/O
- [ ] No shared dentry/path hash (unless design explicitly approved post–Phase 2)
- [ ] No extra success-path alloc vs baseline (or justified + measured)
- [ ] No heavier hypercall prolog
- [ ] Invalidation rules documented for any cache

## Revert trigger
- [ ] Author agrees: MT flake or plate regression → revert, not pile-on
```

---

## 6. Realistic ceilings

| Workload | Plausible goal | Not a near-term goal |
| --- | --- | --- |
| Few-file compress (B) | hold ~×1.1–1.3 | ×1.0 |
| Multi-file (product / UTM) | hold ~×1.2–1.4; optional F3/F1\* if plate A still chatty | ×1.0 via trampoline polish alone |
| MT locks (C) | F1 already banked; S5 only if residual | “another futex rewrite” without stats |

Product note: ~×1.2 on Linux aarch64 already beats scarce macOS CI cost by a
wide margin (root README). Perf work is optional relative to **git** surface
unless a specific job is boundary-bound.

---

## 7. Suggested next commits (after M0 + P1)

1. ~~**M0** — boundary stats~~ (`syscall/boundary_stats.rs`).
2. ~~**P1** — class microbench~~ (`syscall/boundary_bench.rs`, `scripts/bench-boundary-classes.sh`).
3. Record plate A/B/C with `KAKEHASHI_BOUNDARY_STATS=1` (+ optional `=ns`) and
   paste a P1 ranking into the next perf PR description.
4. **G1** (optional quick) to clean pid noise.
5. **One** of F4 → F1\* or F3 according to M0 top-N — never both.
6. Stop and reassess; only then consider Phase 3.

---

## 8. References

- [`roadmap.md`](roadmap.md) — completed work, failed prototypes, product priority  
- [`architecture.md`](architecture.md) — pipeline, memory, hypercall  
- [`guest-host-boundary.md`](guest-host-boundary.md) — TPIDR, NEON, alt stack  
- [`invariants.md`](invariants.md) — MUST / MUST NOT  
- [`threading.md`](threading.md) — join and worker teardown  
- Root [`README.md`](../README.md#performance-honest) — measured gap, CI framing  
- Code: `crates/kh-runtime` trap/syscall/mem/bottle; freestanding
  `kh-libsystem` `core/{sys,heap}` + `dylib/libsystem_c/posix` +
  `dylib/libsystem_pthread`  
- Bench helpers: `scripts/bench-fair-local.sh`, `scripts/bench-boundary-classes.sh` (Docker-first P1)  
- Existing opt-in: `KAKEHASHI_FUTEX_STATS`
