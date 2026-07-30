# Performance roadmap (hypercall / archive)

Living plan for making freestanding hypercall competitive with native Linux on
hot workloads (especially multi-thread `7zz`). Normative safety rules remain in
[invariants.md](invariants.md). This document is **aspirational + process**: what
to try, in what order, what is allowed, and what has already failed.

## Baseline (current)

| Path | Role |
| ---- | ---- |
| Production BSD entry | Freestanding `blr` → `kh_hypercall_entry` (main + workers) |
| Per-call cost | Guest prolog (full Q0–Q31) → host TPIDR → alt stack → NEON tramp → Rust dispatch → leave |
| Slot map | `host_slot` keyed by `gettid` + `Mutex` (no host `thread_local!` under guest TPIDR) |
| Correctness gate | `KAKEHASHI_HYPERCALL=1` + `7zz a -mx=5 -mmt=4` + `t` (Docker / bare-metal) |

### Observed gap (Ubuntu aarch64, ~240 MiB / ~8k files, `mx=5 mmt=4`)

| | native `7zz` | `kh` hypercall | ratio |
| -- | --: | --: | --: |
| real | ~34 s | ~161 s | **×4.7** |
| user | ~73 s | ~186 s | ×2.6 |

On compression-heavy, fewer-file samples the gap shrinks (often ~×1.1–1.2). The
large gap is dominated by **path walk + per-syscall boundary tax**, not “wrong
LZMA”.

### strace signatures (hyper vs native, smaller tree)

Typical hypercall-side noise:

| Host syscall | Symptom | Likely source |
| ------------ | ------- | ------------- |
| `gettid` × huge | tens of k | every `host_slot` lookup |
| `futex` × large | map `Mutex` | same |
| `readlinkat` × large, many `ENOENT` | path / symlink noise | bottle / path walk |
| `mprotect` × large | unexpected for archive | identify before “optimizing” |
| `read` / `openat` | similar order of magnitude to native | I/O itself is not the only tax |

Use `strace -c -f` and `perf record -g` on **the same tree** for before/after.

---

## Goals

| Tier | Target (rough) | Notes |
| ---- | -------------- | ----- |
| G0 | No regressions | Always green `mmt=4` + unit tests |
| G1 | ×2–3 of native on 8k-file bench | Realistic after A-tier |
| G2 | ×1.5–2 on same bench | Needs light I/O path + slot fast path |
| G3 | ≤×1.2 on compression-heavy, few files | Already close |
| Fantasy | Native path-walk parity | Unlikely without kernel-level tricks |

---

## Ideas by tier

### A — High ROI (try next; one change at a time)

| ID | Idea | Why | Hard parts |
| -- | ---- | --- | ---------- |
| **A1** | **Guest-TLS slot cookie** (offset reserved in freestanding TLS block) | Kill most `gettid` on enter under **guest** TPIDR | Must **never** probe cookie while TPIDR is **host** glibc TLS; validate magic + `slot.guest_tpidr == mrs` |
| **A2** | **Host-only slot / tid cache after `kh_tls_enter_host`** | Skip second/third `gettid` in same hypercall (`alt_sp`, leave) | Cache only after host TPIDR restored; never read host `thread_local!` under guest TPIDR |
| **A3** | **Light hypercall for hot I/O/fs numbers** | Skip **second** full NEON save (`TRAMP_BYTES`) when prolog already saved Q* | Keep prolog NEON; freestanding must still treat call as full C clobber or host restore is not enough for LLVM; MT gate mandatory |
| **A4** | **Kill `readlinkat` storm** | 95% errors = pure waste | Find caller (`strace -e readlinkat -k`); fix path/canonicalize/bottle symlink walk |
| **A5** | **Explain / remove excess `mprotect`** | 15k vs ~15 native | `strace -e mprotect -k`; do not “batch” blindly |

### B — Medium (after A is green)

| ID | Idea | Why |
| -- | ---- | --- |
| **B1** | Faster `translate_path` (no PathBuf churn; intern bottle root) | Every `open`/`stat` |
| **B2** | Hot `read`/`write`/`lseek`/`fstat` with minimal registry work (range cache already exists — extend carefully) | Archive I/O |
| **B3** | Avoid global locks on FD map / process state (already lock-free-ish for FD — keep it) | MT scaling |
| **B4** | Optional: no alt-stack switch for pure ST / documented fallback only | Micro-cost; **MUST NOT** become MT default on guest stack |
| **B5** | Larger guest read sizes / less chatty stdio in freestanding where safe | Fewer hypercalls |

### C — Large / architectural

| ID | Idea | Why |
| -- | ---- | --- |
| **C1** | Seccomp / userspace rewrite of a **tiny** safe Linux subset | Nuclear option |
| **C2** | Dual entry only as **experiment**, not production dual-path default | Forbidden as prod model (invariant 7) |
| **C3** | Accept path-walk tax; document “native for bulk pack, kh for Darwin ABI apps” | Product honesty |

---

## Failed prototypes (do not re-land without new design)

Recorded during Docker MT stress (`7zz -mmt>1`). Symptoms were SEGV (host `kh` and/or guest PC), often early in archive.

| Attempt | What broke | Lesson |
| ------- | ---------- | ------ |
| Guest cookie probed via `mrs` **without** guaranteeing guest TPIDR | Garbage “magic” / cookie from **host** TLS after enter | Cookie **only** when `TPIDR` is known guest (magic + match stored `guest_tpidr`) |
| Light path: `bl kh_trampoline_dispatch` skipping NEON tramp under MT | SEGV under `-mmt>1` | Need prolog+restore invariants + freestanding ABI; re-validate MT |
| Freestanding `hypercall_thin` without full C/NEON clobber list | Unstable MT / SEGV | Guest LLVM must not keep live caller-saved SIMD across `blr` unless host contract is proven and tested |
| Using host `thread_local!` for slot pointer **before** host TPIDR restore | Classic `si_addr≈0xa0` class faults | Under guest TPIDR, only `gettid` + map (or validated guest cookie) |
| Storing `Box<ThreadSlot>` raw pointers + aggressive cache | MT races / UAF risk if clear races | Prefer tid-keyed map until cookie design is airtight |

---

## What you MAY do

1. **One logical change per PR**, with explicit `docker-7zz` / bare-metal `mmt=4` in the description.
2. Add **counters / env flags** (e.g. `KAKEHASHI_HYPERCALL_LIGHT=0` kill-switch) behind default-off for risky paths.
3. Optimize **while host TPIDR is live** freely (after `kh_tls_enter_host`): Rust, glibc, alloc, `thread_local!` for pure host caches.
4. Optimize **guest freestanding** code paths that do not change the host ABI without staging `resources/libSystem.B.dylib`.
5. Use **strace / perf / RUST_LOG** on bottle paths (`KAKEHASHI_ROOT` / `~/.local/share/kakehashi/bottle`); remember guest `/tmp` ≠ host `/tmp`.
6. Widen **known-good** light syscall lists only after MT archive + unit tests.
7. Document new failure modes in [invariants.md](invariants.md) when you find them.

## What you MUST NOT do

1. **MUST NOT** leave guest `TPIDR_EL0` active across host Rust/glibc/`tracing` (invariant 11b).
2. **MUST NOT** use Rust `thread_local!` (or TLS-dependent malloc) for boundary bookkeeping while guest TPIDR is live (invariant 10).
3. **MUST NOT** skip **full Q0–Q31 + FPCR/FPSR** save before the first host `bl` in production hypercall entry (invariant 13) — “light” paths may only skip a *second* save if the first is complete and restore still runs.
4. **MUST NOT** run host dispatch / join-publish / `munmap` on a guest worker stack under MT (invariants 4, 14, 16).
5. **MUST NOT** reintroduce dual production paths “main=hypercall, workers=SIGTRAP only” (invariant 7).
6. **MUST NOT** end workers with `pthread_exit` / leave dirty `x29` (invariants 5–6).
7. **MUST NOT** publish freestanding `libSystem` ABI changes without staging  
   `crates/kh-runtime/resources/libSystem.B.dylib` and reinstalling into bottles.
8. **MUST NOT** land perf PRs that only pass `7zz -- i` or `-mmt=1`; **`-mmt=4 -mx=5` is the gate**.
9. **MUST NOT** “optimize” by dropping identity-map/`check_range` safety on guest buffers (invariant 17).
10. **MUST NOT** reintroduce `dist/guest` as the primary libSystem product path (invariant 19).

## Implementation process

```text
1. Write the hypothesis (which strace/perf line moves).
2. Implement behind a default-safe path (flag off or identical behavior).
3. cargo test -p kh-runtime --lib
4. docker-7zz / bare-metal:
     KAKEHASHI_HYPERCALL=1 kh run 7zz -- a -t7z -m0=lzma2 -mx=5 -mmt=4 …
     KAKEHASHI_HYPERCALL=1 kh run 7zz -- t …
5. Optional: strace -c -f before/after on the same tree.
6. Enable flag by default only after ≥3 green MT runs + no new flake.
7. Update this roadmap (move idea to “Done” or “Failed”).
```

### Suggested order

1. **A4** `readlinkat` (usually pure win, low ABI risk)  
2. **A5** `mprotect` attribution  
3. **A2** host-only cache **after** enter (never under guest)  
4. **A1** guest cookie v2 (strict validation)  
5. **A3** light I/O entry (last among A — highest MT risk)

---

## Verification checklist (perf PR)

- [ ] `cargo test -p kh-runtime --lib` (and workspace gate if touching loader/cli)
- [ ] `KAKEHASHI_HYPERCALL=1` `7zz a -mx=5 -mmt=4` → Everything is Ok  
- [ ] `7zz t` on the archive → Ok  
- [ ] Repeat MT archive ≥2 times (flake check)  
- [ ] If freestanding ABI changed: stage dylib + `kh bottle ensure --libsystem …`  
- [ ] Bare-metal Ubuntu note if only Docker was used (page size / glibc differ)  
- [ ] strace or perf snippet in PR for claimed win  
- [ ] No new guest TPIDR left live on host-only paths  

Bottle path reminder:

```bash
# guest /tmp  →  $KAKEHASHI_ROOT/tmp  or  ~/.local/share/kakehashi/bottle/tmp
BOTTLE="${KAKEHASHI_ROOT:-$HOME/.local/share/kakehashi/bottle}"
mkdir -p "$BOTTLE/tmp/bench"
# fill $BOTTLE/tmp/bench, then:
KAKEHASHI_HYPERCALL=1 kh run 7zz -- a -t7z -m0=lzma2 -mx=5 -mmt=4 \
  /tmp/out.7z /tmp/bench/
```

---

## Done / deferred log

| Date | Item | Outcome |
| ---- | ---- | ------- |
| 2026-07 | Hypercall MT correct (SYS_exit, NEON, alt stack, TPIDR install defer) | Correctness baseline |
| 2026-07 | Cookie / light entry / freestanding NEON clobber experiments | **Failed** under `-mmt>1`; reverted |
| — | A1–A5 as above | Open |

---

## References

- [Invariants](invariants.md) — binding MUST / MUST NOT  
- [Guest–host boundary](guest-host-boundary.md) — hypercall sequence  
- [Threading](threading.md) — join / worker teardown  
- [Architecture](architecture.md) — crates and bottle  
- `crates/kh-runtime/src/trap.rs` — `kh_hypercall_entry`  
- `crates/kh-runtime/src/host_slot.rs`, `tls.rs`  
- `crates/kh-libsystem/src/sys.rs` — `hypercall_thin`  
