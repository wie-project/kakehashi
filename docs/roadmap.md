# Roadmap

Status of performance work and process for further changes. Safety rules:
[invariants.md](invariants.md). User-facing perf honesty and CI economics:
root [README.md](../README.md#performance-honest).

## Current status

| Item | State |
| --- | --- |
| Production BSD entry | Freestanding hypercall (main + workers) |
| Multi-thread correctness | Green (`7zz -mmt=4 -mx=5` create + test; Docker + UTM) |
| Zip MT hang (mmt≥3) | Fixed (PRIVATE futex, heap lock, cond always-wake) |
| Perf plateau (UTM 8k-file) | ~**×5.2** wall vs native Linux `7zz` on same tree |

### Measured plateau (Ubuntu aarch64, ~8k files / ~240 MiB, `mx=5 mmt=4`)

| | native `7zz` | `kh` | ratio |
| --- | ---: | ---: | ---: |
| wall | ~22.5 s | ~118 s | **×5.2** |

Residual cost is **hypercall boundary × syscall count** + real LZMA — not
PathBuf join and not empty cond-wake storms (those were fixed). Compression-
heavy, few-file samples are often ~×1.1–1.2.

**Do not** land further micro-opts on the 8k archive path without a new design
that reduces crossings or cheapens the boundary. Correctness gates remain
mandatory; wall-clock parity with native is **not** a ship blocker (see README
CI economics).

## Completed (summary)

| Area | Outcome |
| --- | --- |
| Hypercall MT baseline | SYS_exit teardown, NEON, alt stack, TPIDR install defer |
| A4 `readlinkat` | Cache bottle alias `real_path` at insert |
| A5 excess `mprotect` | Batch bind/rebase; skip no-op RW |
| A2 / A1 TLS | Hot path guest-TLS mirrors; gettid only on slow path |
| F1 / F1c futex | Contended-bit mutex; cond signal≠broadcast; UTM wall ~3:38→~1:57 |
| B1 bottle dirfd | Kept for hygiene; no measurable wall win post-F1c |
| A3 light hypercall | **Removed** — no wall win; one production path |
| Zip MT deadlock | PRIVATE park/wake, 50 ms safety timeout, heap/mutex/cond fixes |

## Failed prototypes (do not re-land)

| Attempt | Lesson |
| --- | --- |
| Guest cookie via `mrs` without proven guest TPIDR | Only probe when magic marks guest TLS |
| Light hypercall skipping NEON under MT | SEGV / no win; full save required |
| Freestanding thin without full NEON clobber list | Guest LLVM keeps live SIMD → unstable MT |
| `thread_local!` / raw slot pointers on boundary | SEGV / UAF under guest TPIDR |
| Dual production paths (main=hypercall, workers=SIGTRAP) | Forbidden (invariant 7) |

## Open work (product, not micro-perf)

Priority is **guest surface**, not another ×5→×4 micro-pass:

| Priority | Direction | Notes |
| --- | --- | --- |
| 1 | **curl** (network CLI) | **Milestone met** (G0–G5). Polish only — see [curl.md](curl.md) |
| 2 | **git** | **Next product slice.** Process/spawn, more pipes/FS; remotes reuse curl network |
| — | Optional polish | `getrusage` / Usage% for 7zz; openssl.cnf seed; freopen; not gates |

Rationale: curl was the smaller vertical slice that forced network ABI on top
of FS/threads. Git is larger (process model, more POSIX) but remotes can reuse
the curl network path.

### Curl milestone — **done** (trace-first)

Method and commands: [curl.md](curl.md). User-facing recipes:
[README — What works](../README.md#what-works).

| Slice | State |
| --- | --- |
| `kh install curl` (+ optional `KAKEHASHI_CURL`) | done |
| Guest `/usr/local/bin/curl` + bottle CA seed | done |
| `scripts/docker-curl.sh` (+ probe) | done |
| G1 `--version` | **pass** |
| G3 HTTP GET body + exit 0 | **pass** (Docker + UTM) |
| G4 HTTPS GET (OpenSSL + CA) | **pass** (Docker) |
| G5 UTM HTTP confirm | **pass** |
| Remaining | polish only (HTTPS UTM smoke, broader CLI flags, soft-framework quieting) |

Process notes for curl polish PRs: internet allowed; clippy `-D warnings`;
keep `7zz -mmt=4` green; clean-room only (no Darling).

## Process

### MAY

1. One logical change per PR with `docker-7zz` / bare-metal `mmt=4` in the description.
2. Default-off counters/flags for risky paths (`KAKEHASHI_FUTEX_STATS`).
3. Optimize freely **while host TPIDR is live**.
4. Stage freestanding ABI changes into `resources/libSystem.B.dylib`.

### MUST NOT

1. Leave guest TPIDR live across host Rust/glibc (invariant 11b).
2. Use `thread_local!` for boundary bookkeeping under guest TPIDR (invariant 10).
3. Skip full Q0–Q31 + FPCR/FPSR save before host `bl` (invariant 13).
4. Run host dispatch / join-publish / `munmap` on a guest worker stack (invariants 4, 14, 16).
5. Dual production syscall paths (invariant 7).
6. End workers with `pthread_exit` or dirty `x29` (invariants 5–6).
7. Ship freestanding ABI without staging the embed.
8. Land perf PRs that only pass `7zz -- i` or `-mmt=1`; **`-mmt=4 -mx=5` is the gate**.
9. Drop identity-map / `check_range` on guest buffers (invariant 17).
10. Reintroduce `dist/guest` as primary libSystem path (invariant 19).

### Perf PR checklist

- [ ] `cargo test -p kh-runtime --lib` (workspace if touching loader/cli)
- [ ] `KAKEHASHI_HYPERCALL=1` `7zz a -mx=5 -mmt=4` → Ok; `7zz t` → Ok
- [ ] Repeat MT create ≥2 times
- [ ] Stage dylib if freestanding ABI changed
- [ ] Bare-metal note if only Docker was used
- [ ] strace/perf snippet only if claiming a wall win

## References

- [Invariants](invariants.md)
- [Guest–host boundary](guest-host-boundary.md)
- [Threading](threading.md)
- [Architecture](architecture.md)
