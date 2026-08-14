# Roadmap

What shipped. Safety: [architecture.md](architecture.md). User-facing perf: root [README.md](../README.md#performance-honest).

## Status

| Item | State |
| --- | --- |
| BSD entry | Freestanding hypercall (main + workers) |
| Multi-thread | Green (`7zz -mmt=4 -mx=5` create + test) |
| Zip MT hang (`mmt≥3`) | Fixed (PRIVATE futex, heap lock, cond wake) |
| Multi-file wall (UTM) | ~**×1.24** vs native Linux `7zz` |
| curl / git / Apple clang | Met — [utilities.md](utilities.md) |

### Multi-file (Ubuntu aarch64, `mx=5 mmt=4`)

| tree | native `7zz` | `kh` | ratio |
| --- | ---: | ---: | ---: |
| ~14.5k files / ~309 MiB (Nook) | ~44.1 s | ~54.8 s | **×1.24** |

Historical ~×5.2 was first-fit freelist O(n²); size-class LIFO closed it. Residual is boundary × crossings + guest LZMA. Wall-clock parity is not a ship blocker.

## Done

| Area | Outcome |
| --- | --- |
| Hypercall MT | `SYS_exit` teardown, NEON, alt stack, TPIDR install defer |
| `readlinkat` | Cache bottle alias `real_path` at insert |
| Bind `mprotect` | Batch; skip no-op RW |
| TLS | Guest-TLS mirrors; gettid only on slow path |
| Futex | Contended-bit mutex; cond signal ≠ broadcast |
| Zip MT deadlock | PRIVATE park/wake, heap/mutex/cond |
| Size-class freelist | Multi-file ~×5.2 → ~×1.24 |
| Heap / boundary stats | `kh heap stats`; `KAKEHASHI_BOUNDARY_STATS` |
| Load path | mmap container, file-backed RX, instruction-only `svc` scan, bind export index, `KH_HELPER_SPAWN` |
| curl | G0–G5 — [utilities.md](utilities.md#curl) |
| git / CLT | G0–G8 — [utilities.md](utilities.md#git) |
| Apple clang | G0–G5 + LTO — [utilities.md](utilities.md#apple-clang) |

## Do not re-land

| Attempt | Lesson |
| --- | --- |
| Guest cookie via `mrs` without TLS magic | Only probe when magic marks guest TLS |
| Light hypercall skipping NEON under MT | SEGV / no wall win |
| Thin freestanding without full NEON clobber | Guest LLVM keeps live SIMD |
| `thread_local!` / raw slots on the boundary | SEGV / UAF under guest TPIDR |
| Dual production paths (main hypercall, workers SIGTRAP) | Forbidden (invariant 7) |
| Shared process-wide path/dentry caches | Lock/invalidation cost > `openat` |

## Process

One logical change per PR. Stage `resources/libSystem.B.dylib` on freestanding ABI change. Gate: `7zz a -mx=5 -mmt=4` and `t`, create ≥2 times. Do not claim a wall win without a native Linux baseline on the same tree.

MUST NOT: guest TPIDR across host Rust; `thread_local!` under guest TPIDR; skip full NEON save; host dispatch/join/`munmap` on a guest worker stack; dual syscall paths; `pthread_exit` / dirty `x29`; drop `check_range`; revive `dist/guest`.
