# Kakehashi documentation

Normative design reference for maintainers.

| Document | Subject |
| --- | --- |
| [Architecture](architecture.md) | Crates, pipeline, bottle, `kh-libsystem` tree |
| [Threading](threading.md) | 1:1 threads, join protocol, worker teardown |
| [Guest–host boundary](guest-host-boundary.md) | TPIDR, hypercall, alt stack, NEON |
| [Invariants](invariants.md) | Binding MUST / MUST NOT |
| [Clean-room / legal](legal-method.md) | No Darling; trace-first ABI |
| [Roadmap](roadmap.md) | Status, next work |
| [Optimization process](roadmap2.md) | Measure-first perf rules |
| [Curl](curl.md) | Network surface (milestone met) |
| [Git / CLT](git.md) | Apple `git` (milestone met) |
| [Apple clang](clang.md) | CLT `clang` under `kh` |
| [Syscall coverage](syscall-coverage.md) | BSD numbers + helpers (done / gaps) |

User recipes and install: root [`README.md`](../README.md).

## Code map

| Location | Role |
| --- | --- |
| `crates/kh-runtime/src/thread/` | Host worker spawn / exit |
| `crates/kh-runtime/src/cpu/trap.rs` | Hypercall entry, residual `svc`→`brk` |
| `crates/kh-runtime/src/thread/tls.rs`, `cpu/host_slot.rs` | TLS boundary |
| `crates/kh-libsystem/src/core/sys.rs` | Guest hypercall thin + `SYS_*` |
| `crates/kh-libsystem/src/dylib/libsystem_pthread/` | Guest pthread |
| `crates/kh-loader/src/execute.rs` | Wire hypercall into freestanding dylib |

## Multi-thread gate

```bash
./scripts/docker-kh.sh 7zz -- a -t7z -m0=lzma2 -mx=5 -mmt=4 \
  /Volumes/linux/out/mt.7z /Volumes/linux/src/README.md
./scripts/docker-kh.sh 7zz -- t /Volumes/linux/out/mt.7z
```

Expect `Everything is Ok`, exit 0.
