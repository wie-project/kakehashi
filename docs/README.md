# Kakehashi documentation

Normative design reference for maintainers. Prefer these pages over chat
history when changing runtime, threading, or the guest/host boundary.

| Document | Subject |
| --- | --- |
| [Architecture](architecture.md) | Crates, pipeline, bottle, memory |
| [Threading](threading.md) | 1:1 threads, join protocol, worker teardown |
| [Guest–host boundary](guest-host-boundary.md) | TPIDR, hypercall, alt stack, NEON |
| [Invariants](invariants.md) | Binding MUST / MUST NOT |
| [Roadmap](roadmap.md) | Perf status, next work, process |

User-facing install and CI economics: root [`README.md`](../README.md).

## Sources of truth (code)

| Location | Role |
| --- | --- |
| `crates/kh-runtime/src/thread.rs` | Host worker spawn / exit |
| `crates/kh-runtime/src/trap.rs` | `kh_hypercall_entry`, residual `svc`→`brk` |
| `crates/kh-runtime/src/tls.rs`, `host_slot.rs` | TLS boundary; A1 mirrors + gettid fallback |
| `crates/kh-libsystem/src/pthread.rs`, `sys.rs` | Guest pthread + hypercall thin |
| `crates/kh-loader/src/execute.rs` | Wire hypercall into freestanding dylib |

## Multi-thread gate

Linux aarch64 (Docker or bare-metal):

```bash
KAKEHASHI_HYPERCALL=1 ./scripts/docker-7zz.sh a -t7z -m0=lzma2 -mx=5 -mmt=4 \
  /Volumes/linux/out/mt.7z /Volumes/linux/src/README.md
KAKEHASHI_HYPERCALL=1 ./scripts/docker-7zz.sh t /Volumes/linux/out/mt.7z
```

Expect `Everything is Ok` and exit 0. SEGV with PC in host `libgcc_s.so.1`
during worker exit historically means a broken teardown path (see
[Threading — Worker teardown](threading.md#worker-teardown)).
