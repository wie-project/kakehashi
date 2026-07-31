# Kakehashi documentation

Internal design reference for maintainers and agents. Prefer these pages over
chat history when changing runtime, threading, or guest/host boundary code.

| Document | Subject |
| -------- | ------- |
| [Architecture](architecture.md) | Crates, execution model, bottle, memory |
| [Threading](threading.md) | 1:1 threads, join protocol, worker teardown |
| [Guest–host boundary](guest-host-boundary.md) | TPIDR, hypercall, alt stack, NEON |
| [Invariants](invariants.md) | Non-negotiable rules (do not regress) |
| [Roadmap](roadmap.md) | Perf ideas, order of work, allow / forbid |

## Audience and tone

These documents are **normative** for production paths on Linux aarch64.
Examples and env vars are descriptive; MUST / MUST NOT rules are binding for
code that claims to implement the model.

## Related sources of truth

| Location | Role |
| -------- | ---- |
| `crates/kh-runtime/src/thread.rs` | Host worker spawn / exit |
| `crates/kh-runtime/src/trap.rs` | `kh_hypercall_entry`, trampoline |
| `crates/kh-runtime/src/tls.rs`, `host_slot.rs` | TLS boundary; gettid map; enter+alt merge (A2) |
| `crates/kh-libsystem/src/pthread.rs`, `sys.rs` | Guest pthread + hypercall thin |
| `crates/kh-loader/src/execute.rs` | Wire hypercall into freestanding dylib |
| `README.md`, `CONTRIBUTING.md` | User-facing build / PR gates |

## Verification (threading)

A minimal multi-thread gate (Linux aarch64 / Docker):

```bash
KAKEHASHI_HYPERCALL=1 ./scripts/docker-7zz.sh a -t7z -m0=lzma2 -mx=5 -mmt=4 \
  /Volumes/linux/out/mt.7z /Volumes/linux/src/README.md
KAKEHASHI_HYPERCALL=1 ./scripts/docker-7zz.sh t /Volumes/linux/out/mt.7z
```

Expect `Everything is Ok` and process exit 0. A SEGV with PC in host
`libgcc_s.so.1` during worker exit historically meant a broken teardown path
(see [Threading — Worker teardown](threading.md#worker-teardown)).
