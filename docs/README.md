# Kakehashi documentation

| Document | Subject |
| --- | --- |
| [Architecture](architecture.md) | Crates, pipeline, bottle, TLS, hypercall, threads, invariants |
| [Utilities](utilities.md) | curl, Apple git, Apple clang |
| [Roadmap](roadmap.md) | Shipped status and process |
| [Syscall coverage](syscall-coverage.md) | BSD numbers + helpers |

User recipes: root [`README.md`](../README.md).

## Multi-thread gate

```bash
./scripts/docker-kh.sh 7zz -- a -t7z -m0=lzma2 -mx=5 -mmt=4 \
  /Volumes/linux/out/mt.7z /Volumes/linux/src/README.md
./scripts/docker-kh.sh 7zz -- t /Volumes/linux/out/mt.7z
```

Expect `Everything is Ok`, exit 0.
