# Apple clang milestone

Product goal: run **Apple `clang`** (from official Command Line Tools) under
`kh` on Linux aarch64. Clean-room ABI; trace-first. Clippy + unit tests; Docker
Colima first, UTM later.

This is the first **priority compiler** guest after the open-source utility
slice (`curl`, `7zz`, `git`). Same class of work as [curl](curl.md) and
[git](git.md): freestanding surface only as the log demands.

Clean-room rules: [legal-method.md](legal-method.md). See also:
[roadmap](roadmap.md), [architecture](architecture.md).

## Status (gates)

| Gate | Pass criteria | State |
| --- | --- | --- |
| G0 | `kh install xcode-tools` → bottle has CLT + `…/usr/bin/clang` | **pass** (shared with git) |
| G1 | `kh run clang -- --version` banner + exit 0 | **pass** (Docker Colima, 2026-08: `Apple clang version 21.0.0`) |
| G2 | Missing surface list from `--version` / tiny C compile probes | open |
| G3 | Compile trivial `hello.c` → object or executable under bottle | open |
| G4 | Link + run guest binary produced by guest clang (optional stretch) | open |

### Progress log (Docker Colima, 2026-08)

| Step | Result |
| --- | --- |
| Long nlist trampoline (`MAX_NAME` 96→256, variable slots, 512 KiB pool) | **done** — no more `name longer than MAX_NAME` |
| `___cxa_guard_{acquire,release,abort}` | **done** |
| `system_clock` / `steady_clock` / `sleep_for` chrono | **done** |
| `backtrace` soft | **done** |
| `std::mutex` / cond / `__call_once` (`libcxx_sync`) | **done** |
| Darwin `pthread_mutex_t` sig `0x32AAABA7` at word0 → lock word at **+8** | **done** (was infinite park on protobuf statics) |
| Freestanding `basic_string` Apple alternate layout (data@0, size@8, cap\|MSB@16; short size @byte23) | **landed** — verified against host CLT dump |
| Mutex re-entry (`pthread_self` owner + depth) | **done** — unblocked LLVM `ManagedStatic` futex deadlock |
| `operator new` aligned/nothrow, `system_category`, `imaxabs`, `__next_prime`, `set_new_handler`, `__tlv_bootstrap` | **done** |
| Broader `basic_string` (substr ctor, insert/erase/replace, `operator+`) | **landed** |
| SIGSEGV in `operator+(char const*, string)` | **fixed** — AArch64 sret is `x8`, not first arg; return `StringRep` by value |
| **G1 `clang --version`** | **pass** (Docker) |

### Next (trace-first)

| Observed | Layer | Plan |
| --- | --- | --- |
| Hang / further missing after ~mod_init mid list | freestanding libc++ / POSIX | `KAKEHASHI_LOG=info` + post-`mod_init done`; implement only *called* symbols |
| Remaining `basic_string` methods (insert/replace/erase/…) | `libcxx_string` | On demand from missing-symbol log |
| `libz` / `libresolv` skipped soft | bottle | Only if G1 path needs them |

Clang links `libSystem`, `libc++.1`, `libz`, `libresolv`. Bottle aliases
`libc++.1.dylib` → freestanding `libSystem.B.dylib` (same as git/7zz). We do
**not** ship Apple libc++; we grow freestanding C++ runtime stubs only as the
guest path requires.

## Method (trace-first)

1. Smallest failing scenario: `clang --version` (G1).
2. Run under Docker Colima (`scripts/docker-clang.sh`) and capture WARN / missing
   symbol / fault PC.
3. Record **symbol → observed need → stub vs real → plan**.
4. Implement from scratch:
   - guest C ABI → `kh-libsystem` → `./scripts/stage-libsystem.sh`
   - load/bind → `kh-loader`
   - host BSD / helpers → `kh-runtime`
5. Smoke G1; keep `7zz -mmt=4` and curl/git gates green when touching shared paths.
6. Soft stubs until a path needs real behavior — no private frameworks.

Provenance for non-trivial ABI work goes in the PR (or a short table here):
Observed / Spec / Impl / Not used — see [legal-method.md](legal-method.md).

## Where the binary lives

| | Path |
| --- | --- |
| **Guest** | `/Library/Developer/CommandLineTools/usr/bin/clang` (also bare `clang` via `GUEST_PATH_DIRS`) |
| **Host (default bottle)** | `~/.local/share/kakehashi/bottle/Library/Developer/CommandLineTools/usr/bin/clang` |
| **Docker / repo bottle** | `<repo>/.kh/data/bottle/Library/Developer/CommandLineTools/usr/bin/clang` |

Install is the same package as git: `kh install xcode-tools` (public Software
Update catalog; no Apple ID).

## Docker helpers

```bash
# G1 smoke (build kh, ensure bottle, install CLT if needed, run clang --version)
./scripts/docker-clang.sh --version

# Arbitrary guest args after --
./scripts/docker-clang.sh -cc1 -help
```

Process notes for PRs: internet allowed for catalog/install; clippy `-D warnings`
on all default crates; clean-room only — [legal-method.md](legal-method.md).

## Related probes

Small checked-in **products of** Apple clang (not the compiler itself) live in
`tests/clang-probe/` (`puts_hello`, `printf_hello`, …). Those already run under
`kh` and exercise freestanding libc, not the CLT `clang` driver.
