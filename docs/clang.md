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
| G2 | Missing surface list from `--version` / tiny C compile probes | **pass** (trace log; see progress) |
| G3 | Compile trivial `hello.c` → object or executable under bottle | **pass** (Docker: `return_zero.c` → Mach-O arm64 `.o`; also `stdio_hello.c` with SDK) |
| G4 | Link + run guest binary produced by guest clang (optional stretch) | **pass** (Docker: multi-file `g4-mini` via `ld-classic` + SDK TBDs; product runs `g4-mini PASS`, exit 0) |

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
| `posix_spawn` + `wait4` (driver spawns `-cc1`) | **done** |
| `_NSGetExecutablePath` real path (was hard-coded git) | **done** — helper + `kh run` records guest path |
| `std::to_string`, soft `shared_ptr`, `kdebug_*`, `arc4random*` | **done** |
| TLV: large per-key block + **register-preserving** `__tlv_bootstrap` | **done** — fixed SEGV in `SemaPPCallbacks::FileChanged` (`x9` live across thunk) |
| `std::__sort` (`char`/`int`/`unsigned`/`ushort`) | **done** |
| **G3 `clang -c return_zero.c -o ….o`** | **pass** (Docker, Mach-O arm64 object, exit 0) |
| `clang -E` preprocess | **pass** |
| `#include <stdio.h>` / SDK headers | **pass** — swscan SDKs + freestanding `SDKROOT`/`DEVELOPER_DIR` soft env |
| CLT product **26.6** → `SDKs/MacOSX.sdk` → `MacOSX26.5.sdk` | **pass** (Docker install) |
| `clang -c stdio_hello.c` | **pass** (Mach-O arm64 `.o`, 744 B) |
| Multi-file probe `tests/clang-probe/g4-mini/` | **sources ready** (host build/run PASS) |
| Guest multi-file **compile** (`-c` × N) | **pass** (Docker) |
| `@executable_path/../lib` rpath | **fixed** — `libtapi` / `libswiftDemangle` load for CLT tools |
| Darwin BSD `qsort_r` ABI (thunk before compar) | **fixed** — was SEGV PC-on-stack in `ld-classic` |
| Soft surface for `ld-classic` (`ld_surface`, `reallocf`, Blocks/GCD soft, `stoi`, …) | **landed** |
| Prefer `--ld-path=…/ld-classic` (not modern `ld` / ObjC+Foundation) | **required** for G4 |
| `___cxa_throw` diagnostics (type/msg/ra) | **done** — exposed real ld message path |
| Soft `__dynamic_cast` always-null | **root cause** — `findDylib` `dynamic_cast<ld::dylib::File*>` failed → `indirect dylib … is not a dylib` |
| Itanium `__dynamic_cast` walk (vtable[-1] typeinfo, SI/VMI bases) | **fixed** — reexport TBD chain works |
| Soft always-src `__dynamic_cast` | **rejected** — wrong `Resolver::doFile` branch → SEGV |
| `ccsha256_di` was **data** symbol | **fixed** — must be function returning `ccdigest_info*`; `final` @+0x38 |
| Soft `ccdigest_info` + `strtod`/`modf`/`posix_madvise`/`nothrow` | **landed** for libtapi / UUID |
| **G4 link + run `g4-mini`** | **pass** (Docker Colima, Mach-O arm64 product, exit 0) |

### Next (trace-first)

| Observed | Layer | Plan |
| --- | --- | --- |
| Harder `-cc1` / more libc++ | freestanding | On demand from missing-symbol log |
| Full RTTI / exception unwind | freestanding | Soft `dynamic_cast` is hierarchy walk only; real catch still aborts |

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

Install is the same product as git: `kh install xcode-tools` (public Software
Update catalog; no Apple ID). That product also installs the current MacOSX
SDK (`CLTools_macOSNMOS_SDK` only — not previous-major LMOS). Freestanding
seeds `SDKROOT` + `DEVELOPER_DIR` so Apple clang finds headers without a
working `xcrun`.

## Docker helpers

```bash
# G1 smoke (build kh, ensure bottle, install CLT if needed, run clang --version)
./scripts/docker-clang.sh --version

# Guest args are passed through (do **not** add an extra leading `--` — it
# becomes a clang argv that ends option parsing).
./scripts/docker-clang.sh -cc1 -help

# G3 object compile
./scripts/docker-clang.sh -x c -c \
  /Volumes/linux/src/tests/clang-probe/return_zero.c \
  -o /Volumes/linux/out/return_zero.o

# G4 multi-file link + product under guest (ld-classic + SDK TBDs)
./scripts/docker-clang.sh \
  -O0 -std=c11 -arch arm64 \
  --ld-path=/Library/Developer/CommandLineTools/usr/bin/ld-classic \
  -I /Volumes/linux/src/tests/clang-probe/g4-mini/include \
  /Volumes/linux/src/tests/clang-probe/g4-mini/src/calc.c \
  /Volumes/linux/src/tests/clang-probe/g4-mini/src/report.c \
  /Volumes/linux/src/tests/clang-probe/g4-mini/src/words.c \
  /Volumes/linux/src/tests/clang-probe/g4-mini/src/main.c \
  -o /Volumes/linux/out/g4-mini
# then:  kh run /Volumes/linux/out/g4-mini   →  g4-mini PASS
```

Process notes for PRs: internet allowed for catalog/install; clippy `-D warnings`
on all default crates; clean-room only — [legal-method.md](legal-method.md).

## Related probes

Small checked-in **products of** Apple clang (not the compiler itself) live in
`tests/clang-probe/` (`puts_hello`, `printf_hello`, …). Those already run under
`kh` and exercise freestanding libc, not the CLT `clang` driver.
