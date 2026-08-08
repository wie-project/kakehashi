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
| G5 | Standard multi-file link with **modern `ld`** (no `ld-classic`) + run | **pass** (Docker: objs + SDK; full clang-driver multi-file with live `-lto_library` → `g4-mini PASS` in ~7s; nested re-exec + `DYLD_LIBRARY_PATH` fixed — no soft-ENOENT) |
| G5+LTO | `clang -flto` multi-file link + run under freestanding + live CLT `libLTO` | **pass** (Docker: mini exit 0; `g4-mini` `-flto` → `g4-mini PASS`, exit 0) |

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
| Soft libobjc / `os_unfair_lock` (`objc_surface`) for modern `ld` | **landed** — pool/retain/`msgSend` nil; class data stubs |
| Soft libc++ iostream ZTV/ZTT + `ios_base`/`locale` (`libcxx_iostream`) | **landed** — fixes `ld::Options::parse` stringstream construction; `ld -v` **pass** |
| Soft `_dyld_image_count` / image name | **landed** |
| Soft `std::filesystem` path ops (`libcxx_fs`) | **landed** — path component methods return **view `{ptr,len}` in x0/x1** (ld call sites: no sret; `cbz x1`) |
| Soft `operator new(align)` / `_simple_*` / `vm_allocate` | **landed** — modern ld missing surface |
| Soft streambuf `xsputn` writes stderr + returns `n` | **landed** — was spin (return 0) / empty `ld: ` errors |
| Soft `_simple_vsprintf` real format+append | **landed** — was no-op → empty `mach_o::Error::message()` → sparse `ld: ` |
| `read_c_bytes` for Darwin paths (no UTF-8 reject) | **landed** — non-UTF-8 path bytes were `EFAULT` |
| Soft `filebuf` read + ifstream filebuf @+0x10 | **landed** — TBD load path for modern `ld` / tapi |
| `vm_allocate` 16 KiB-aligned user (host 4 KiB OK) | **landed** — `UnsafeHeaderWriter` minHeaderAlignment |
| Page-aligned freestanding `malloc` (≥256 B mmap) | **landed** — same assert class as `vm_allocate` |
| **G5 standard link** (modern `ld`, explicit TBD / SDK) | **pass** (Docker: modern `ld` + `libSystem.B.tbd` → product `g4-mini PASS`; classic still green) |
| G4 regression after G5 soft surface | **pass** (Docker: classic link + `g4-mini PASS`) |
| Darwin `TMPDIR` / `confstr(_CS_DARWIN_USER_TEMP_DIR)` ≈ host `/var/folders/…/T/` | **landed** — freestanding no longer seeds short `/tmp` for LTO object paths |
| `basic_string` `__recommend` (MacOSX.sdk alternate layout) | **landed** |
| Darwin `regex_t` 32-byte layout (`re_magic`/`re_nsub`/`re_endp`/`re_g`) | **fixed** — was 16-byte `{nsub,opaque}`; `re_nsub` read host handle |
| `std::__get_classname` → Apple `_CTYPE_*` mask + soft ctype table bits | **fixed** — was pointer return; unblocked live `libLTO` `APPLE_1_*` bitcode version check |
| **G5+LTO `clang -flto` mini + `g4-mini`** | **pass** (Docker: product `g4-mini PASS`, exit 0) |

### Standard path (modern `ld` + ObjC) — inventory

Default CLT driver uses **`ld`**, which links:

| Load | Role |
| --- | --- |
| `@rpath/libtapi` / `libLTO` / `libcodedirectory` / `libswiftDemangle` | Present in CLT `usr/lib` (loaded) |
| `/usr/lib/libobjc.A.dylib` | **Absent** in bottle → flat bind → freestanding soft |
| `Foundation` / `CoreFoundation` / `CoreAnalytics` | **Absent** → skip + freestanding soft |
| `libc++.1` / `libSystem.B` | Aliased → freestanding |

**Static undef of modern `ld` (arm64):** 308 imports. After freestanding
exports + rpath dylibs, the freestanding-relevant holes that matter for G5
are roughly:

| Bucket | ~count | Notes |
| --- | ---: | --- |
| ObjC runtime | 9 | pool / retain / `msgSend` / opts — **soft landed** |
| `OBJC_CLASS_$_NS*` | 6 | class data stubs — **soft landed** |
| `os_unfair_lock*` / os_log / signpost | ~8 | lock soft landed; log/signpost soft |
| libc++ iostream / filesystem | ~40 | still missing (ifstream, locale, `std::fs`) |
| LTO / thinLTO / libcd | many | resolve via `@rpath` dylibs when those load |
| tapi C++ API | many | via `libtapi` when loaded |
| other C (`vm_*`, `getrusage`, `uuid_*`, …) | ~20+ | on demand |

**BSD syscalls (kh-runtime table):**

| Metric | Value |
| --- | ---: |
| Logical `BsdSyscall` variants (all have dispatch arms) | **77** |
| Unique Darwin numbers in lookup (aliases / nocancel) | **95** |
| Host helpers `KH_HELPER_*` | **19** |
| XNU `syscalls.master` scale (approx primary slots) | ~500–550 |
| Static “not in table” (ENOSYS if called) | **~400+** numbers |

**Observed on G5 Docker probe (`KAKEHASHI_BOUNDARY_STATS=1`):** **0 unknown
BSD syscalls**. Top buckets were known (`kh_wake`, `sigaction`, `stat`,
`fork`/`wait4`, …). Failure mode is **guest symbols / soft ObjC layout**, not
missing `svc` numbers.

### Next (trace-first)

| Observed | Layer | Plan |
| --- | --- | --- |
| modern `-L $SDK/usr/lib -lSystem` (no absolute TBD) | kh-runtime path repair | **pass** (Docker): freestanding join drops `/` → `…/liblibSystem.tbd`; `repair_ld_guest_path` chains `liblib` → `lib/lib` on open/access/stat; product `g4-mini PASS` |
| modern `-syslibroot $SDK -lSystem` alone (clang-driver shape) | kh-runtime path repair + F_GETPATH | **pass** (Docker): join dropped `/` after SDK root → probes `…/MacOSX.sdkusr/lib` (not `…/sdk/usr/lib`); `repair_ld_syslibroot_join` + chain with `liblib`; `fcntl(F_GETPATH)` fills guest path (was soft-ok → tapi ENOENT); product `g4-mini PASS` |
| Full clang driver default link (no `ld-classic`) | bottle + modern `ld` | **pass** (Docker): modern `ld` + `-syslibroot` + `-lSystem` + live `-lto_library`; product `g4-mini PASS` |
| modern `ld` + `-lto_library` (clang default) | freestanding + loader | **pass** non-bitcode (Docker, ~1s after one re-exec). Root cause: Apple `ld` stages `/tmp/ld-support-*/libLTO.dylib`, sets `DYLD_LIBRARY_PATH`, and **re-execs** itself. Nested `kh run` dropped `DYLD_*` from guest stack/soft env and ignored it for `@rpath` → infinite re-exec (~45 hops / 25s). Fixed: (1) real `mkdtemp`/`mkpath_np`/`create_symlink` + host-translated symlink targets; (2) seed/pass `DYLD_LIBRARY_PATH` on nested re-exec; (3) prefer `DYLD_LIBRARY_PATH` before LC_RPATH for `@rpath`. No soft-ENOENT hide |
| Microbench g4-mini full driver (no `-flto`) | host vs kh | **native** Apple clang 17 host ~**0.13s**; **kh** bottle clang 21 ~**6.35s** (~**49×**). Split: native `-c`×4 ~0.48s / `ld` ~0.10s; kh `-c`×4 ~7.6s / `ld`+`-lto_library` ~1.5s |
| `KAKEHASHI_BOUNDARY_STATS=ns` (driver) | analyzer | Parent clang: **~1044** crossings, dominated by **`wait4`** (~5.6s of ~6.3s wall — children are separate `kh` after fork/exec). Top count: `mmap`/`munmap`/`kh_wake`. Nested re-exec now inherits `KAKEHASHI_BOUNDARY_STATS` |
| `-flto` multifile | freestanding + live libLTO | **pass** (Docker, 2026-08). Bitcode compile + modern `ld` + live CLT `libLTO` (LLVM 21) → product runs. Root causes fixed (fact-first, no argv crutches / soft-ENOENT): (1) **Darwin temp layout** — seed `TMPDIR` + `confstr(_CS_DARWIN_USER_TEMP_DIR)` to `/var/folders/…/T/` so `-object_path_lto` is ~60 chars like host (short `/tmp` broke materialize); (2) **`basic_string` `__recommend`** match MacOSX.sdk alternate layout; (3) **Darwin `regex_t` layout** (32 B: `magic`/`nsub`/`endp`/`re_g`) — wrong 16 B layout made `re_nsub` read the handle; (4) **`std::__get_classname` → `ctype_base::mask` (`uint32_t`)** + Apple `_CTYPE_*` table bits — old soft returned a pointer, so embedded `std::regex` `[[:digit:]]` never matched → `Invalid bitcode version (Producer: 'APPLE_1_…' Reader: '…')`. Also: locale/rune table offsets, ctype facet soft table, `sscanf` in C `va_list`. |
| Perf note | process model | ~50× on g4-mini is mostly start/`wait4` tax. Target ~5× on long builds **without** `khserver`/wineserver-style daemon — prefer fewer outer processes, cheaper map, less crossings |
| Wall time under kh (UTM/Docker) | process model | g4-mini ~**6–7s** full driver is expected today: each outer `kh run` remaps freestanding+clang; parent spends wall in `wait4` of nested `-cc1`/`ld`. Prefer `make one CC="kh run clang --"` (one outer process). Default Makefile no longer forces `ld-classic` |
| Soft Foundation / deeper ObjC if driver pulls more | freestanding | On demand |
| Harder `-cc1` / more libc++ | freestanding | On demand |
| Full RTTI / exception unwind | freestanding | Soft `dynamic_cast` is hierarchy walk only; real catch still aborts |

Clang links `libSystem`, `libc++.1`, `libz`, `libresolv`. Bottle aliases
`libc++.1.dylib` → freestanding `libSystem.B.dylib` (same as git/7zz). We do
**not** ship Apple libc++; we grow freestanding C++ runtime stubs only as the
guest path requires. Multi-file **modern `ld`** is green with absolute `-L` to
SDK `usr/lib` + `-lSystem` (and with explicit TBD). The default clang driver
path (modern `ld`, `-syslibroot`, live CLT `libLTO` on disk, no absolute TBD,
no soft-ENOENT) is green for non-bitcode **and** `-flto` multi-file links.

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

# G5 clang-driver multi-file (modern ld, no --ld-path, no absolute TBD)
./scripts/docker-clang.sh \
  -O0 -std=c11 -arch arm64 \
  -I /Volumes/linux/src/tests/clang-probe/g4-mini/include \
  /Volumes/linux/src/tests/clang-probe/g4-mini/src/calc.c \
  /Volumes/linux/src/tests/clang-probe/g4-mini/src/report.c \
  /Volumes/linux/src/tests/clang-probe/g4-mini/src/words.c \
  /Volumes/linux/src/tests/clang-probe/g4-mini/src/main.c \
  -o /Volumes/linux/out/g4-mini-driver
# then:  kh run /Volumes/linux/out/g4-mini-driver   →  g4-mini PASS

# G5+LTO full-bitcode multi-file (live libLTO; same sources)
./scripts/docker-clang.sh \
  -flto -O0 -std=c11 -arch arm64 \
  -I /Volumes/linux/src/tests/clang-probe/g4-mini/include \
  /Volumes/linux/src/tests/clang-probe/g4-mini/src/calc.c \
  /Volumes/linux/src/tests/clang-probe/g4-mini/src/report.c \
  /Volumes/linux/src/tests/clang-probe/g4-mini/src/words.c \
  /Volumes/linux/src/tests/clang-probe/g4-mini/src/main.c \
  -o /Volumes/linux/out/g4-mini-flto
# then:  kh run /Volumes/linux/out/g4-mini-flto   →  g4-mini PASS
#
# Or under kh inside the container:
#   make -C /Volumes/linux/src/tests/clang-probe/g4-mini flto-one \
#     CC="kh run clang --" OUT=/Volumes/linux/out/g4-mini-flto
```

Process notes for PRs: internet allowed for catalog/install; clippy `-D warnings`
on all default crates; clean-room only — [legal-method.md](legal-method.md).

## Related probes

Small checked-in **products of** Apple clang (not the compiler itself) live in
`tests/clang-probe/` (`puts_hello`, `printf_hello`, …). Those already run under
`kh` and exercise freestanding libc, not the CLT `clang` driver.
