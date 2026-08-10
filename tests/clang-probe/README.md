# Clang guest probes

Real **Apple clang** arm64 Mach-O programs that exercise the freestanding guest
`libSystem.B.dylib`. Checked-in binaries keep Docker/Linux CI free of a macOS
toolchain.

| Binary | Source | Bottle symbols | Expected |
|--------|--------|----------------|----------|
| `write_exit` | `write_exit.c` | `_write`, `__exit` | stdout `hello\n`, exit 0 |
| `return_zero` | `return_zero.c` | (none; `return` only) | exit 0 via dyld-like host exit |
| `puts_hello` | `puts_hello.c` | `_puts` | stdout `hello\n`, exit 0 |
| `printf_hello` | `printf_hello.c` | `_printf` (no `%`) | stdout `hello\n`, exit 0 |
| `g4-mini/` | multi-file C (calc/report/words/main) | freestanding stdio/string | `g4-mini PASS`, exit 0 (G4 link probe) |
| `7zz.bin` | upstream 7-Zip (universal Mach-O) | full freestanding libSystem | see below |

```bash
# Rebuild small probes on macOS:
clang -O0 -arch arm64 -o write_exit write_exit.c
clang -O0 -arch arm64 -o return_zero return_zero.c
clang -O0 -arch arm64 -o puts_hello puts_hello.c
clang -O0 -arch arm64 -o printf_hello printf_hello.c
codesign --remove-signature write_exit return_zero puts_hello printf_hello

# From repo root — bottle picks up crates/kh-runtime/resources/libSystem.B.dylib:
kh bottle ensure
kh run --dry-load tests/clang-probe/write_exit

# Live (Linux aarch64 / Docker):
kh run --expect-code 0 tests/clang-probe/puts_hello
```

## `7zz.bin` (real guest)

Checked-in Darwin **universal** (`x86_64` + `arm64`) 7-Zip CLI. Used by:

| Script | Purpose | Host output |
|--------|---------|-------------|
| `../../scripts/docker-kh.sh 7zz --` | ad-hoc compress/list/test | `.tmp/kh-out/` by default |
| `../../scripts/bench-fair-local.sh` | timed native vs kh | `.tmp/kh-bench-fair/artifacts/` |

```bash
# From repo root — archive is on the HOST after the command returns:
./scripts/docker-kh.sh 7zz -- a /Volumes/linux/out/demo.7z \
  /Volumes/linux/src/README.md
ls -lh .tmp/kh-out/demo.7z

# Fair bench (native.7z + kh.7z + checksums + summary):
./scripts/bench-fair-local.sh
ls -lh .tmp/kh-bench-fair/artifacts/
cat .tmp/kh-bench-fair/summary.txt
```

**Do not** write only to `/Volumes/linux/tmp/…` if you want to keep the file:
that is container-local `/tmp` and disappears with `docker run --rm`. Prefer
`/Volumes/linux/out/…` or `/Volumes/linux/src/.tmp/…`. See the top-level
README “Guest path ↔ host path” table.

## Ladder notes

- `LC_MAIN` is invoked with `blr` so `return` from `main` resumes the host;
  Kakehashi then `exit`s with `main`'s status (dyld-equivalent).
- `_puts` / `_printf` are host helpers (`x16 = 0x4B48_xxxx`), not full libc.
- `_printf` currently rejects format strings that contain `%`.
