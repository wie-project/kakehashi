# Clang guest probes

Real **Apple clang** arm64 Mach-O programs that exercise the synthetic bottle
`libSystem.B.dylib` (not Apple code). Checked-in binaries keep Docker/Linux CI
free of a macOS toolchain.

| Binary | Source | Bottle symbols | Expected |
|--------|--------|----------------|----------|
| `write_exit` | `write_exit.c` | `_write`, `__exit` | stdout `hello\n`, exit 0 |
| `return_zero` | `return_zero.c` | (none; `return` only) | exit 0 via dyld-like host exit |
| `puts_hello` | `puts_hello.c` | `_puts` | stdout `hello\n`, exit 0 |
| `printf_hello` | `printf_hello.c` | `_printf` (no `%`) | stdout `hello\n`, exit 0 |

```bash
# Rebuild on macOS:
clang -O0 -arch arm64 -o write_exit write_exit.c
clang -O0 -arch arm64 -o return_zero return_zero.c
clang -O0 -arch arm64 -o puts_hello puts_hello.c
clang -O0 -arch arm64 -o printf_hello printf_hello.c
codesign --remove-signature write_exit return_zero puts_hello printf_hello

# Dry-load (any host):
kh run --dry-load --root ../fixtures/bottle write_exit

# Live (Linux aarch64 / Docker):
kh run --expect-code 0 --root ../fixtures/bottle puts_hello
```

## Ladder notes

- `LC_MAIN` is invoked with `blr` so `return` from `main` resumes the host;
  Kakehashi then `exit`s with `main`'s status (dyld-equivalent).
- `_puts` / `_printf` are host helpers (`x16 = 0x4B48_xxxx`), not full libc.
- `_printf` currently rejects format strings that contain `%`.
