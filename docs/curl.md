# Curl milestone

Product goal: run a **Darwin `curl`** under `kh` on Linux aarch64 and prove
**network I/O**. Clean-room ABI; internet allowed. Clippy + unit tests; Docker
Colima first, UTM later.

**Method: trace-first.** Download a real Darwin arm64 binary → install into the
bottle → `kh run` / `kh trace` → implement only what the log shows.

See also: [roadmap](roadmap.md), [architecture](architecture.md).

## Where the binary lives

Same pattern as 7zip:

| | Path |
| --- | --- |
| **Guest** | `/usr/local/bin/curl` |
| **Host (default bottle)** | `~/.local/share/kakehashi/bottle/usr/local/bin/curl` |
| **Docker probe bottle** | `<repo>/.kh/data/bottle/usr/local/bin/curl` |
| **Relative under bottle root** | `usr/local/bin/curl` (`GUEST_CURL_REL`) |

`kh run curl` resolves the bare name via guest `PATH` (`/usr/local/bin`, …).

## Install (download from the internet)

```bash
kh bottle ensure
kh install curl
# → downloads Darwin arm64 archive, installs guest /usr/local/bin/curl
```

- Default URL: `DARWIN_CURL_URL` in `crates/kh-runtime/src/bottle/guest_tools.rs`
  (currently stunnel/static-curl `curl-macos-arm64-*.tar.xz`).
- Skip download: `KAKEHASHI_CURL=/path/to/curl kh install curl`.
- Needs host `curl`/`wget` + `tar` (same as 7zip install).

```bash
kh install list
# curl → /usr/local/bin/curl
```

## Docker test (same pattern as 7zip)

Like `docker-7zz.sh`: build `kh` in the Linux aarch64 image, ensure bottle,
`kh install curl` (download), then `kh run curl -- …`.

```bash
# Everyday run (exit code = guest exit), like docker-7zz:
./scripts/docker-curl.sh --version

# Trace-first expansion (G1/G2): also saves stderr + unknown BSD numbers
./scripts/docker-curl-probe.sh --version
# same as: KH_CURL_PROBE=1 ./scripts/docker-curl.sh --version

# Later, after load works:
./scripts/docker-curl.sh -sS -o /Volumes/linux/out/body http://example.com/
```

Probe artifacts: host `.tmp/kh-curl-probe/` (`*.stderr`, `*.unknown-syscalls.txt`,
optional JSON from `kh trace --json`).

| Signal | Next step |
| --- | --- |
| Unresolved dylib / framework at load | Binary deps — not a BSD number yet |
| `kh: unknown BSD syscall #N` | Implement **that** number only |
| Known call, wrong errno / hang | Fix translation for that call |

Do **not** pre-land a full speculative socket table without a probe log.

## Gates

| Gate | Pass |
| --- | --- |
| G0 | `kh install curl` places binary at guest `/usr/local/bin/curl` |
| G1 | Load / `--version` produces a useful failure or success log |
| G2 | Stable list of missing syscalls / symbols |
| G3 | HTTP GET under `kh` (product network gate) |
| G4 | HTTPS (deferred; may need different binary or TLS strategy) |
| G5 | UTM confirm |

## Note on the default download

The stunnel static macOS arm64 build is a real arm64 Mach-O and is good enough
to **install + probe**. It may still link Apple frameworks for TLS (visible at
load/bind). That is expected data for G1/G2 — not a reason to vendor macOS
system binaries or cross-compile in-tree.

## Status

| Item | State |
| --- | --- |
| Download install like 7zip | done |
| Guest path `/usr/local/bin/curl` | done |
| `docker-curl.sh` (like `docker-7zz.sh`) | done |
| `docker-curl-probe.sh` (G1/G2 capture) | done |
| G1 first probe (`--version`) | **fail at load** (see below) |
| Syscall handlers from G2 log | after load/bind succeeds |

### G1 log (Docker probe iteration)

**Path map / install (like 7zip):**

```bash
./scripts/docker-curl.sh --version          # everyday
./scripts/docker-curl-probe.sh --version    # + logs under .tmp/kh-curl-probe/
```

| Guest | Host (Docker bottle) |
| --- | --- |
| `/usr/local/bin/curl` | `.kh/data/bottle/usr/local/bin/curl` |

**Progress (trace-first):**

1. Load failed: `__DefaultRuneLocale` → freestanding locale tables.
2. Then `_fread` / string surface / `dyld_stub_binder` alias.
3. CF/Security two-level binds: flat fallback + apple stubs + `_kh_missing_symbol`
   catch-all for remaining strong imports (~100) so load can finish.
4. Guest **runs** but still exits **127** when the first bound-missing import is
   actually *called* (not yet which name — implement next real body from use).
5. Freestanding C `*printf` (`printf_fmt.c`, force-loaded) for stable-Rust lack of
   `c_variadic`.

No `unknown BSD syscall` yet — still pre-network, filling libSystem surface.

Default download still lists Apple frameworks (TLS); HTTP may avoid them if those
stubs are never called.
