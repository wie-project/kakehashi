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
| G4 | HTTPS GET under `kh` (TLS + product body) |
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
| G1 first probe (`--version`) | **pass** (banner + exit 0) |
| G3 HTTP GET | **pass** (body + clean exit 0) |
| G4 HTTPS GET | **pass** (OpenSSL TLS + soft AppleSecTrust; body + exit 0) |

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
4. Named missing trampolines (`_kh_missing_symbol_named`) so first *call* logs
   the nlist name (not just bind-time list).
5. Call-order surface for G1: `_fcntl` → `pthread_once` / rwlock / TSD / self →
   `fopen`/`fclose` → `bsearch` (+ freestanding `*printf` in `printf_fmt.c`).
6. **G1 pass:** `curl --version` prints the stunnel static-curl banner, exit 0.
7. **G3 pass (product body + clean exit):** HTTP GET writes Example Domain HTML to
   `/Volumes/linux/out/body` (≈559 B) and the guest **exits 0**. Surface added
   trace-first: `pipe` (O_NONBLOCK), socket/connect/poll/sendto/recvfrom/getsockname,
   `getaddrinfo` host helper, `inet_pton`/`ntop`, soft `dlopen`/`arc4random_buf`/
   `gethostname`, pthread mutexattr + `cond_timedwait`, bottle `private/etc/resolv.conf`
   for c-ares.
8. **Clean-exit fix:** host `socket`/`accept` force `O_NONBLOCK` (same idea as pipes).
   Without it, after a keep-alive HTTP body curl did a blocking `recv` and hung forever.
   With non-blocking sockets, post-body `recv` returns `EAGAIN` and multi finishes.

```bash
./scripts/docker-curl.sh -sS -o /Volumes/linux/out/body http://example.com/
# host: .tmp/kh-out/body  should contain "Example Domain"; exit code 0
```

9. **G4 pass (HTTPS):** `https://example.com/` writes Example Domain (≈559 B) and
   exits 0. Crypto is real OpenSSL from stunnel static-curl. Cert path uses soft
   CF/Security stubs (`SecTrustEvaluateWithError` always succeeds) because
   Apple frameworks are not in the bottle — note printed once:
   `soft SecTrust: always-succeed`. Not a real macOS trust store.

```bash
./scripts/docker-curl.sh -sS -o /Volumes/linux/out/https-body https://example.com/
# host: .tmp/kh-out/https-body  should contain "Example Domain"; exit code 0
```

**Next:** G5 UTM confirm (optional polish: host-backed trust / real CA bundle).
