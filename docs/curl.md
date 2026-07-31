# Curl milestone

Product goal: run a **Darwin `curl`** under `kh` on Linux aarch64 and prove
**network I/O**. Clean-room ABI; internet allowed. Clippy + unit tests; Docker
Colima first, UTM later.

**Method: trace-first.** Download a real Darwin arm64 binary → install into the
bottle → `kh run` / `kh trace` → implement only what the log shows.

See also: [roadmap](roadmap.md), [architecture](architecture.md), root
[README — What works](../README.md#what-works).

## Status (gates)

| Gate | Pass criteria | State |
| --- | --- | --- |
| G0 | `kh install curl` → guest `/usr/local/bin/curl` | **pass** |
| G1 | `kh run curl -- --version` banner + exit 0 | **pass** |
| G2 | Stable missing-syscall / symbol list from probes | **pass** (happy path covered) |
| G3 | HTTP GET body + clean exit 0 | **pass** (Docker + UTM) |
| G4 | HTTPS GET body + clean exit 0 (real OpenSSL + CA) | **pass** (Docker; CA bundle) |
| G5 | UTM bare-metal confirm | **pass** (HTTP body + exit 0 on UTM) |

**Product milestone: met** for version / HTTP / HTTPS GET of public sites under
Docker, and HTTP GET under UTM.

### Harmless log noise

| Log | Meaning |
| --- | --- |
| `open fail … /etc/ssl/openssl.cnf` | Optional OpenSSL config; not required for GET |
| `skip dylib … Security/CoreFoundation/…` | Apple frameworks absent; soft stubs |
| `unresolved strong symbol; … trampoline` | Bound but not called on happy path |
| soft CF/Security tags | Load-time stubs; verify path uses OpenSSL + bottle CA |

### What remains (curl polish, not blockers)

| Item | Notes |
| --- | --- |
| HTTPS on UTM smoke | Same commands as G4; confirm after `bottle ensure` on bare metal |
| Self-signed / badssl negative | Docker: expect non-zero; re-check on UTM if TLS path changes |
| Stub surface called later | e.g. `freopen`, more time/string APIs when a flag path hits them |
| Real Security.framework | Out of scope; soft SecTrust remains for AppleSecTrust feature bit |
| `/etc/ssl/openssl.cnf` seed | Optional quieting of OpenSSL probe |
| Broader curl CLI | POST, auth, proxies, HTTP/2–3 end-to-end, FTP — implement trace-first only when a gate needs them |

Next **product** surface after curl: **git** ([roadmap](roadmap.md)).

## Where the binary lives

Same pattern as 7zip:

| | Path |
| --- | --- |
| **Guest** | `/usr/local/bin/curl` |
| **Host (default bottle)** | `~/.local/share/kakehashi/bottle/usr/local/bin/curl` |
| **Docker probe bottle** | `<repo>/.kh/data/bottle/usr/local/bin/curl` |
| **Relative under bottle root** | `usr/local/bin/curl` (`GUEST_CURL_REL`) |
| **CA bundle (guest)** | `/etc/ssl/cert.pem` → bottle `private/etc/ssl/cert.pem` (host CA or download) |

`kh run curl` resolves the bare name via guest `PATH` (`/usr/local/bin`, …).

## Install

```bash
kh bottle ensure
kh install curl
# → downloads Darwin arm64 archive, installs guest /usr/local/bin/curl
# → seeds CA into private/etc/ssl/cert.pem (host store, or Mozilla download)
```

- Default curl URL: `DARWIN_CURL_URL` in `crates/kh-runtime/src/bottle/guest_tools.rs`
  (stunnel/static-curl `curl-macos-arm64-*.tar.xz`).
- Skip curl download: `KAKEHASHI_CURL=/path/to/curl kh install curl`.
- CA seed order: existing bottle file → `KAKEHASHI_CA_BUNDLE` → host
  `ca-certificates` / `/etc/ssl/cert.pem` → download
  [`https://curl.se/ca/cacert.pem`](https://curl.se/ca/cacert.pem) (needs host
  `curl`/`wget`). **Not vendored in-tree** — stays current via OS or download.
- Needs host `curl`/`wget` + `tar` for install/download helpers.

## Working commands

### Local (Linux aarch64 / UTM)

```bash
kh bottle ensure
kh install curl

kh run curl -- --version

# HTTP (G3/G5)
kh run curl -- -sS -o .tmp/kh-out/body http://example.com/
echo exit:$?
wc -c .tmp/kh-out/body

# HTTPS (G4)
kh run curl -- -sS -o .tmp/kh-out/https-body https://example.com/
echo exit:$?
wc -c .tmp/kh-out/https-body

# Negative verify
kh run curl -- -sS -o /dev/null https://self-signed.badssl.com/
echo badssl_exit:$?   # expect ≠ 0
```

Relative `-o` paths use the **host CWD** of `kh`. Missing parents for
`O_CREAT` opens are auto-created by the runtime.

### Docker (Colima)

```bash
./scripts/docker-curl.sh --version
./scripts/docker-curl.sh -sS -o /Volumes/linux/out/body http://example.com/
./scripts/docker-curl.sh -sS -o /Volumes/linux/out/https-body https://example.com/
# host: .tmp/kh-out/body , .tmp/kh-out/https-body

# Trace-first expansion
./scripts/docker-curl-probe.sh --version
# → .tmp/kh-curl-probe/
```

| Guest | Host (Docker) |
| --- | --- |
| `/Volumes/linux/out/…` | `<repo>/.tmp/kh-out/…` |
| `/usr/local/bin/curl` | `.kh/data/bottle/usr/local/bin/curl` |

## Trace-first progress (summary)

1. Load: `__DefaultRuneLocale`, `fread`/string surface, `dyld_stub_binder`, CF soft stubs.
2. G1: `fcntl` → pthread/TSD → fopen → banner **exit 0**.
3. G3: sockets/`pipe` O_NONBLOCK, poll, sendto/recvfrom, `getaddrinfo` helper,
   resolv.conf seed, clean exit (non-blocking sockets so keep-alive recv → EAGAIN).
4. G4: OpenSSL TLS + bottle CA (host or downloaded `cacert.pem`); host `VERIFY_CERT`; self-signed fails.
5. G5: UTM HTTP GET body + exit 0; fixes along the way: `strerror_r`, `-o` parent mkdir.

Do **not** pre-land a full speculative socket table without a probe log.

## Note on the default download

The stunnel static macOS arm64 build is a real arm64 Mach-O. It may still
*reference* Apple frameworks for TLS (visible at load/bind). Crypto for HTTPS
GET uses **OpenSSL** from that binary plus the bottle CA — not a vendored
macOS Security.framework.
