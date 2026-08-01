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
| Stub surface called later | full `msg_control` ancillary, rich `sscanf` formats, real `setjmp` restore — only if a path hits them hard |
| Real Security.framework | Out of scope; soft SecTrust remains for AppleSecTrust feature bit |
| `/etc/ssl/openssl.cnf` seed | Optional quieting of OpenSSL probe |
| Broader curl CLI | POST, auth, proxies, HTTP/2–3 end-to-end, FTP — implement trace-first only when a gate needs them |

### Recent freestanding polish (UTM crash fix)

UTM log showed `[kh-libsystem] missing symbol called: _nl_langinfo` mid HTTP GET
(after first `poll`/`EAGAIN`). Added "C" locale `nl_langinfo` / `nl_langinfo_l`
plus related surface hit on the same unresolved-bind list:

| Area | Symbols |
| --- | --- |
| Locale | `nl_langinfo`, `nl_langinfo_l` |
| stdio | `fseek`/`fseeko`, `ftell`/`ftello`, `getc`, `freopen`, `rewind` |
| Time | `gmtime_r`, `localtime_r`, `difftime`, `strftime` (subset) |
| String | `strpbrk`, `memmem`, `memset_s`, `basename` |
| Mem | `mmap`, `munmap`, `mprotect`, `mlock` (soft) |
| Misc | `rand`/`srand`, `sigaction` (soft), `getpwuid_r`, `__darwin_check_fd_set_overflow` |

After freestanding changes: rebuild dylib → `./scripts/stage-libsystem.sh` →
`kh bottle ensure` (or Docker helpers, which stage when a built dylib is present).

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

# CLI option matrix (tier1 HTTP polish; tier2 cookies/http2/…)
./scripts/docker-curl-options.sh tier1
./scripts/docker-curl-options.sh tier2
# → .tmp/kh-curl-options/summary.txt
```

| Guest | Host (Docker) |
| --- | --- |
| `/Volumes/linux/out/…` | `<repo>/.tmp/kh-out/…` |
| `/usr/local/bin/curl` | `.kh/data/bottle/usr/local/bin/curl` |

### Option smoke (Docker)

Not a claim that every curl flag works end-to-end — only the cases in
`scripts/docker-curl-options.sh`. Exit 0 (or expected non-zero) and no
`missing symbol called:`.

```bash
./scripts/docker-curl-options.sh tier1
./scripts/docker-curl-options.sh tier9-10
./scripts/docker-curl-options.sh all          # tier1..10
```

| Tier | Focus | Result |
| --- | --- | --- |
| **1** | Core HTTP/HTTPS polish | **pass** |
| **2** | cookies, compressed, range, http2, json, retry | **pass** |
| **3** | output/FS/trace/`-R`/url helpers/form data | **pass** |
| **4** | transfer control | **pass** |
| **5** | TLS surface | **pass** |
| **6** | auth soft + dead proxy/socks | **pass** |
| **7** | multi-URL / parallel / resolve / connect-to | **pass** |
| **8** | HTTP/3, DoH, HSTS/alt-svc, TFO, xattr | **pass** |
| **9** | `file://`, upload, FTP/SSH/SMTP/… soft, `--manual` | **pass** |
| **10** | live local HTTP + HTTP proxy + unix socket + DNS leftovers | **pass** |

**tier9–10** Docker: **pass=42 fail=0**. Notable green hard paths:

- `file://` + `-T` upload  
- live **HTTP proxy** (plain + CONNECT HTTPS)  
- live **`--unix-socket`** (AF_UNIX + bottle path translation)  
- FTP to `ftp.gnu.org` (soft success), gopher/dict soft success  
- `--manual` exits without missing-symbol  

Freestanding leftovers closed: `setjmp`/`longjmp`, `sscanf`, `fnmatch`,
`realpath`, `socketpair`, `getnameinfo`, `getservby*`, `gethostbyname`,
`kqueue`/`kevent` soft, `tcgetattr`/`tcsetattr`, `notify_*`.

Runtime: AF_UNIX sockaddr layout + `translate_path` (sun_len=0 uses connect
addrlen).

Not claimed: real 401 Digest/NTLM challenge servers, full FTP feature matrix,
production-grade client cert PKI. Further flags → extend the script
**trace-first**.

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
