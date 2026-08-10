# Git / Xcode Command Line Tools milestone

**Status: milestone met** (G0–G8). Same class as [curl](curl.md): day-to-day
Apple CLT `git` under `kh` on Linux aarch64 is usable; remaining work is polish,
not open gates.

Product goal: run **Apple `git`** (from official Command Line Tools) under `kh`
on Linux aarch64. Clean-room ABI; trace-first. Clippy + unit tests; Docker
Colima first.

See also: [roadmap](roadmap.md), [architecture](architecture.md), [curl](curl.md).

## Status (gates)

| Gate | Pass criteria | State |
| --- | --- | --- |
| G0 | `kh install xcode-tools` → bottle has CLT + `…/usr/bin/git` | **pass** (swscan, no Apple ID) |
| G1 | `kh run git -- --version` banner + exit 0 | **pass** (Docker + UTM: `git version 2.50.1 (Apple Git-155)`) |
| G2 | Missing surface from probes | **met** for product paths (HTTPS freestanding libcurl + SSH host bridge) |
| G3 | Local repo: `init` / `status` / `add` / `commit` | **pass** (Docker + UTM; commit exit 0) |
| G4 | Remote over HTTPS (reuse curl network path) | **pass** (Docker: `ls-remote`, shallow + full clones) |
| G5 | Remote over SSH (host OpenSSH bridge) | **pass** (local sshd + real GitHub/GitLab; see below) |
| G6 | Push + branches to private remote | **pass** (Docker: private bare `0700` + SSH; see `scripts/docker-git-push.sh`) |
| G7 | Plain `http://` on socket path (freestanding) | **pass** (Docker smart HTTP; see `scripts/docker-git-http.sh`) |
| G8 | Authenticated GitHub under Docker | **pass** (private SSH push + HTTPS Basic; see `scripts/docker-git-github.sh`) |

### Verified large / real-world clones

| Guest command (under `kh` / Docker) | Host / remote | Result |
| --- | --- | --- |
| Full history `clone` of **Wine** | GitHub and GitLab remotes | **pass** (full history; multi‑M objects / large pack path) |
| `clone --depth 1` **llvm/llvm-project** | `git@github.com:llvm/llvm-project.git` | **pass** (Docker; SSH) |
| `clone --depth 1` linux kernel | HTTPS GitHub | **pass** (~279 MiB pack, ~2 GiB tree) |
| Full `clone` facebook/folly | HTTPS GitHub | **pass** (~97 MiB, ~3k files) |
| Full `clone` small + mid repos | HTTPS (Hello-World, this repo, …) | **pass** |

Full multi‑GiB monorepos (e.g. complete llvm history) are **not** a release
blocker: when the network/host rate-limits the pack, abort is external, not an
ABI gap. Shallow llvm + full Wine already exercise the heavy `index-pack` /
streaming path.

```text
# Large shallow monorepo over SSH (host keys + known_hosts)
./scripts/docker-kh.sh git -- clone --depth 1 git@github.com:llvm/llvm-project.git

# Wine full history (HTTPS or SSH; GitHub or GitLab URL)
# ./scripts/docker-kh.sh git -- clone https://github.com/wine-mirror/wine.git
# ./scripts/docker-kh.sh git -- clone https://gitlab.winehq.org/wine/wine.git
```

### G5 notes (SSH / host OpenSSH bridge)

Apple CLT does **not** ship OpenSSH (base macOS does). `git` SSH remotes
(`git@host:path`, `ssh://…`) call `execvp("ssh")`. Product approach:

| Piece | Location |
| --- | --- |
| Guest `/usr/bin/ssh` | Bottle symlink → host `/usr/bin/ssh` via `Volumes/linux` ([`layout::ensure_host_ssh_bridge`](../crates/kh-runtime/src/bottle/layout.rs)) |
| Guest `/bin/sh` | Host shell bridge ([`layout::ensure_host_bin_bridges`](../crates/kh-runtime/src/bottle/layout.rs)) — required for `GIT_SSH_COMMAND` (`sh -c`) |
| `execve` of host ELF | `reexec_direct` — native Linux OpenSSH (not nested `kh`) |
| Host env rewrite | `HOME=/Volumes/linux…` → real host `HOME` so `~/.ssh` works |
| Soft env | `GIT_SSH` / `GIT_SSH_COMMAND` seeded from host (same as other `GIT_*`) |
| Docker image | `openssh-client` (+ `openssh-server` for local smoke) |

**Not** a freestanding SSH protocol stack (clean-room: host client only).

```text
# Local full path (sshd + keys inside the container; no GitHub account):
./scripts/docker-git-ssh.sh
# → ls-remote + clone over ssh://127.0.0.1:2222/… ; README in .tmp/kh-out/ssh-smoke

# Against GitHub — host OpenSSH needs a **file** key under ~/.ssh (agent-only
# keys on macOS launchd do not reach Colima). docker-kh git bind-mounts
# ~/.ssh → /root/.ssh. Generate + register once if missing:
#   ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N ""
#   # add ~/.ssh/id_ed25519.pub at https://github.com/settings/keys
./scripts/docker-kh.sh git -- clone git@github.com:octocat/Hello-World.git
# Public repos without a key still fail: Permission denied (publickey).
```

### G4 notes (HTTPS / freestanding libcurl)

`git-remote-http` `LC_LOAD`s `/usr/lib/libcurl.4.dylib` (plus soft-skipped
`libz` / `libiconv` / `libexpat` / CoreServices). Product approach matches
`libc++`:

| Piece | Location |
| --- | --- |
| `curl_*` C ABI | freestanding `kh-libsystem` (`src/dylib/libcurl/`) — clean-room, not upstream libcurl |
| Bottle alias | `usr/lib/libcurl.4.dylib` → `libSystem.B.dylib` ([`layout::ensure_libcurl_symlink`](../crates/kh-runtime/src/bottle/layout.rs)) |
| HTTPS I/O (path B) | `KH_HELPER_TLS_CONNECT` → host TCP + **rustls**; guest `read`/`write` on TLS-wrapped FD are **plaintext**; freestanding builds HTTP/1.1 and streams body into `write_fn` (no multi‑GiB guest buffer) |
| Plain HTTP (path B) | same helper + **`TLS_FLAG_PLAIN`** (bit1): TCP only, no rustls; same HTTP/1.1 streamer — **G7** |
| Legacy | `KH_HELPER_HTTP` (host `curl` CLI + 64 MiB body cap) kept for tools that still call it; freestanding `easy_perform` no longer uses it for HTTPS |
| Loader alias fix | map `install_name` from **LC_LOAD** (not only LC_ID) so two-level ordinals against `libcurl.4.dylib` resolve |

**Progress (HTTPS list via freestanding libcurl):**

| Step | State |
| --- | --- |
| `capabilities` | **pass** |
| Helper `list` (protocol v0/v1) | **pass** — refs from GitHub |
| Protocol **v2** (`ls-refs` / fetch) | **pass** — default in `docker-kh.sh git` |
| Host HTTP helper + body + `Content-Type` | **pass** |
| `git ls-remote https://…` (spawned helper) | **pass** (Docker; v1 and v2) |
| `git clone --depth 1 https://…` | **pass** (Docker; working tree + objects) |
| `git clone https://…` (full, small repo) | **pass** (Docker; Hello-World; TLS socket path) |
| `git clone https://…` (full, ~9 MiB pack) | **pass** (Docker; this repo after inflate fix) |
| `git clone --depth 1` linux kernel | **pass** (Docker; ~279 MiB pack, ~2 GiB tree; path B streaming) |
| `git clone` facebook/folly (full, v2) | **pass** (Docker; ~97 MiB, ~3k files) |
| Full **Wine** history (GitHub + GitLab) | **pass** (full clone; large object table / heapsort path) |
| `git clone --depth 1` llvm-project (SSH) | **pass** (Docker; `git@github.com:llvm/llvm-project.git`) |

```text
# capabilities
printf 'capabilities\n\n' | kh run …/git-remote-http -- origin https://…
# → stateless-connect / fetch / get / …

# list (classic v0/v1 helper path; with protocol.version=2 git uses ls-refs)
printf 'list\n\n' | kh run …/git-remote-http -- origin https://github.com/octocat/Hello-World.git
# → @refs/heads/master HEAD / 7fd1a60b… refs/heads/master / …

# full spawn path (protocol.version=2 default)
kh run git -- ls-remote https://github.com/octocat/Hello-World.git
# → 7fd1a60b…\tHEAD / 7fd1a60b…\trefs/heads/master / …

# shallow clone
kh run git -- clone --depth 1 https://github.com/octocat/Hello-World.git hw
# → exit 0; hw/README present

# full clone (TLS path B streaming)
kh run git -- clone https://github.com/octocat/Hello-World.git hw-full
# → exit 0; hw-full/README present
```

**Fixes landed for G4 (list / ls-remote / clone):**

1. **Apple arm64 varargs** — `curl_easy_setopt` / `curl_easy_getinfo` are
   `...` APIs; Darwin places the value on the **stack**, not in `x2`. C wrappers
   in `curl_varargs.c` (`va_arg`) call Rust `kh_curl_easy_*_impl`. Without this,
   `CURLOPT_HTTPHEADER` became `0x5` → SEGV walking the slist.
2. **`fcntl` varargs** — same ABI: `int fcntl(int, int, …)`. Fixed 3-arg export
   never saw `O_NONBLOCK` from curl multi → empty wakeup-pipe `read` hung
   forever (`docker-curl-options.sh` tier1). C wrapper in `fcntl_varargs.c` →
   `kh_fcntl_impl`.
3. **Guest `O_NONBLOCK` tracking** — host pipes/sockets stay non-blocking for
   multi; I/O emulates Darwin **blocking** until the guest `fcntl(F_SETFL)`.
   Nested re-exec clears nonblock on stdio pipes (helper stdin).
4. **`Content-Type`** — smart HTTP discovery needs
   `application/x-git-upload-pack-advertisement`. Host helper parses `-D`
   headers into `KhHttpReq` v2 `out_ctype`; freestanding exposes it via
   `CURLINFO_CONTENT_TYPE`. Missing type made git treat the body as dumb HTTP
   → `info/refs not valid`.
5. **PAGEZERO guards** — low 4 GiB guest pointers rejected in string/curl walks.
6. **Nested `HOME`** — re-exec of Mach-O helpers inherits guest
   `HOME=/Volumes/linux…` as host env; do not prefix again
   (`/Volumes/linux/Volumes/linux/…` broke `~/.gitconfig` / `protocol.version`).
7. **Guest `PATH`** — include CLT `…/libexec/git-core` so `execvp(git-remote-https)`
   finds the helper.
8. **POSIX `regcomp`/`regexec`** — freestanding C ABI + host helpers
   (`KH_HELPER_REG*`, host `regex` crate). In-dylib `regex-automata` was
   dropped: workspace feature-unification with `tracing-subscriber` enabled
   its `std` feature and collided with freestanding `#[panic_handler]`.
9. **`GIT_*` env pass-through** — nested `kh run` after re-exec must seed
   soft environ + stack with host `GIT_DIR` / friends (`KH_HELPER_GETENV`);
   without this: `remote-curl: fetch attempted without a local repo`.
10. **`setitimer`/`getitimer` soft stubs** — clone progress ticker mid-checkout.
11. **CodeQL `rust/access-invalid-pointer` on `easy_from`** — explicit
    `p.is_null()` before PAGEZERO (NotNullCheckBarrier); OOM path of
    `curl_easy_init` returns `null_mut` and must not be treated as live.
12. **HTTPS path B (TLS guest FD + freestanding HTTP/1.1)** — replaces host
    `curl` CLI + 64 MiB body cap for freestanding `easy_perform`:
    - `KH_HELPER_TLS_CONNECT` (`0x4B48_0011`): host TCP + rustls handshake
      (bottle CA); returns guest FD. **G7:** `TLS_FLAG_PLAIN` (bit1) skips
      rustls for `http://` (same HTTP/1.1 streamer on a raw TCP guest FD).
    - Host `read`/`write` on that FD decrypt/encrypt via rustls; guest sees
      plaintext (same as a completed TLS socket from the app’s POV).
    - Freestanding builds request, parses response headers, streams body
      (`Content-Length` / chunked / EOF) into curl `write_fn` in 64 KiB chunks.
    - **POST body**: gather `POSTFIELDS` or `READFUNCTION` (git large want lists);
      if guest sets `Content-Encoding: gzip` but freestanding `deflate` only
      emits zlib-wrapper (not true gzip), **decode zlib + strip CE** before
      send — otherwise GitHub returns **HTTP 400** on full monorepo clones.
    - Verified: Hello-World full clone; **linux** shallow + full `clone` POST
      accepted (pack download) under Docker.
    - **TLS wire flush**: never drop unsent ciphertext on `EAGAIN` (pending
      buffer); flush after `process_new_packets` (TLS 1.3 KeyUpdate). Missing
      this caused `curl 7 chunk data short` / `bad pack header` mid multi‑GiB
      pack streams when the TCP send buffer filled.
    - **TLS deframer**: `process_new_packets` after every `read_tls` +
      `pending_in` leftover wire. Without this, multi-record TCP segments hit
      rustls `message buffer full` → `chunk trailer read fail` early in linux
      full clone.
13. **Freestanding `inflate` rewrite (miniz streaming + git ABI)** — multi‑MiB
    packs failed at `index-pack` (`pack has bad object … inflate returned -3/-5`).
    Root causes vs Apple `git` 2.50 `index-pack`:
    - Hand-rolled NON_WRAPPING history missed miniz `HAS_MORE_INPUT` semantics.
    - Missing `inflateReset` / `deflateReset` (git reuses one `z_stream`).
    - miniz `MZFlush::Finish` clears HAS_MORE; git multi-calls with partial
      windows — always drive miniz with `MZFlush::None`, end via zlib trailer.
    - `index-pack` loops only while `status == Z_OK` (not `Z_BUF_ERROR`); map
      “need more input” Buf → `Z_OK`. Empty `avail_out` still probes StreamEnd.
    Verified: `index-pack` of ~9 MiB pack + full `clone` of this repo (Docker).
14. **`close(0/1/2)` must really close** — stdio was identity-mapped and
    `close` soft-succeeded without dropping the host pipe. Apple
    `fetch-pack --stateless-rpc` does `close(1)` *before* printing the
    fetched-ref list to stdout; on Darwin those writes fail harmlessly, but
    under kh they still reached remote-curl → parent as hundreds of
    `https unexpectedly said: '<sha> refs/…'` lines after an otherwise green
    clone (e.g. **facebook/folly**: 560 heads+tags). Fix: track closed stdio,
    `host close` on take, `EBADF` on later I/O, re-open via `dup2` onto 0/1/2.
    Verified: full `clone https://github.com/facebook/folly` under Docker
    (v1 and v2) — exit 0, no `unexpectedly said` flood.
15. **Protocol v2** — smart HTTP `Git-Protocol: version=2` + `ls-refs` /
    `fetch` (via Apple `git-remote-http` `stateless-connect`) works over path B
    TLS FDs. Verified Docker: `ls-remote`, Hello-World full clone, this repo
    shallow clone, **facebook/folly** full clone (~75 s, 3075 files); default in
    `scripts/docker-kh.sh git` is now `protocol.version=2` (v1 remains if set).
16. **`qsort` heapsort** — freestanding `_qsort` was insertion sort O(n²). After
    `Resolving deltas: 100%`, `index-pack` sorts the object table; wine
    (~1.37M objects) hung for hours in pure CPU with no `.idx`. Replaced with
    heapsort O(n log n). Verified: `kh` `index-pack -v` on wine pack → exit 0
    in ~112 s, 37 MiB `.idx` (native ~135 s).

17. **SSH host bridge (G5)** — guest `/usr/bin/ssh` → host OpenSSH
    (`../../Volumes/linux/usr/bin/ssh`); guest `/bin/sh` for `GIT_SSH_COMMAND`;
    `HOME` bridge rewrite on host-native `execve`; `GIT_SSH` /
    `GIT_SSH_COMMAND` in soft-env seed. Local Docker smoke:
    `scripts/docker-git-ssh.sh` (sshd + bare repo + `ls-remote` + `clone`).
    GitHub needs keys + `known_hosts` (plain `ls-remote git@…` reaches OpenSSH:
    host-key / publickey errors, not missing `ssh`).

### G6 notes (push / private bare / branches)

Push reuses the G5 host OpenSSH bridge (`git-receive-pack` over `ssh://`).
No new freestanding network stack: clean-room host client only.

| Piece | Detail |
| --- | --- |
| Private remote | Host `git clone --bare` + `chmod 700`; SSH pubkey only (no password) |
| Why not GitHub | Smoke needs no account/token; local bare stands in for a private remote |
| Branches | `checkout -b`, commit, `push -u origin <branch>`, FF push, merge + `push main` |
| Docker helper | `scripts/docker-git-push.sh` |

```text
./scripts/docker-git-push.sh
# → clone private bare over SSH → feature branch → push -u → FF push →
#   merge to main → push main; verifies refs on the bare remote
```

**Provenance (G6):** observed Apple `git push` → `execvp(ssh)` → host OpenSSH
→ `git-receive-pack` on bare; no Darling; no proprietary paste. Surface already
covered by G3 (spawn/FS) + G5 (SSH bridge).

**Related:** authenticated GitHub private push/clone is **G8**. HTTPS
`git-receive-pack` uses the same freestanding path as clone (also exercised by
G7 over plain `http://`).

### G7 notes (plain `http://` socket path)

Freestanding libcurl previously rejected `http://` (`only https supported on
socket TLS path`). G7 adds **`TLS_FLAG_PLAIN`** on `KH_HELPER_TLS_CONNECT`:

| Piece | Detail |
| --- | --- |
| Host | `tls_fd::connect` with plain flag → TCP, guest FD **without** rustls slot |
| Guest | freestanding `perform_easy` calls the same HTTP/1.1 path as HTTPS |
| Smoke | local `git-http-backend` CGI on `127.0.0.1` — no public network |
| Docker helper | `scripts/docker-git-http.sh` |

```text
./scripts/docker-git-http.sh
# → ls-remote http://127.0.0.1:…/repo.git → clone → branch → push
```

**Provenance (G7):** observed need from failed `ls-remote http://…` under kh;
POSIX/HTTP/1.1 + existing path B; clean-room host TCP; no Darling.

### G8 notes (authenticated GitHub under Docker)

| Piece | Detail |
| --- | --- |
| SSH | Host `~/.ssh` → container `/root/.ssh:ro`; `GIT_SSH_COMMAND` + writable `known_hosts` |
| HTTPS Basic | URL userinfo `https://x-access-token:TOKEN@github.com/…` → freestanding `Authorization: Basic` (base64) |
| Private remote | Host `gh` creates/reuses `OWNER/kh-kakehashi-smoke` (private); smoke force-pushes |
| Token | Host `gh auth token` → docker env only; never printed |
| Docker helper | `scripts/docker-git-github.sh` |

```text
# Host: gh auth login (repo scope); SSH key on GitHub
./scripts/docker-git-github.sh
# → private create/reuse → SSH push → HTTPS ls-remote/clone of private
```

**Provenance (G8):** G5 SSH bridge + freestanding path B; userinfo/Basic from
RFC 7617 / curl man page contracts; no Darling. Optional delete needs
`delete_repo` (`gh auth refresh -h github.com -s delete_repo` + `KH_DELETE_REPO=1`).

### What remains (git polish, not blockers)

| Item | Notes |
| --- | --- |
| Full multi‑GiB monorepo soak under wall-clock budget | Wine full history + llvm shallow already green; unlimited full llvm-class clones depend on host/network rate limits |
| Credential helper noise | Host `credential.helper=osxkeychain` may WARN under Linux bottle (harmless; smoke scripts clear it) |
| Broader remote helpers | LFS, `git svn`, rare helpers — not product gates |

Stage freestanding with **release** dylib when changing `kh-libsystem`:

```bash
cargo build -p kh-libsystem --release --target aarch64-apple-darwin
./scripts/stage-libsystem.sh
```

(so `stage-libsystem` does not pick a stale release over a newer debug build).

### G3 notes (path, uid, zlib, printf)

Apple `git` calls `getcwd` early and builds absolute paths. Freestanding
`getcwd` used to return `"/"`. Host workdirs now map as:

| Host CWD | Guest path from `getcwd` |
| --- | --- |
| `/tmp/repo` | `/private/tmp/repo` (Darwin layout; host bridge) |
| other host path | `/Volumes/linux` + host absolute |
| under bottle | bottle-relative absolute (`/usr/…`) |

Path translation special-cases `/private/tmp`, `/tmp`, and `/Volumes/linux`
so git’s own `readlink` realpath (which collapses `/Volumes/linux` → `/`) still
hits the host FS.

Also for G3: `chdir`, identity `iconv_*`, soft `atexit`, host
`getuid`/`geteuid`/`getgid`/`getegid` (fixes `safe.directory` when files are
root-owned under Docker), `strtoimax`/`strtoumax`, `getdelim`/`getline`,
freestanding **zlib** (`deflate*`/`inflate*`/`crc32`/`adler32` via
`miniz_oxide` with **history-buffered inflate** for streaming),
`pread`/`pwrite`, `mkstemp`, `___strlcpy_chk`, **real spawn** (`fork` /
`waitpid` / `dup2` / `execve` → re-exec `kh run` for Mach-O; scripts via
shebang), real **`_environ`** data symbol (+ soft `getenv`/`setenv` table),
`setsid`/`setpgid`/`getpgrp`/`kill`, soft `pthread_setcancelstate`, `putc`.

**Printf** must implement POSIX `ssize_t` error returns as **`-1` + errno**
(not `-errno`): git’s `is_reinit()` does `readlink(...) != -1`, so `-ENOENT`
was treated as “HEAD exists” and skipped creating `.git/HEAD`.

**Printf formats** needed by git pathspec / tree write: `%.*s`, `%*s`, `%o`
(octal modes). Missing `%.*s` produced paths like `%*s(null)` and
`fatal: pathspec … did not match`.

After freestanding changes: rebuild dylib → `./scripts/stage-libsystem.sh` →
`kh bottle ensure` (or Docker helpers). Clippy: host crates +
`kh-libsystem --target aarch64-apple-darwin`.

### G3 smoke (Docker / UTM)

```bash
# Host identity once (visible under kh via HOME bridge):
git config --global user.email "you@example.com"
git config --global user.name "Your Name"

rm -rf /tmp/kh-g3 && mkdir -p /tmp/kh-g3 && cd /tmp/kh-g3
kh run git -- init
printf 'hi\n' > README
kh run git -- add README
kh run git -- commit -m init          # no -c needed when ~/.gitconfig bridges
kh run git -- log --oneline          # e.g. 7cdb95d init
kh run git -- status                  # clean on main
# (nothing-to-commit → guest exit 1 is normal git)
```

| Note | Detail |
| --- | --- |
| Spawn | Host `fork` + `waitpid` + `dup2`; `execve` of Mach-O re-execs `kh run <path> -- args`. Nested injects host `KAKEHASHI_ROOT` / `CONFIG_DIR` / `DATA_DIR` (resolved in the parent) so guest `HOME=/Volumes/linux…` does not break bottle discovery. |
| HOME | Guest `HOME=/Volumes/linux{host $HOME}` so host `~/.gitconfig` is readable. Confirm: `kh run git -- config user.name`. |
| FSEvents | Soft stubs in freestanding libSystem (`FSEventStreamCreate` → null). Nested post-commit `git maintenance --detach` used to fail load when bottle was lost under guest HOME (`unresolved symbol _FSEventStreamCreate`); fixed by always injecting host KAKEHASHI_* paths on re-exec. |
| `_environ` | Must be a **data** export. Binding a missing-function trampoline here made git walk trampoline bytes as `char **` and SIGSEGV after `pipe` in `start_command`. |
| Pipe | Host `pipe(2)` is `O_NONBLOCK` (curl/c-ares). Guest-visible `O_NONBLOCK` is tracked per FD; blocking semantics are emulated until `fcntl(F_SETFL)`. Nested re-exec forces stdio pipes blocking for helpers. |
| Open-fail WARN | Expected ENOENT probes (`.gitignore`, empty index, templates, attributes) |

## Install (public Software Update catalog)

Nothing is vendored in-tree. `kh install xcode-tools` (aliases: `clt`, `git`):

1. **Catalog** — fetch a public `*.sucatalog` from
   [`swscan.apple.com`](https://swscan.apple.com) (same source as macOS
   `softwareupdate` / `xcode-select --install`). **No Apple ID, no cookies.**
2. **Select** — product that ships `CLTools_Executables*.pkg`; prefer latest
   stable title (currently **Command Line Tools for Xcode 26.6**).
3. **Download** — same product’s packages from `swcdn.apple.com` into the
   **persistent cache** under `$KAKEHASHI_DATA_DIR/cache/downloads/`:
   - `CLTools_Executables*.pkg` — toolchain (`git`, `clang`, …)
   - `CLTools_macOSNMOS_SDK.pkg` — current major SDK (folder e.g. `MacOSX26.5.sdk`)
   - *not* LMOS (previous major), empty `CLTools_macOS_SDK.pkg`, Remove pkgs, Swift
4. **Extract** — built-in **XAR → pbzx → odc cpio** (no p7zip for `.pkg`).
5. **Bottle** — `{bottle}/Library/Developer/CommandLineTools/…` plus
   `{bottle}/usr/bin/git` → CLT git and `SDKs/MacOSX.sdk` → NMOS versioned SDK.

Optional pin: `KAKEHASHI_XCODE_TOOLS_VERSION=26.6` (substring match on title).

**Version naming:** catalog title is CLT/Xcode **26.6**; the SDK *directory*
inside NMOS is currently `MacOSX26.5.sdk` (Apple’s packaging — not a pin bug).

### Docker: do not re-download every run

Helpers set `KAKEHASHI_DATA_DIR=/src/.kh/data` on the repo bind mount. After the
first successful install:

| Layer | Path (host, under repo) | Behaviour on next `docker run` |
| --- | --- | --- |
| Bottle install | `.kh/data/bottle/Library/Developer/CommandLineTools/` | **no-op** if `usr/bin/git` + SDK headers present |
| Archive cache | `.kh/data/cache/downloads/CLTools_Executables*.pkg` (+ NMOS SDK) | reused if bottle wiped but cache kept |
| Extract cache | `.kh/data/cache/extract/command-line-tools/` (+ `-sdk-*`) | skip re-extract when tree valid |
| Catalog cache | `.kh/data/cache/downloads/software-update.sucatalog` | reused for ~24h |

Force a full re-fetch: `KAKEHASHI_FORCE_DOWNLOAD=1`.

Optional: `KAKEHASHI_CACHE_DIR` overrides the cache root (still bind-mount it).

### Working commands

```bash
kh bottle ensure
kh install xcode-tools            # second call is free if bottle intact (git + SDK)
kh run git -- --version

# optional pin / force:
# KAKEHASHI_XCODE_TOOLS_VERSION=26.6 kh install xcode-tools
# KAKEHASHI_FORCE_DOWNLOAD=1 kh install xcode-tools
```

## Docker helper

```bash
./scripts/docker-kh.sh git -- --version
```

Host image needs `p7zip-full` / `7z` for pkg peel (`Dockerfile.dev`).

## Host requirements

| Tool | Role |
| --- | --- |
| `curl` | sucatalog + swcdn download |
| (built-in) | XAR + pbzx + odc for Software Update `.pkg` |
| `7z` / `7zz` | optional fallback for `.dmg` wrappers only |

## What is out of scope

- Full Xcode.app / simulators / GUI
- Codesign / notarization
- Vendoring Apple SDKs or blobs in the git tree
- Darling-derived code
- Authenticated developer.apple.com portal downloads
- Every git extension (LFS, `git svn`, every credential helper)

## Method

Same as curl: **trace-first**. Install real Darwin `git` → `kh run` / `kh
trace` → implement only the syscalls and freestanding symbols the log shows.

Clean-room rules for all ABI work (no Darling, no proprietary paste, provenance
in PRs): **[legal-method.md](legal-method.md)**.
