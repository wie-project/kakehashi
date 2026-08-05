# Git / Xcode Command Line Tools milestone

Product goal: run **Apple `git`** (from official Command Line Tools) under `kh`
on Linux aarch64. Clean-room ABI; trace-first. Clippy + unit tests; Docker
Colima first.

See also: [roadmap](roadmap.md), [architecture](architecture.md), [curl](curl.md).

## Status (gates)

| Gate | Pass criteria | State |
| --- | --- | --- |
| G0 | `kh install xcode-tools` → bottle has CLT + `…/usr/bin/git` | **pass** (swscan, no Apple ID) |
| G1 | `kh run git -- --version` banner + exit 0 | **pass** (Docker + UTM: `git version 2.50.1 (Apple Git-155)`) |
| G2 | Missing surface from probes | **in progress** (HTTPS helper / freestanding libcurl) |
| G3 | Local repo: `init` / `status` / `add` / `commit` | **pass** (Docker + UTM; commit exit 0) |
| G4 | Remote over HTTPS (reuse curl network path) | **in progress** (`ls-remote` pass; clone open) |

### G4 notes (HTTPS / freestanding libcurl)

`git-remote-http` `LC_LOAD`s `/usr/lib/libcurl.4.dylib` (plus soft-skipped
`libz` / `libiconv` / `libexpat` / CoreServices). Product approach matches
`libc++`:

| Piece | Location |
| --- | --- |
| `curl_*` C ABI | freestanding `kh-libsystem` (`src/curl.rs`) — clean-room, not upstream libcurl |
| Bottle alias | `usr/lib/libcurl.4.dylib` → `libSystem.B.dylib` ([`layout::ensure_libcurl_symlink`](../crates/kh-runtime/src/bottle/layout.rs)) |
| HTTP(S) I/O | host helper `KH_HELPER_HTTP` (`0x4B48_000C`) runs host `curl` + bottle CA |
| Loader alias fix | map `install_name` from **LC_LOAD** (not only LC_ID) so two-level ordinals against `libcurl.4.dylib` resolve |

**Progress (HTTPS list via freestanding libcurl):**

| Step | State |
| --- | --- |
| `capabilities` | **pass** |
| Helper `list` (protocol v0/v1) | **pass** — refs from GitHub |
| Host HTTP helper + body + `Content-Type` | **pass** |
| `git ls-remote https://…` (spawned helper) | **pass** (Docker; protocol v1) |

```text
# capabilities
printf 'capabilities\n\n' | kh run …/git-remote-http -- origin https://…
# → stateless-connect / fetch / get / …

# list (protocol.version=1 in ~/.gitconfig; v2 returns empty refs by design)
printf 'list\n\n' | kh run …/git-remote-http -- origin https://github.com/octocat/Hello-World.git
# → @refs/heads/master HEAD / 7fd1a60b… refs/heads/master / …

# full spawn path
kh run git -- ls-remote https://github.com/octocat/Hello-World.git
# → 7fd1a60b…\tHEAD / 7fd1a60b…\trefs/heads/master / …
```

**Fixes landed for G4 list / ls-remote:**

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

**Still open for full G4:** `clone` / fetch pack transfer, protocol v2
`stateless-connect`. Prefer `protocol.version=1` in guest `~/.gitconfig` until
v2 RPC is complete.

Local G3 without the remote helper remains green. Curl options **tier1** is
green again after the `fcntl` varargs fix.

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
   stable title (“Command Line Tools for Xcode …”).
3. **Download** — package from `swcdn.apple.com` into the **persistent cache**
   under `$KAKEHASHI_DATA_DIR/cache/downloads/`.
4. **Extract** — built-in **XAR → pbzx → odc cpio** (no p7zip for `.pkg`).
5. **Bottle** — `{bottle}/Library/Developer/CommandLineTools/…` plus
   `{bottle}/usr/bin/git` → CLT git.

Optional pin: `KAKEHASHI_XCODE_TOOLS_VERSION=26.6` (substring match on title).

### Docker: do not re-download every run

Helpers set `KAKEHASHI_DATA_DIR=/src/.kh/data` on the repo bind mount. After the
first successful install:

| Layer | Path (host, under repo) | Behaviour on next `docker run` |
| --- | --- | --- |
| Bottle install | `.kh/data/bottle/Library/Developer/CommandLineTools/` | **no-op** if `usr/bin/git` exists |
| Archive cache | `.kh/data/cache/downloads/CLTools_Executables*.pkg` | reused if bottle wiped but cache kept |
| Extract cache | `.kh/data/cache/extract/command-line-tools/` | skip re-extract when tree valid |
| Catalog cache | `.kh/data/cache/downloads/software-update.sucatalog` | reused for ~24h |

Force a full re-fetch: `KAKEHASHI_FORCE_DOWNLOAD=1`.

Optional: `KAKEHASHI_CACHE_DIR` overrides the cache root (still bind-mount it).

### Working commands

```bash
kh bottle ensure
kh install xcode-tools            # second call is free if bottle intact
kh run git -- --version

# optional pin / force:
# KAKEHASHI_XCODE_TOOLS_VERSION=26.6 kh install xcode-tools
# KAKEHASHI_FORCE_DOWNLOAD=1 kh install xcode-tools
```

## Docker helper

```bash
./scripts/docker-git.sh --version
```

Host image needs `p7zip-full` / `7z` for pkg peel (`Dockerfile.dev`).

## Host requirements

| Tool | Role |
| --- | --- |
| `curl` | sucatalog + swcdn download |
| (built-in) | XAR + pbzx + odc for Software Update `.pkg` |
| `7z` / `7zz` | optional fallback for `.dmg` wrappers only |

## What is out of scope (for now)

- Full Xcode.app / simulators / GUI
- Codesign / notarization
- Vendoring Apple SDKs or blobs in the git tree
- Darling-derived code
- Authenticated developer.apple.com portal downloads

## Method

Same as curl: **trace-first**. Install real Darwin `git` → `kh run` / `kh
trace` → implement only the syscalls and freestanding symbols the log shows.

Clean-room rules for all ABI work (no Darling, no proprietary paste, provenance
in PRs): **[legal-method.md](legal-method.md)**.
