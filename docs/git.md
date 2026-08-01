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
| G2 | Missing surface from probes | **in progress** (see below) |
| G3 | Local repo: `init` / `status` / `add` / `commit` | **pass** (Docker; see note on post-commit exit) |
| G4 | Remote over HTTPS (reuse curl network path) | pending |

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
`pread`/`pwrite`, `mkstemp`, `___strlcpy_chk`, soft `fork`/`vfork`, `putc`.

**Printf** must implement POSIX `ssize_t` error returns as **`-1` + errno**
(not `-errno`): git’s `is_reinit()` does `readlink(...) != -1`, so `-ENOENT`
was treated as “HEAD exists” and skipped creating `.git/HEAD`.

**Printf formats** needed by git pathspec / tree write: `%.*s`, `%*s`, `%o`
(octal modes). Missing `%.*s` produced paths like `%*s(null)` and
`fatal: pathspec … did not match`.

After freestanding changes: rebuild dylib → `./scripts/stage-libsystem.sh` →
`kh bottle ensure` (or Docker helpers). Clippy: host crates +
`kh-libsystem --target aarch64-apple-darwin`.

### G3 Docker smoke

```bash
rm -rf /tmp/kh-g3 && mkdir -p /tmp/kh-g3 && cd /tmp/kh-g3
kh run git -- init
printf 'hi\n' > README
kh run git -- add README
kh run git -- -c user.email=t@t -c user.name=t commit -m init
kh run git -- log --oneline   # e.g. 7cdb95d init
kh run git -- status          # clean on main
```

| Note | Detail |
| --- | --- |
| Post-commit exit | `git commit` may still **SIGSEGV in `start_command`** (subprocess/hooks surface) after writing the commit; the commit is durable (`log` / clean `status`). Soft `fork` is present; fuller spawn is G3+ polish. |
| Open-fail WARN | Expected ENOENT probes (`.gitignore`, empty index, templates) |

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
