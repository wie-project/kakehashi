# Git / Xcode Command Line Tools milestone

Product goal: run **Apple `git`** (from official Command Line Tools) under `kh`
on Linux aarch64. Clean-room ABI; trace-first. Clippy + unit tests; Docker
Colima first.

See also: [roadmap](roadmap.md), [architecture](architecture.md), [curl](curl.md).

## Status (gates)

| Gate | Pass criteria | State |
| --- | --- | --- |
| G0 | `kh install xcode-tools` → bottle has CLT + `…/usr/bin/git` | **pass** (swscan, no Apple ID) |
| G1 | `kh run git -- --version` banner + exit 0 | **pass** (Docker: `git version 2.50.1 (Apple Git-155)`) |
| G2 | Stable missing-syscall / symbol list from probes | pending |
| G3 | Local repo: `init` / `status` / `add` / `commit` | pending |
| G4 | Remote over HTTPS (reuse curl network path) | pending |

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
