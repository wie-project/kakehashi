# Guest utilities

Darwin binaries under `kh` on Linux aarch64. Trace-first: implement only what the guest calls. Clean-room: [`AGENTS.md`](../AGENTS.md).

## curl

**Met** (G0–G5). Darwin `curl` via `kh install curl`.

| Gate | Criteria | State |
| --- | --- | --- |
| G0 | bottle `/usr/local/bin/curl` | pass |
| G1 | `kh run curl -- --version` | pass |
| G3 | HTTP GET, exit 0 | pass (Docker + UTM) |
| G4 | HTTPS GET (OpenSSL + bottle CA) | pass (Docker) |
| G5 | UTM HTTP confirm | pass |

```bash
kh install curl
kh run curl -- --version
kh run curl -- -sS -o /Volumes/linux/out/body http://example.com/
```

Guest path: `/usr/local/bin/curl`. Optional `KAKEHASHI_CURL`. Scripts: `scripts/docker-kh.sh curl`, `scripts/docker-curl-options.sh`.

OpenSSL may probe missing `/etc/ssl/openssl.cnf`; Security/CoreFoundation stay soft stubs. HTTPS uses bottle CA.

## git

**Met** (G0–G8). Apple CLT `git` via `kh install xcode-tools`.

| Gate | Criteria | State |
| --- | --- | --- |
| G0 | CLT + `…/usr/bin/git` (public swscan) | pass |
| G1 | `git --version` (`2.50.1 (Apple Git-155)`) | pass |
| G3 | local `init` / `add` / `commit` | pass |
| G4 | HTTPS remotes (freestanding libcurl) | pass |
| G5 | SSH via host OpenSSH bridge | pass |
| G6 | push to private bare | pass |
| G7 | plain `http://` | pass |
| G8 | authenticated GitHub | pass |

Verified: Wine full history (GitHub + GitLab); `llvm-project --depth 1` over SSH; linux kernel shallow HTTPS.

```bash
kh install xcode-tools
kh run git -- --version
kh run git -- clone --depth 1 https://github.com/octocat/Hello-World.git
# SSH uses host /usr/bin/ssh (bottle symlink). File key under ~/.ssh; not a guest sshd.
./scripts/docker-git-ssh.sh
./scripts/docker-git-github.sh
```

`git-remote-http` binds `/usr/lib/libcurl.4.dylib` → freestanding alias. HTTPS: `KH_HELPER_TLS_CONNECT` + rustls; plaintext `read`/`write` on the wrapped FD. SSH: `execve` of host ELF OpenSSH (`reexec_direct`), `HOME` rewritten so `~/.ssh` works.

## Apple clang

**Met** (G0–G5 + `-flto`). Same CLT package as git.

| Gate | Criteria | State |
| --- | --- | --- |
| G0 | `…/usr/bin/clang` | pass |
| G1 | `clang --version` (Apple clang 21) | pass |
| G3 | `-c` trivial C → Mach-O `.o` | pass |
| G4 | link + run guest product (`ld-classic` + SDK) | pass |
| G5 | modern `ld` + SDK TBDs + run | pass |
| G5+LTO | `clang -flto` multi-file + run | pass |

```bash
kh run clang -- --version
# Prefer one outer process (nested -cc1/ld are extra kh starts):
make one CC="kh run clang --"
./scripts/docker-kh.sh clang
# probes: tests/clang-probe/ (return_zero, g4-mini, flto)
```

Bottle aliases `libc++.1.dylib` → freestanding `libSystem.B.dylib`. Default driver uses modern `ld` + live CLT `libLTO`. Nested re-exec keeps `DYLD_LIBRARY_PATH`. `TMPDIR` / `confstr(_CS_DARWIN_USER_TEMP_DIR)` follow Darwin `/var/folders/…/T/` so LTO object paths fit.

Wall on tiny multi-file links is mostly **process start** (`wait4` of nested `kh`), not missing syscalls. Syscall table: [syscall-coverage.md](syscall-coverage.md).
