# Kakehashi

Userspace **macOS ARM64 → Linux aarch64** translation layer (CLI-first, no JIT).

Load Darwin Mach-O on Linux aarch64, map a freestanding `libSystem`, translate
BSD syscalls, and run real guests (clang probes, **7-Zip `7zz`**, **curl**,
**Apple `git`**, threads).

|                    |                                                   |
| ------------------ | ------------------------------------------------- |
| Live execution     | **Linux aarch64** (bare metal, VM, Colima/Docker) |
| Dry-load / inspect | Any host (including macOS)                        |
| Design reference   | [`docs/`](docs/README.md)                         |

## What works

Verified on **Docker/Colima** and **UTM** (Linux aarch64). Install once:

```bash
cargo install kakehashi
# or from a checkout:
cargo install --path crates/kh-cli --force

kh bottle ensure
kh install 7zip         # Darwin 7zz → guest /usr/local/bin/7zz
kh install curl         # Darwin curl → guest /usr/local/bin/curl
kh install xcode-tools  # Apple CLT git (public swscan; no Apple ID)
```

Relative `-o` / archive paths resolve against the **host CWD** of the `kh`
process (create parent dirs yourself, or rely on auto-mkdir for `O_CREAT`).
Through the bottle, `/Volumes/linux/…` bridges to the host root (`/` → host `/`).

### 7-Zip (`7zz`)

```bash
# Version / help
kh run 7zz --
kh run 7zz -- --help

# Create archive (cwd-relative)
kh run 7zz -- a demo.7z README.md
kh run 7zz -- t demo.7z
kh run 7zz -- l demo.7z
kh run 7zz -- x -o./out demo.7z

# Multi-thread compress (correctness gate)
kh run 7zz -- a -t7z -m0=lzma2 -mx=5 -mmt=4 mt.7z README.md
kh run 7zz -- t mt.7z
# expect: Everything is Ok, exit 0
```

**Docker helpers** (artifacts under host `.tmp/kh-out/`):

```bash
./scripts/docker-7zz.sh --help
./scripts/docker-7zz.sh a /Volumes/linux/out/demo.7z /Volumes/linux/src/README.md
ls -lh .tmp/kh-out/demo.7z

./scripts/docker-7zz.sh a -t7z -m0=lzma2 -mx=5 -mmt=4 \
  /Volumes/linux/out/mt.7z /Volumes/linux/src/README.md
./scripts/docker-7zz.sh t /Volumes/linux/out/mt.7z
```

### curl

```bash
# Banner (G1)
kh run curl -- --version

# HTTP GET → file (G3 / G5). Parents for -o are created when missing.
kh run curl -- -sS -o .tmp/kh-out/body http://example.com/
# expect: exit 0, ~559 bytes, HTML contains "Example Domain"
wc -c .tmp/kh-out/body
head -c 80 .tmp/kh-out/body; echo

# HTTP to stdout
kh run curl -- -sS http://example.com/ | head -c 80; echo

# HTTPS GET (G4) — OpenSSL + bottle CA (from host or curl.se download)
kh run curl -- -sS -o .tmp/kh-out/https-body https://example.com/
wc -c .tmp/kh-out/https-body

# Negative: bad / self-signed cert must fail (rc ≠ 0)
kh run curl -- -sS -o /dev/null https://self-signed.badssl.com/; echo exit:$?
```

**Docker helpers:**

```bash
./scripts/docker-curl.sh --version
./scripts/docker-curl.sh -sS -o /Volumes/linux/out/body http://example.com/
./scripts/docker-curl.sh -sS -o /Volumes/linux/out/https-body https://example.com/
ls -lh .tmp/kh-out/body .tmp/kh-out/https-body

# Trace-first probe logs → .tmp/kh-curl-probe/
./scripts/docker-curl-probe.sh --version

# Option matrix (large tiers) → .tmp/kh-curl-options/
./scripts/docker-curl-options.sh tier1
./scripts/docker-curl-options.sh tier9-10
./scripts/docker-curl-options.sh all          # tier1..10
```

Harmless noise on many runs:

- `kh: open fail ENOENT(openat) path=/etc/ssl/openssl.cnf` — OpenSSL optional config; HTTP/HTTPS still work via the seeded CA bundle.
- `WARN … skip dylib … Security/CoreFoundation` — Apple frameworks not in the bottle; soft stubs cover the load path.
- `unresolved strong symbol; bound to named missing trampoline` — symbols not hit on the happy path.

Details and gates: [`docs/curl.md`](docs/curl.md).

### Also green

| Surface                           | Notes                                                    |
| --------------------------------- | -------------------------------------------------------- |
| Clang / fixture probes            | `tests/clang-probe/`, `tests/fixtures/`                  |
| Multi-thread `7zz -mmt=4`         | Docker + UTM                                             |
| Bottle + freestanding `libSystem` | `kh bottle ensure` embeds dylib                          |
| Unit tests + clippy               | `cargo test` / `clippy` workspace (excl. `kh-libsystem`) |

### Apple `git` (CLT)

**Milestone met** (G0–G8). Day-to-day remotes work: local commits, HTTPS/SSH
clone and push, plain `http://`, private GitHub. Large clones verified below.

```bash
kh install xcode-tools   # public swscan; no Apple ID
# Default is protocol v2 (also set by scripts/docker-git.sh):
git config --global protocol.version 2

kh run git -- --version
kh run git -- ls-remote https://github.com/octocat/Hello-World.git
kh run git -- clone --depth 1 https://github.com/octocat/Hello-World.git hw
# full / large clones stream over TLS guest FDs (path B; no 64 MiB body cap)
# kh run git -- clone https://github.com/octocat/Hello-World.git hw-full
```

**Verified large clones** (Docker / Colima):

| What | How | Notes |
| --- | --- | --- |
| **Wine** full history | GitHub and GitLab remotes | Full clone (not shallow); large object / `index-pack` path |
| **llvm/llvm-project** | `git@github.com:llvm/llvm-project.git` | `--depth 1` over SSH |
| linux kernel | HTTPS | `--depth 1` (~279 MiB pack) |
| facebook/folly | HTTPS | full clone |

```bash
# Shallow monorepo over SSH (host ~/.ssh key registered on GitHub)
./scripts/docker-git.sh clone --depth 1 git@github.com:llvm/llvm-project.git

# Wine full history (pick a mirror)
# ./scripts/docker-git.sh clone https://github.com/wine-mirror/wine.git
# ./scripts/docker-git.sh clone https://gitlab.winehq.org/wine/wine.git

# Push / plain HTTP / private GitHub smokes (local or host gh):
# ./scripts/docker-git-push.sh
# ./scripts/docker-git-http.sh
# ./scripts/docker-git-github.sh
```

Details and gates: [`docs/git.md`](docs/git.md). Docker helpers:
`scripts/docker-git.sh`, `docker-git-ssh.sh`, `docker-git-push.sh`,
`docker-git-http.sh`, `docker-git-github.sh`.

### Not a product claim (yet)

Full curl feature set (POST bodies, proxies, HTTP/3 end-to-end, every scheme),
real Apple Security.framework, every git extension (LFS, `git svn`, …),
GUI, codesign. Unlimited full multi‑GiB monorepo clones under a fixed wall
budget remain **best-effort** (network/host rate limits); Wine full + llvm
shallow already green.

## Crates

| Crate           | Role                                                                         |
| --------------- | ---------------------------------------------------------------------------- |
| **`kakehashi`** | Binary `kh` (install this)                                                   |
| `kh-loader`     | Mach-O parse, map, execute                                                   |
| `kh-runtime`    | Memory, traps, BSD syscalls, bottle; embeds freestanding `libSystem.B.dylib` |
| `kh-libsystem`  | Source for that dylib (`aarch64-apple-darwin` only; not a Linux host crate)  |

The guest dylib is vendored at `crates/kh-runtime/resources/libSystem.B.dylib`
and compiled into the runtime with `include_bytes!`. Publishing `kh-runtime`
ships the dylib; end users do not need a separate download.

## Requirements

- Rust 1.88+
- **Linux aarch64** for live `kh run` / `kh trace`
- Page sizes: **4 KiB** (containers) and **16 KiB** (Asahi-class)
- Optional: `curl`/`wget` + `tar` for `kh install 7zip` / `kh install curl`

## Install

```bash
cargo install kakehashi
# or from a checkout: cargo install --path crates/kh-cli

kh bottle ensure
kh install 7zip
kh install curl
```

### Bottle layout

Default root: `~/.local/share/kakehashi/bottle/` (override with
`KAKEHASHI_DATA_DIR` / `KAKEHASHI_ROOT`).

| Host                          | Guest                                               |
| ----------------------------- | --------------------------------------------------- |
| `…/bottle/`                   | `/`                                                 |
| `…/usr/local/bin/7zz`         | `/usr/local/bin/7zz`                                |
| `…/usr/local/bin/curl`        | `/usr/local/bin/curl`                               |
| `…/usr/lib/libSystem.B.dylib` | `/usr/lib/libSystem.B.dylib`                        |
| `…/private/etc/ssl/cert.pem`  | `/etc/ssl/cert.pem` (host CA or downloaded Mozilla) |
| `…/Volumes/linux/…`           | `/Volumes/linux/…` → host FS                        |

## Performance (honest)

Kakehashi runs guest code **natively** on the CPU. The tax is the **syscall
boundary** (TLS switch, alt stack, NEON save/restore, Rust dispatch) × how
chatty the guest is — not an instruction emulator.

### Measured gap

On Ubuntu aarch64 bare-metal (UTM), multi-file `7zz` archive
(`-t7z -m0=lzma2 -mx=5 -mmt=4`, ~14.5k files / ~309 MiB tree, `mmt=4`):

|      | native Linux `7zz` | Darwin `7zz` under `kh` |     ratio |
| ---- | -----------------: | ----------------------: | --------: |
| wall |           ~44.1 s |                  ~54.8 s | **~×1.24** |

Same machine, same tree, same flags; both exit 1 on a single scan warning
(broken symlink) — not a hang. Older ~×5.2 numbers (~8k / ~240 MiB, ~22.5 s
native / ~118 s `kh`) were dominated by freestanding **first-fit freelist**
O(n²) churn; size-class LIFO freelists closed most of that gap. Residual is
mostly real LZMA + boundary × crossings (not “wrong compression”).

Few-file / compression-heavy samples remain ~×1.1–1.3.

Hypercall is always wired for freestanding libSystem (sole production BSD
entry). Residual `svc`→`brk`/SIGTRAP remains only for unpatched fixtures.

### Why ~×1.2 is still useful in CI

The product goal for CI is not “as fast as native macOS,” but **run Darwin
CLI/tools on cheap Linux aarch64 runners** instead of scarce, expensive
macOS capacity.

**GitHub Actions hosted runners** (private-repo overage rates, USD per
minute; see [Actions runner pricing](https://docs.github.com/en/billing/reference/actions-runner-pricing)):

| Runner                               | Per-minute rate |
| ------------------------------------ | --------------: |
| Linux 2-core arm64                   |      **$0.005** |
| Linux 2-core x64                     |          $0.006 |
| macOS 3–4 core (M1/Intel)            |      **$0.062** |
| macOS larger (e.g. 12-core / M2 Pro) |   $0.077–$0.102 |

macOS standard is roughly **×10–×12** the Linux arm64 minute rate before any
wall-time difference. A job that is only **~×1.2 slower** under `kh` on Linux
arm64 than native Linux (and far cheaper per minute than macOS) is a strong
CI win; even a larger gap would often still beat macOS billable cost
(illustrative: 2 × $0.005 ≈ $0.010 vs 1 × $0.062). Public-repo free minutes
and self-hosted Linux amplify that further; macOS hosted capacity also tends
to queue longer and (on GitLab SaaS) is Premium/Ultimate / beta-gated.

**When macOS runners still win:** GUI, codesign/notarization, Xcode UI tests,
or any workload that is not a pure CLI Darwin binary under freestanding
`libSystem`.

**Gates, not benches:** CI correctness is `cargo test` / smoke / `7zz -mmt=4`,
not “match native wall clock.” Perf work is tracked in
[`docs/roadmap.md`](docs/roadmap.md).

## Quick start (Docker / Colima on Apple Silicon)

```bash
docker build -t kakehashi:dev -f Dockerfile.dev .
docker run --rm -v "$PWD":/src -w /src kakehashi:dev \
  cargo test --workspace --exclude kh-libsystem

# Full smoke (build + clippy + test + micro run)
./scripts/docker-smoke.sh
```

## Build

```bash
cargo build -p kakehashi --release
cargo test --workspace --exclude kh-libsystem
cargo clippy --workspace --exclude kh-libsystem --all-targets -- -D warnings

# Maintainers: refresh embed after freestanding ABI changes
cargo build -p kh-libsystem --release --target aarch64-apple-darwin
./scripts/stage-libsystem.sh   # → crates/kh-runtime/resources/libSystem.B.dylib
```

`libSystem` discovery: `--libsystem` → `KAKEHASHI_LIBSYSTEM` → paths next to
`kh` → crate `resources/` → **embedded** bytes in `kh-runtime`.

## Testing map

| Goal               | Command                                                            | Artifacts                                          |
| ------------------ | ------------------------------------------------------------------ | -------------------------------------------------- |
| Unit tests         | `cargo test --workspace --exclude kh-libsystem`                    | terminal                                           |
| Docker smoke       | `./scripts/docker-smoke.sh`                                        | ends with `smoke ok`                               |
| Fixtures           | `kh run --expect-code … tests/fixtures/…`                          | see `tests/fixtures/README.md`                     |
| Clang probes       | `kh run --root tests/fixtures/bottle tests/clang-probe/puts_hello` | stdout `hello`                                     |
| Real Darwin `7zz`  | `./scripts/docker-7zz.sh …`                                        | host `.tmp/kh-out/`                                |
| Real Darwin `curl` | `./scripts/docker-curl.sh …`                                       | host `.tmp/kh-out/`; probe → `.tmp/kh-curl-probe/` |
| Fair CPU bench     | `./scripts/bench-fair-local.sh`                                    | host `.tmp/kh-bench-fair/`                         |

`.tmp/`, `.kh/`, and `target/` are gitignored.

### Guest path ↔ host path (Docker helpers)

Bottle bridges the Linux FS as `/Volumes/linux/…`:

| Guest path                     | Host                                                                |
| ------------------------------ | ------------------------------------------------------------------- |
| `/Volumes/linux/src/README.md` | `<repo>/README.md`                                                  |
| `/Volumes/linux/out/demo.7z`   | `<repo>/.tmp/kh-out/demo.7z` (durable; default for `docker-7zz.sh`) |
| `/Volumes/linux/tmp/…`         | container `/tmp/…` — **gone** after `docker run --rm`               |

## Scripts

| Script                           | Purpose                                                                               |
| -------------------------------- | ------------------------------------------------------------------------------------- |
| `scripts/stage-libsystem.sh`     | Build product → `crates/kh-runtime/resources/`                                        |
| `scripts/install-linux.sh`       | Local build + install `kh` + `bottle ensure`                                          |
| `scripts/docker-smoke.sh`        | Smoke suite inside `Dockerfile` image                                                 |
| `scripts/docker-7zz.sh`          | Darwin `7zz` under `kh` (outputs → `.tmp/kh-out`)                                     |
| `scripts/docker-curl.sh`         | Darwin `curl` under `kh` (same shape as `docker-7zz`)                                 |
| `scripts/docker-curl-probe.sh`   | `KH_CURL_PROBE=1` wrapper (logs → `.tmp/kh-curl-probe`)                               |
| `scripts/docker-curl-options.sh` | Tiered curl flag smoke (`tier1`…`tier10`, `tier9-10`, `all` → `.tmp/kh-curl-options`) |
| `scripts/docker-git.sh`          | Apple `git` from CLT under `kh` (swscan + `.kh/data` cache)                           |
| `scripts/docker-git-ssh.sh`      | Git SSH smoke: local sshd + bare + `ls-remote` / `clone`                              |
| `scripts/docker-git-push.sh`     | Git push smoke: private bare + branches + `push` over SSH                             |
| `scripts/docker-git-http.sh`      | Git plain `http://` smoke: smart HTTP `ls-remote` / `clone` / `push`                  |
| `scripts/docker-git-github.sh`    | Authenticated GitHub private: SSH push + HTTPS Basic clone (host `gh` + keys)         |
| `scripts/bench-fair-local.sh`    | Native vs kh compress (artifacts → `.tmp/kh-bench-fair`)                              |

## License

Apache License 2.0. See [`LICENSE.txt`](LICENSE.txt) and [`NOTICE`](NOTICE).

This project is **not** derived from Darling. Do not vendor proprietary Apple
SDKs or blobs. Contributors must follow the clean-room process in
[`docs/legal-method.md`](docs/legal-method.md).
