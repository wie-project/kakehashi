> [!IMPORTANT]
> Thank you everyone for supporting the project in the form of stars, but I will no longer be able to maintain the project.
> Too many things to keep track of, the need to manually transfer macOS binaries, and most importantly, the lack of issues and PRs to understand what interests people — these are the reasons for ending it.
> I don’t blame anyone, as I understand how hard it is to maintain such a project (which also uses AI in development). If someone is still interested in continuing to support the project through PRs, creating forks, or proposing ideas for new projects (which I don’t have right now) — I’ll be glad.
> Thanks again for everything.

# Kakehashi

Userspace **macOS ARM64 → Linux aarch64** translation layer. CLI-first, no JIT, no instruction emulator.

It loads Darwin Mach-O binaries on Linux, maps a freestanding `libSystem`, translates BSD syscalls at the guest–host boundary, and runs real tools natively on aarch64.

| Feature / Target              | Environment                                                        |
| ----------------------------- | ------------------------------------------------------------------ |
| **Live execution (`kh run`)** | **Linux aarch64** only (bare metal, UTM, Colima, Docker, OrbStack) |
| **Dry-load (`kh run --dry-load`)** | Any host (including macOS)                                    |
| **Design docs**               | [`docs/`](docs/README.md)                                          |

## Installation & Quick Start

```bash
cargo install kakehashi
# Or from a checkout:
cargo install --path crates/kh-cli --force
```

### Guest Environment Setup (The Bottle)

`Kakehashi` requires a guest filesystem root (the "bottle") containing native macOS binaries. **The bottle location is strictly fixed** and cannot be changed.

1. **Fixed Path Structure:** The runtime looks for the guest environment at:

   ```text
   ~/.local/share/kakehashi/bottle/
   ```

   _Storage Constraint:_ Due to filesystem and path mechanics, the bottle **must reside on the host's internal system drive**. External drives, or non-native mount systems (e.g., exFAT) are strictly unsupported.

2. **Manual Binaries Transfer:** Manually copy the following core system directories from your **macOS 26+** installation into the host bottle directory:
   - `/bin` → `~/.local/share/kakehashi/bottle/bin/`
   - `/sbin` → `~/.local/share/kakehashi/bottle/sbin/`
   - `/usr/bin` → `~/.local/share/kakehashi/bottle/usr/bin/`
   - `/usr/lib/zsh` → `~/.local/share/kakehashi/bottle/usr/lib/zsh/` (interactive `zsh`; `zle.so` and other modules. Check with `kh bottle status`.)

   _(Note: This base utility set—including `rm`, `zsh`, `codesign`—occupies ~256 MB uncompressed and is critical for runtime isolation. `/usr/lib/zsh` is ~1 MB extra. `libpcre.0.dylib` / `libiconv.2.dylib` live in the dyld shared cache and cannot be copied; `kh bottle ensure` aliases them to libSystem.)_

3. **Install Xcode Command Line Tools:** Once the base directories are staged, bootstrap the rest of the environment by running:
   ```bash
   kh install xcode-tools
   ```
   This pulls and unpacks the official Apple CLT (including `clang`, `git`, and the SDK) into your bottle.

_Note: Guest execution uses host CWD. Guest `/Volumes/linux/…` maps directly to host `/`._

## Verified Ecosystem (What Works)

Verified on **Docker/Colima/OrbStack** and **UTM** (Linux aarch64). Guest code runs as native ARM64; the runtime only intervenes at syscalls, threads, and faults.

### 7-Zip

```bash
kh run 7zz -- a demo.7z README.md
kh run 7zz -- t demo.7z
```

### curl

```bash
kh run curl -- --version
kh run curl -- -sS -o body http://example.com
```

### Apple git (CLT)

```bash
kh run git -- --version
kh run git -- clone --depth 1 https://github.com/octocat/Hello-World.git hw
```

### Apple clang (CLT)

```bash
kh run clang -- --version
kh run clang -- -c hello.c -o hello.o
```

### Not Claimed Yet

Full curl feature surface, real Apple Security.framework, git LFS/svn, GUI, codesign, full macOS app stack. Nested `clang`/`ld` processes pay a process-start tax, not a correctness gap.

## Reference Hardware & Configuration

The project is explicitly tested and verified stable using the following environment setup:

- **Build Host (Compiling `kh-libsystem`):** MacBook Pro M1 (2020), 8 GB RAM / 256 GB SSD, running **macOS 26.6.1**.
- **Test Host (Running `kh run`):** **Ubuntu 26.04 live-server (arm64)** inside UTM on the same M1 Mac host.

## How it Works

1. Resolve the static **bottle** path (`~/.local/share/kakehashi/bottle/`).
2. Load Mach-O + dylibs, bind symbols, and wire the BSD hypercall into the runtime.
3. Jump to `LC_MAIN`; guest ARM64 runs natively on the CPU.
4. Syscalls, helpers, and pthread context boundaries cross into `kh-runtime` and back.

_Note: Clean-room development process. Not derived from Darling. No proprietary Apple blobs in-tree._

## Crates

| Crate           | Role                                                                     |
| --------------- | ------------------------------------------------------------------------ |
| **`kakehashi`** | Binary `kh` (install this)                                               |
| `kh-loader`     | Mach-O parse, map, bind, execute                                         |
| `kh-runtime`    | Memory, traps, BSD syscalls, bottle, threads; embeds `libSystem.B.dylib` |
| `kh-libsystem`  | Freestanding dylib source (`aarch64-apple-darwin` only)                  |

### `kh-libsystem` layout

```text
crates/kh-libsystem/src/
  core/           # syscalls, errno, heap, process, host helpers
  dylib/          # libsystem_c, pthread, libcurl, libc++, libz, …
  frameworks/     # CoreFoundation, Security, CoreServices (soft)
```

## Requirements

- **Rust 1.88+**
- **Linux aarch64** for live `kh run`
- **Page sizes:** 4 KiB and 16 KiB (Asahi-class)

## Performance

Guest code runs **natively**. Cost is boundary × crossings (TLS, alt stack, NEON, dispatch), not an emulator.

Multi-file `7zz` runs at approximately **×1.24** vs native Linux `7zz`. Nested Apple clang pays a process-start tax per `-cc1`/`ld` hop; the load path is optimized, but wall-clock parity with native macOS is not the primary CI goal. See [`docs/roadmap.md`](docs/roadmap.md).

## License

Apache-2.0 — [`LICENSE.txt`](LICENSE.txt), [`NOTICE`](NOTICE).

Detailed documentation: [`docs/`](docs/README.md).
Contributing guidelines: [`CONTRIBUTING.md`](CONTRIBUTING.md).
