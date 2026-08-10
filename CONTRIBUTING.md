# Contributing Rules

If you want to help this project, please follow these guidelines.

## Rules

1. **Pre-PR checklist** — `cargo fmt --check`, `cargo clippy --workspace --exclude kh-libsystem --all-targets -- -D warnings`, and `cargo test --workspace --exclude kh-libsystem` should pass. (`kh-libsystem` is a freestanding aarch64-apple-darwin dylib under `src/{core,dylib,frameworks}/`. Put new C ABI symbols in the matching `dylib/<name>/` or `frameworks/` module; substrate (helpers, hypercall, heap) in `core/`. After changing its ABI surface, rebuild with `--target aarch64-apple-darwin --release` and run `./scripts/stage-libsystem.sh` so the crates.io embed `crates/kh-runtime/resources/libSystem.B.dylib` stays in sync — commit the resource when shipping. End users only need `kh bottle ensure`; the dylib is embedded in `kh-runtime`.) Host CLI package name is **`kakehashi`** (binary `kh`). On Linux aarch64 / Colima, `./scripts/docker-smoke.sh` is the full integration gate. Bench artifacts must land under host `.tmp/`; do not rely on container-only `/tmp`.

2. **Clippy discipline** — Prefer fixing warnings over adding `allow`. Keep `allow` attributes rare and justified.

3. **`unsafe`** — Denied by default at the workspace level. Allowed only in isolated `kh-runtime` modules that require host syscalls, mapping, or trap entry. Every `unsafe` block needs a `// SAFETY:` comment stating the invariants. Runtime/thread/boundary changes must respect [`docs/invariants.md`](docs/invariants.md) (especially worker teardown: `SYS_exit`, not `pthread_exit`).

4. **Language** — Source code and comments are English only.

5. **Legal / clean-room** — Follow [`docs/legal-method.md`](docs/legal-method.md). Hard bans: no Darling (or similar) code for implementation; no porting proprietary Apple sources or decompiled bodies; no vendoring Apple SDKs/CLT blobs in-tree. Primary method: **trace-first** black-box observation of legally obtained guests + public specs (POSIX, man pages, Apple open source as **specification** only).

6. **AI-assisted contributions** — Allowed if you reviewed the change yourself and it complies with the rules above.

After those steps, open a pull request.
