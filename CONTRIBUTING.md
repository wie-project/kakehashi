# Contributing Rules

If you want to help this project, please follow these guidelines.

## Rules

1. **Pre-PR checklist** — `cargo fmt --check`, `cargo clippy --workspace --exclude kh-libsystem --all-targets -- -D warnings`, and `cargo test --workspace --exclude kh-libsystem` should pass. (`kh-libsystem` is a freestanding aarch64-apple-darwin dylib. After changing its ABI surface, rebuild with `--target aarch64-apple-darwin --release` and run `./scripts/stage-libsystem.sh` so both `dist/guest/` and the crates.io embed `crates/kh-runtime/resources/libSystem.B.dylib` stay in sync — commit the resource when shipping. End users only need `kh bottle ensure`; the dylib is embedded in `kh-runtime`.) Host CLI package name is **`kakehashi`** (binary `kh`). On Linux aarch64 / Colima, `./scripts/docker-smoke.sh` is the full integration gate. Bench artifacts must land under host `.tmp/` (see README “Testing map”); do not rely on container-only `/tmp`.

2. **Clippy discipline** — Prefer fixing warnings over adding `allow`. Keep `allow` attributes rare and justified.

3. **`unsafe`** — Denied by default at the workspace level. Allowed only in isolated `kh-runtime` modules that require host syscalls, mapping, or trap entry. Every `unsafe` block needs a `// SAFETY:` comment stating the invariants.

4. **Language** — Source code and comments are English only.

5. **Legal** — Do not copy code from Darling (GPL-3.0). Treat closed Apple components carefully; study public Apple open source as specification, do not vendor proprietary blobs.

6. **AI-assisted contributions** — Allowed if you reviewed the change yourself and it complies with the rules above.

After those steps, open a pull request.
