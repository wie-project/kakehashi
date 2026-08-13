# Contributing Rules

If you want to help this project, please follow these guidelines.

## Requirements for Hardware and Software

### 1. Development & Testing Environment

- **Host Machine:** Any Apple Silicon Mac running the latest macOS version (for cross-compilation/code analysis), or a native Linux ARM64 machine (bare-metal, UTM, or Colima/Docker/OrbStack).
- **Linux Environment:** A Linux `aarch64` environment (any major distribution) is strictly required to run, trace, and test the project.

### 2. AI-Assisted Development (Optional)

If you use AI agents or LLM-based tools during development, ensure your setup meets the following criteria:

- **Connectivity:** The AI environment must have access to your Linux VM, machine, or Docker container via SSH to execute tests.
- **Token Optimization:** It is highly recommended to install the `rtk` utility. This minimizes token consumption during terminal command execution.
- **Compliance:** Failure to use `rtk` will trigger continuous environment checks and lookups in accordance with the guidelines specified in [AGENTS.md](AGENTS.md).

## Rules

### 1. Pre-PR Checklist & Workflow

Before submitting a Pull Request, execute the following validation sequence. All checks must pass without errors:

```bash
# Check code formatting
cargo fmt --check

# Run clippy across the main workspace
cargo clippy --workspace --all-targets -- -D warnings

# Run clippy for the freestanding libsystem (requires cross-compilation target)
cargo clippy -p kh-libsystem --target aarch64-apple-darwin -- -D warnings

# Run workspace tests
cargo test --workspace --exclude kh-libsystem
```

- **Storage Isolation:** Benchmark and temporary artifacts must land strictly under the host `.tmp/` directory. Do not rely on container-only `/tmp`.

### 2. Repository Language

- **Strict English:** All source code, API documentations, inline comments, and commit messages must be written in English only to ensure accessibility for global contributors.

### 3. Clean-Room Methodology & Legal Integrity

We strictly enforce a clean-room development process. The following boundaries are non-negotiable:

- **Hard Bans:** Absolutely no code from `darlinghq/darling` (or its forks) may be read, referenced, or used. Porting proprietary Apple sources, translating Apple binary assembly into pseudo-C, using decompiled bodies, or vendoring Apple SDKs/CLT blobs in-tree is strictly prohibited.
- **No Comment Scraping:** When analyzing public Apple header files (`.h`), never copy comments, legal notices, or non-functional text into the codebase.
- **Permitted Method:** Use **trace-first**, black-box observation of legally obtained guests (via tools like `otool`, `llvm-objdump`, `kh run --dry-load`) combined with public specifications (POSIX, man pages).
- **Specification Only:** Apple Open Source mirrors may be analyzed **exclusively as a specification** to understand behaviors, never for direct code copying.
