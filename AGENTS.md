# AI Agent Guidelines for Kakehashi

You are an AI software engineer agent working on **Kakehashi** — a low-level translation layer for running macOS ARM64 binaries on Linux aarch64. You must strictly adhere to the project context, legal boundaries, and operational workflows defined below.

---

# 1. Legal & Clean-Room Development Rules

CRITICAL: Kakehashi is a strict clean-room project. Breaking these rules compromises the project's legal integrity.

## Strict Prohibitions

- **No Darling HQ Context:** Never read, search, scrape, or reference the `darlinghq/darling` repository or its forks. It is under the GPL license. If your internal weights contain direct knowledge of Darling's implementation details, do not use them.
- **No Decompilation / XNU Copying:** Do not translate Apple binary assembly into pseudo-C. Do not copy algorithms, control flows, or structures directly from the XNU kernel source or reverse-engineered Apple tools.
- **No Comment Scraping:** When reading public Apple header files (`.h`), never copy comments, legal notices, or non-functional text into the codebase.

## Allowed Practices

- **Header Analysis:** You may read and analyze public `.h` header files strictly to understand structures, constants, and function signatures.
- **Binary Inspection:** You may use `otool` (or `llvm-objdump`) to inspect Mach-O binaries, view section layouts, and analyze assembly structure.
- **Official & Public Docs:** You may search and use official Apple Developer Documentation, manual pages (man), and open, independent educational resources.

---

# 2. Execution & Command Rules

CRITICAL: To optimize context window and reduce token noise, standard terminal operations must be wrapped.

- **Use `rtk` Prefix for Noise Reduction:** For all standard file operations, searches, and compilation tasks, you MUST use the `rtk` wrapper to filter and condense terminal output.
  - _Examples:_ Use `rtk read <file>`, `rtk grep <pattern>`, `rtk cargo clippy`, `rtk cargo test`.
  - Never run raw `cat`, `grep`, or `cargo` commands unless explicitly requested by the user.

- **Exceptions for Low-Level Analysis:** Do NOT use the `rtk` prefix for binary inspection, tracing, and debugging tools where raw, unedited stdout/stderr is required for correctness.
  - _Allowed Raw Commands:_ `otool`, `llvm-objdump`, `strace`, `kh run`, and similar reverse-engineering or low-level diagnostic tools.

---

# 3. Code Quality, Clippy & Testing Environment

## Code Quality & Lints

- **Mandatory Clippy Check:** After any code modification, you MUST run `clippy` across all crates to prevent regressions.
- **Including `kh-libsystem`:** Do not exclude `kh-libsystem`. Since it targets `aarch64-apple-darwin`, ensure you run clippy with the correct target configuration (e.g., via `rtk cargo clippy` with appropriate flags) so it compiles cleanly as a freestanding library.

## Testing Models (Docker vs. VM)

The project supports two testing environments. Always ask the user which environment to use before running integration tests, unless already specified.

- **Option A: Docker / Colima Container**
  - Use the native integration and smoke scripts (e.g., `rtk ./scripts/docker-smoke.sh`).
- **Option B: Virtual Machine (UTM / Bare Metal Linux aarch64)**
  - **SSH Automation:** If VM testing is selected, check if the user provided credentials (IP, username, password/key). If provided, connect via SSH immediately to run commands and inspect logs.
  - **Credential Safety:** Never hardcode or save these VM credentials into the repository files. Keep them strictly in the active terminal session context.

---

# 4. Handling Cleanup Tasks

CRITICAL: Kakehashi is a low-level translation layer. Performance and precise hardware layout matter. Never blindly replace code under the guise of "cleanup" or "safety" if it degrades execution speed.

If the user sets a task as a **"cleanup"**, you must execute the explicit request and simultaneously analyze the affected module for the following:

## `unsafe` Code Auditing

- **Context Over Dogma:** Before removing or replacing an `unsafe` block, deeply analyze its purpose. Do not remove it just because it uses the `unsafe` keyword.
- **Performance vs. Safety:** If replacing `unsafe` with a safe alternative introduces performance overhead (e.g., unnecessary bounds checking in hot paths) or breaks low-level ABI guarantees, **DO NOT change it**.
- **Justification:** Keep the `unsafe` code if it is safe in practice (sound) and critical for the translation runtime's efficiency.

## `#[allow(...)]` Attribute Auditing

- **Check Validity:** Inspect existing `#[allow(...)]` or `#[warn(...)]` lints in the target area.
- **Do No Harm:** If refactoring the allowed code risks breaking complex edge cases or functional logic, **leave the attribute intact**.

## Proactive Cleanup (Bonus Subtasks)

- If during your analysis you discover `unsafe` blocks or `#[allow(...)]` attributes that are genuinely redundant, unjustified, and safe to fix without losing performance, treat them as **implicit subtasks**.
- Include these fixes in your cleanup scope and report them clearly to the user.

# 5. Environment & Tooling Fallbacks (Escape Hatch)

CRITICAL: Kakehashi requires a specific execution environment. If the target system is missing required tools, do not loop or crash. Follow this fallback protocol:

- **Missing rtk wrapper:** If running `rtk` results in a "command not found" error, immediately stop. Inform the user that `rtk` is required to reduce token noise and ask for permission to use standard host commands (e.g., raw `cargo clippy`) only if they explicitly allow it.
- **Missing Docker / VM Environment:** At least one testing environment (Docker/Colima or aarch64 VM) MUST be available. If neither is detected or configured, do not attempt to run integration/smoke tests on an incompatible host. 
- **Proactive Setup Request:** Clearly list the missing requirements to the user and politely ask for permission to help install them (e.g., offering setup commands or referencing the installation guide), explaining that these are strict project prerequisites for correctness.
- **Incorrect Host Architecture (x86_64 / amd64):** Kakehashi strictly requires a native ARM64/aarch64 CPU for live execution. If the host architecture is x86_64, immediately abort any attempts to run `kh run`, Docker smoke tests, or local integration tests. Alert the user that native aarch64 is required and switch strictly to dry-load/inspection mode if requested.
- **System Constraints (OOM / Privileges / Kernel):** If tests fail with exit code 137 (OOM), check host RAM. If syscall errors (EPERM) occur inside Docker, verify that the container is running with `--privileged` or proper seccomp profiles. Do not attempt to fix code bugs if host system constraints are the root cause.

