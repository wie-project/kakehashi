# Clean-room method and legal boundaries

Normative process for contributors implementing Darwin ABI, freestanding
`libSystem`, syscalls, and guest milestones (`curl`, `git` / CLT, etc.).

This is **engineering policy** for an Apache-2.0 project. It is not legal advice.
When in doubt, ask maintainers before landing code that might be derived from
restricted sources.

Related: [CONTRIBUTING](../CONTRIBUTING.md), [NOTICE](../NOTICE),
[Architecture](architecture.md), [Git milestone](git.md), [Curl milestone](curl.md).

## Goals

| Goal | Implication |
| --- | --- |
| Independent implementation | Kakehashi is **not** derived from Darling or from proprietary Apple sources |
| Clean-room freestanding ABI | Bottle ships our `libSystem.B.dylib`, not Apple’s libraries from CLT/SDK |
| No proprietary redistribution in-tree | Do not vendor Apple SDKs, dylibs, or CLT blobs into the git tree |
| Compatibility by observation | Guests are real Darwin Mach-O; we implement the **surface they need** |

Users obtain Command Line Tools / guest binaries via documented install paths
(e.g. public Software Update catalog). Those artifacts stay outside the source
tree (cache / bottle under `$KAKEHASHI_DATA_DIR`).

## Hard bans

### 1. Darling (and other GPL macOS reimplementations)

**Do not** copy, paste, port, or “lightly adapt” code from Darling (GPL-3.0) or
similar projects into this repository.

**Do not** open Darling sources **while implementing** a feature, even for “just
the idea.” For a solo contributor who both reads and writes, that is not
clean-room.

If a multi-person team ever needs external inspiration from such a tree:

- One person may write a **spec-only** note (behavior, syscall names, tests) with
  **no code** and no line-by-line structure from the source project.
- A **different** person implements from that spec without reading the banned tree.

Default for this project: treat Darling as a **ban list**. Prefer trace + public
specs instead.

### 2. Proprietary Apple code as implementation source

**Do not:**

- Decompile or disassemble closed Apple binaries and port algorithms into
  kakehashi
- Copy closed-source Apple C/C++/asm into freestanding or host crates
- Vendor proprietary frameworks, SDKs, or CLT payloads in the git tree

**Do not** treat private headers or reverse-engineered private SPI dumps as a
license to reimplement by transcription.

### 3. Mixing incompatible licenses into the tree

Do not bulk-import Apple open source (APSL, etc.) or third-party code into this
Apache-2.0 tree without an explicit maintainers decision and correct
attribution/`NOTICE` updates. Prefer small clean-room implementations or
well-known permissive libraries already approved for the workspace (e.g.
`miniz_oxide` for zlib-shaped APIs).

## Allowed sources (priority order)

Use sources **in this order**. Higher rows beat lower rows when they conflict.

| Priority | Source | Use for | Do not use for |
| --- | --- | --- | --- |
| 1 | `kh run` / `kh trace`, unresolved-symbol logs, smoke failures | What the guest actually needs next | Guessing full macOS surface |
| 2 | POSIX, man pages, public Darwin/macOS documentation | Contracts: errno, return values, flags | Platform-private SPI |
| 3 | Public Apple open source releases (opensource.apple.com and matching tags) | Clarify intended behavior of public APIs | Blind copy-paste into our tree |
| 4 | Behavioral / acceptance tests (`init`/`status`, HTTP GET, etc.) | Gate “done” | Speculating internal Apple design |
| 5 | Symbol lists from guest binaries (`nm`, `otool -L`, missing exports) | Names and link dependencies only | Porting function bodies from disassembly |
| 6 | Disassembly of guest or system dylibs | Last resort: call flow / which symbol is hit | Line-by-line reimplementation of closed code |
| — | Darling / GPL reimplementations | **Never for implementation** | — |

### Black-box observation of Apple binaries

Running **legally obtained** guest software (e.g. CLT `git` via
`kh install xcode-tools`) under `kh` and recording syscalls, errno, paths, and
exit codes is the **primary** reverse-engineering method for this project.

That observes the **ABI and process model**, not a license to copy Apple’s
implementation.

### Public headers and open source as specification

Public function signatures, types, and documented semantics may guide a
from-scratch implementation. Reading APSL (or other) sources to understand
behavior is not the same as pasting them into kakehashi. When an open-source
file is the only clear reference, reimplement from the documented contract and
tests; do not transplant large chunks of foreign-licensed code.

## Trace-first implementation loop

Same method as [curl](curl.md) and [git](git.md):

1. Pick the smallest failing guest scenario for the milestone gate.
2. Run under `kh` (prefer Docker helpers where documented) and capture trace /
   WARN / fault PC / missing symbol.
3. Record a row: **symbol or syscall → observed need → stub vs real → plan**.
4. Implement **from scratch** in the appropriate crate:
   - host BSD surface → `kh-runtime`
   - guest C ABI → `kh-libsystem` (then stage dylib)
   - load/bind → `kh-loader`
5. Smoke the gate; keep existing multi-thread / curl gates green when required.
6. Prefer **soft stubs** (null / ENOTSUP / no-op) until a guest path requires real
   behavior—do not pull in private frameworks “because macOS has them.”

Do **not** expand scope to “full macOS.” Implement only the surface the log and
gates demand.

## Provenance in pull requests

For non-trivial ABI or syscall work, the PR description (or a short note in the
relevant milestone doc) should make provenance obvious:

| Field | Example |
| --- | --- |
| **Observed** | `kh trace`: `readlink` on `.git/HEAD`; git treats only `-1` as failure |
| **Spec** | POSIX `readlink`; man errno |
| **Impl** | clean-room in freestanding printf / syscall handler X |
| **Not used** | Darling; decompiled Apple `libSystem` |

If a change is “too similar” to a restricted source, rewrite from man/POSIX and
tests rather than polishing a transcription.

## What may live where

| Artifact | In git tree? | Notes |
| --- | --- | --- |
| kakehashi source (Rust/C freestanding) | Yes | Apache-2.0 |
| Embedded freestanding `libSystem.B.dylib` | Yes | Built from `kh-libsystem` via stage script |
| Test Mach-O fixtures we author | Yes | Project-owned |
| Apple CLT / SDK / proprietary dylibs | **No** | Install + cache/bottle only |
| Copied Darling sources | **No** | Hard ban |

## Contributor checklist

Before opening a PR that adds Darwin surface:

- [ ] Implementation is original (or an already-approved permissive dependency)
- [ ] No Darling (or similar) code or structure was used while writing it
- [ ] No proprietary Apple source or decompiled bodies were ported
- [ ] No new proprietary blobs were added to the repository
- [ ] Need was driven by **trace / gate**, not a full-API wishlist
- [ ] Soft stub vs real is justified; private frameworks not vendored
- [ ] Freestanding ABI changes staged (`stage-libsystem.sh`) when required
- [ ] Provenance noted for non-obvious behavior (errno conventions, path layout, etc.)

## Summary

**We reimplement the userspace contract that guests exercise, from public
specs and black-box observation. We do not rehost Apple’s or Darling’s code.**
