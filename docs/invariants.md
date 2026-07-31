# Invariants

Normative rules for Linux aarch64 production behavior. Violating any rule has
caused multi-thread regressions (`7zz -mmt>1`) or host corruption. Changes that
touch these areas are high risk; re-run the multi-thread gate in
[docs/README.md](README.md#multi-thread-gate).

## Threading and join

1. **MUST** map one guest pthread to one host OS thread.
2. **MUST** publish `KhThread.done` only from the **host**, after leaving the guest stack.
3. **MUST NOT** set `done` in the guest trampoline before `bsdthread_terminate` returns into host teardown.
4. **MUST NOT** run host join-publish, `munmap`, or thread exit on a guest stack that join may reclaim.
5. **MUST** end workers with **`SYS_exit`** (thread exit), not glibc **`pthread_exit`**.
6. **MUST** clear **`x29`** when switching to the host worker-exit frame (and in SIGTRAP `ucontext`).
7. **MUST NOT** reintroduce dual-path “workers only on SIGTRAP / main on hypercall” as the production default.

## TLS (`TPIDR_EL0`)

8. **MUST** capture host `TPIDR_EL0` before any guest `msr` on that OS thread.
9. **MUST** restore host TPIDR before host Rust, glibc, panic formatting, or `tracing`.
10. **MUST NOT** use Rust `thread_local!` (or host TLS-dependent alloc) while guest TPIDR is live for boundary bookkeeping; use **`host_slot`** (gettid-keyed).
11. **MUST** provide per-thread `___error` via guest TLS, not a process-global static.
11b. **MUST NOT** leave guest `TPIDR_EL0` active across host-only code after `install_main_guest_tls`. Switch guest TPIDR only at `call_guest` / `jump_to_guest` (and restore host on return from `call_guest`).

## Hypercall and stacks

12. **MUST** use a single production syscall entry for main and workers: freestanding hypercall → `kh_hypercall_entry`.
13. **MUST** save full **Q0–Q31 + FPCR/FPSR** before any host `bl` in the hypercall entry. Production also uses full tramp around Rust dispatch. **MUST NOT** reintroduce a "light" NEON skip without measured wall win and MT re-validation.
14. **MUST** run host dispatch on the **host alt stack**, not the guest worker stack.
15. **MUST** pre-map the host alt stack while host TPIDR is live.
16. **MUST NOT** rely on “dispatch on guest stack” as an MT-safe fallback.

## Memory and I/O

17. **MUST** treat guest VA as identity-mapped host pointers only after `check_range` (or equivalent).
18. **MUST NOT** hold a process-global lock on `read` / `write` / `pread` / `pwrite` hot paths.
19. **MUST** keep freestanding `libSystem` product path under
    `crates/kh-runtime/resources/libSystem.B.dylib` (embed); **MUST NOT** reintroduce
    `dist/guest` as the primary discovery path.

## Unsafe and modules

20. **MUST** keep `unsafe` in allowlisted `kh-runtime` modules with explicit `// SAFETY:` invariants.
21. **MUST NOT** widen `unsafe` into CLI or loader for register / TPIDR control; use `cpu` / `tls` / `entry` / `trap` / `thread`.

## Historical failure modes

| Symptom | False lead | Actual root |
| --- | --- | --- |
| SEGV PC in host `libgcc_s` under hypercall MT | NEON / hypercall vs SIGTRAP | `pthread_exit` → `_Unwind_ForcedUnwind` over guest `x29` |
| Intermittent SEGV after join | Random heap | `done` published too early; join munmaps live stack |
| errno races under MT | Guest app bug | Process-global `___error` |
| Crash only with `-mmt>1 -mx>0` | “Compression math” | Boundary/teardown; ST may mask |

## Change checklist

When editing `thread.rs`, `trap.rs` hypercall asm, `tls.rs`, `host_slot.rs`,
or freestanding `pthread.rs` / `sys.rs`:

- [ ] Join order: result → terminate → host stack → done → wake
- [ ] Worker end: `SYS_exit`, `x29` cleared
- [ ] Hypercall: host TPIDR + alt stack + full NEON before host code
- [ ] No new `thread_local!` on guest-TPIDR paths
- [ ] Gate: `7zz a -mx=5 -mmt=4` and `t` pass with hypercall default
- [ ] Stage `resources/libSystem.B.dylib` if guest ABI changed

## References

- [Threading](threading.md)
- [Guest–host boundary](guest-host-boundary.md)
- [Architecture](architecture.md)
