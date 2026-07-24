//! Native ARM64 execution context, guest memory layout, and trap hooks.
//!
//! Dependency rule: this crate must not depend on `kh-loader` or `kh-cli`.
//!
//! `unsafe` is denied by workspace lints and only allowed in tightly scoped
//! modules (`mem/*`, `trap`, `entry`, `bottle` C-string reads, `syscall` I/O).

pub mod bottle;
pub mod entry;
pub mod mem;
pub mod regs;
pub mod stack;
pub mod syscall;
pub mod trap;

pub use bottle::{
    PathError, bottle_root, set_bottle_root, translate_path, translate_path_with_root,
};
pub use entry::{EntryError, call_guest, call_guest_args, jump_to_guest};
pub use mem::{
    DARWIN_ARM64_PAGE_SIZE, GuestMemory, GuestPageSize, HostPageSize, MapError, MapRequest,
    MappedRegion, PageError, PageLayout, VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE, map_stack,
    mprotect_darwin, mprotect_rw, register_borrowed, registry_clear,
};
pub use regs::ThreadRegs;
pub use stack::{StackError, bootstrap_stack};
pub use syscall::{
    BsdSyscall, SyscallArgs, SyscallResult, known_syscalls, lookup as lookup_syscall, name_of,
};
pub use trap::{
    PSTATE_C, TrapConfig, TrapError, TrapEvent, TrapOutcome, clear_expect_code,
    clear_trace_on_exit, finish_with_exit_code, install_trap_handlers, patch_svc_to_brk,
    set_expect_code, set_trace_on_exit, take_trace_events,
};
