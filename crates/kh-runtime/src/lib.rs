//! Native ARM64 execution context, guest memory layout, and trap hooks.
//!
//! Dependency rule: this crate must not depend on `kh-loader` or `kh-cli`.
//!
//! `unsafe` is denied by workspace lints and only allowed in tightly scoped
//! modules (`host`, `mem/*`, `trap`, `entry`, and `bottle::read_c_string`).

pub mod bottle;
pub mod entry;
pub mod host;
pub mod mem;
pub mod process;
pub mod regs;
pub mod stack;
pub mod syscall;
pub mod thread;
pub mod trap;

pub use bottle::{
    BottleError, BottleStatus, CreateOptions, CreateResult, DEFAULT_7ZZ_PATH, ENV_7ZZ,
    GUEST_LIBCXX_REL, GUEST_LIBCXX_TARGET, PathError, active_root, bottle_root,
    create as create_bottle, create_with as create_bottle_with, destroy as destroy_bottle,
    discover_7zz, ensure_libcxx_symlink, has_libcxx_symlink, set_bottle_root,
    status as bottle_status, translate_path, translate_path_with_root,
};
pub use process::{ProcessState, reset_run};

pub use entry::{EntryError, call_guest, call_guest_args, jump_to_guest, jump_to_guest_args};
pub use mem::{
    AddressSpace, DARWIN_ARM64_PAGE_SIZE, GuestMemory, GuestPageSize, HostPageSize, MapError,
    MapRequest, MappedRegion, PageError, PageLayout, VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE,
    map_stack, mprotect_darwin, mprotect_rw, register_borrowed, registry_clear, registry_install,
    registry_take,
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
