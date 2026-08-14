//! Native ARM64 execution context, guest memory layout, and trap hooks.
//!
//! Dependency rule: this crate must not depend on `kh-loader` or `kh-cli`.
//!
//! Layout:
//! - [`bottle`] — guest root FS / tools install
//! - [`mem`] — page geometry, mapping, address-space registry
//! - [`syscall`] — BSD / helper dispatch
//! - [`cpu`] — registers, trap backend, entry, host-thread slots
//! - [`thread`] — guest threads + TLS
//! - [`process`] — process-wide run state, stack, dyld table
//! - [`host`] — host OS primitives + fat Mach-O open
//!
//! `unsafe` is denied by workspace lints and only allowed in tightly scoped
//! modules (`cpu/*`, `host/*`, `mem/*`, `thread/*`, `syscall` handlers, and
//! `bottle::read_c_string`).

pub mod bottle;
pub mod cpu;
pub mod host;
pub mod mem;
pub mod process;
pub mod syscall;
pub mod thread;

// Stable paths for modules that used to sit at the crate root.
pub use cpu::entry;
pub use cpu::host_slot;
pub use cpu::regs;
pub use cpu::trap;
pub use host::fat_thin;
pub use process::dyld_table;
pub use process::stack;
pub use thread::tls;
pub use thread::tls_fd;
pub use thread::tls_verify;

pub use bottle::{
    BottleError, BottleStatus, CreateOptions, CreateResult, DARWIN_7ZZ_URL, DARWIN_CURL_URL,
    DEFAULT_7ZZ_PATH, ENV_7ZZ, ENV_CURL, GUEST_7ZZ_REL, GUEST_CURL_REL, GUEST_LIBCURL_REL,
    GUEST_LIBCURL_TARGET, GUEST_LIBCXX_REL, GUEST_LIBCXX_TARGET, GUEST_PATH_DIRS, InstallPackage,
    InstallReport, PathError, ToolError, active_root, bottle_has_macos_prefix, bottle_root,
    create as create_bottle, create_with as create_bottle_with, destroy as destroy_bottle,
    discover_7zz, discover_curl, ensure as ensure_bottle, ensure_libcurl_symlink,
    ensure_libcxx_symlink, guest_path_to_host, has_libcurl_symlink, has_libcxx_symlink,
    install_package, macos_prefix_hint, package_host_path, resolve_guest_program, set_bottle_root,
    status as bottle_status, translate_path, translate_path_with_root,
};
pub use dyld_table::{
    RTLD_DEFAULT, RTLD_NEXT, RTLD_SELF, clear as dyld_table_clear, dlopen_lookup, dlsym_lookup,
    dlsym_sign_ia as dyld_dlsym_sign_ia, exports_flat as dyld_exports_flat,
    register_image as dyld_register_image, set_dlsym_sign_ia as dyld_set_dlsym_sign_ia,
};
pub use process::dlopen_load::{set_dlopen_loader, try_dlopen_load};
pub use process::{ProcessState, reset_run};

pub use entry::{EntryError, call_guest, call_guest_args, jump_to_guest, jump_to_guest_args};
pub use host::MappedFile;
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
    otool_classic_wants_llvm_disasm,
};
pub use tls::{
    GUEST_TLS_MAGIC, enter_host_tls, install_main_guest_tls, leave_host_tls, prepare_host_meta,
};
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
pub use trap::kh_trampoline_dispatch;
pub use trap::{
    PSTATE_C, TrapConfig, TrapError, TrapEvent, TrapOutcome, clear_expect_code,
    clear_trace_on_exit, finish_with_exit_code, hypercall_entry_addr, install_trap_handlers,
    patch_svc_to_brk, set_expect_code, set_trace_on_exit, take_trace_events,
};
// `kh_hypercall_entry` is a `global_asm!` symbol; address via `hypercall_entry_addr`.
