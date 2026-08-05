//! Micro execution: map, patch traps, bootstrap stack, jump to entry.
#![allow(unsafe_code)]

use std::path::{Path, PathBuf};

use kh_runtime::{
    AddressSpace, GuestPageSize, TrapConfig, TrapError, TrapEvent, bootstrap_stack, call_guest,
    call_guest_args, finish_with_exit_code, install_main_guest_tls, install_trap_handlers,
    map_stack, patch_svc_to_brk, registry_install, registry_take, set_bottle_root,
};
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
use kh_runtime::{VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE, mprotect_darwin, mprotect_rw};

use crate::error::LoadError;
use crate::init;
use crate::session::LoadSession;

/// Default guest stack size for the micro spike (1 MiB).
/// Guest stack for micro execution (8 MiB — C++ guests like `7zz` use deep frames).
pub const DEFAULT_STACK_SIZE: u64 = 8 * 1024 * 1024;

/// Options for a micro run / trace.
#[derive(Debug, Clone)]
pub struct RunOptions {
    /// Bottle root (`KAKEHASHI_ROOT` / `--root`) for path translation.
    pub root: Option<PathBuf>,
    /// Guest page size policy.
    pub guest_page_size: GuestPageSize,
    /// Guest argv (not including argv0 = executable path — that is prepended).
    pub guest_args: Vec<String>,
    /// Maximum trap events to retain.
    pub max_events: usize,
    /// Maximum syscalls before forced process exit.
    pub max_syscalls: usize,
    /// When true, only map (caller should use [`LoadSession::dry_load`] instead).
    pub dry_load: bool,
}

impl Default for RunOptions {
    fn default() -> Self {
        Self {
            root: None,
            guest_page_size: GuestPageSize::default(),
            guest_args: Vec::new(),
            max_events: 256,
            max_syscalls: 256,
            dry_load: false,
        }
    }
}

/// Result of a completed micro run (when the host does not process-exit).
#[derive(Debug)]
pub struct RunResult {
    /// Exit code if the guest called `exit` without `_exit` from the handler.
    pub exit_code: Option<i32>,
    /// Captured trap events (empty if process already exited).
    pub events: Vec<TrapEvent>,
    /// Number of `svc` instructions patched to `brk`.
    pub patched_svc: usize,
    /// Entry VA used for the jump.
    pub entry: u64,
    /// Stack pointer passed to the guest.
    pub sp: u64,
    /// Applied **main** image slide.
    pub slide: u64,
    /// Number of `mod_init` functions invoked before main.
    pub initializers_run: usize,
}

/// Maps, patches, and transfers control to the guest entry.
///
/// On a successful guest `exit`, this function **does not return**: the trap
/// handler terminates the process with the guest status.
pub fn run_micro(path: &Path, opts: &RunOptions) -> Result<RunResult, LoadError> {
    if opts.dry_load {
        return Err(LoadError::NotImplemented(
            "run_micro: use LoadSession::dry_load for --dry-load",
        ));
    }

    set_bottle_root(opts.root.clone());
    // Drop any previous active address space (unmaps owned guest mmaps).
    drop(registry_take());

    let mut session = LoadSession::open_with_guest(path, opts.root.clone(), opts.guest_page_size)?;
    let _ = session.map_process()?;

    let slide = session
        .images()
        .first()
        .map_or(0, crate::session::ProcessImage::slide);
    let entry = session
        .entry_va()
        .ok_or(LoadError::NotImplemented("image has no entry point"))?;

    let host = session
        .images()
        .first()
        .and_then(|img| img.memory.as_ref())
        .map(kh_runtime::GuestMemory::host)
        .ok_or(LoadError::NotImplemented("memory missing"))?;

    let mut stack = map_stack(host, DEFAULT_STACK_SIZE)?;

    let argv0 = path.file_name().and_then(|s| s.to_str()).unwrap_or("guest");
    let mut argv_owned = Vec::with_capacity(opts.guest_args.len().saturating_add(1));
    argv_owned.push(argv0.to_owned());
    argv_owned.extend(opts.guest_args.iter().cloned());
    let argv_refs: Vec<&str> = argv_owned.iter().map(String::as_str).collect();
    // Minimal macOS-like environment so guests see a real PATH under the bottle.
    // HOME bridges the host home via `/Volumes/linux…` so host
    // `git config --global` (and `~/.gitconfig`) is visible to Apple git under
    // `kh run`. Fall back to bottle `/var/root` when host HOME is unset/odd.
    let home = guest_home_env();
    let env_owned = [
        // git-core first so `execvp("git-remote-https")` finds CLT helpers (G4).
        "PATH=/Library/Developer/CommandLineTools/usr/libexec/git-core:\
/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
            .to_owned(),
        home,
        "TMPDIR=/tmp".to_owned(),
    ];
    let env_refs: Vec<&str> = env_owned.iter().map(String::as_str).collect();

    let stack_base = stack.guest_addr;
    let sp = bootstrap_stack(stack.host_bytes_mut(), stack_base, &argv_refs, &env_refs)
        .map_err(|err| LoadError::NotImplemented(stack_err_static(&err)))?;

    // Build process address space, then install for trap-path checks / mmap bookkeeping.
    // Hypercall NEON tramp is mapped separately (once, process-local); residual `svc`→`brk`
    // needs the registry only for later mmap bookkeeping and SIGTRAP translation.
    let mut address_space = AddressSpace::new();
    for img in session.images() {
        if let Some(memory) = img.memory.as_ref() {
            for region in memory.regions() {
                address_space.register_borrowed(region);
            }
        }
    }
    address_space.register_borrowed(&stack);
    drop(registry_install(address_space));

    // Wire freestanding libSystem → `kh_hypercall_entry` (sole production BSD path).
    // Residual Darwin `svc` in fixtures/apps is always rewritten to `brk` below;
    // that is *not* a second production path (see invariants 7, 12).
    warn_if_hypercall_env_opt_out();
    let hypercall_wired = install_libsystem_hypercall(&mut session);
    // Rewrite any leftover Darwin `svc` so Linux never executes them as host syscalls.
    let mut patched_svc = 0usize;
    for memory in session.mapped_memories_mut() {
        patched_svc = patched_svc
            .saturating_add(patch_svc_to_brk(memory.regions_mut()).map_err(trap_to_load)?);
    }

    install_trap_handlers(&TrapConfig {
        max_events: opts.max_events,
        max_syscalls: opts.max_syscalls,
    })
    .map_err(trap_to_load)?;

    // Main-thread guest TLS (TPIDR_EL0) before constructors / LC_MAIN touch errno.
    let main_tls = install_main_guest_tls();
    if main_tls != 0 {
        tracing::debug!(
            main_tls = format_args!("{main_tls:#x}"),
            "installed main guest TLS (TPIDR_EL0)"
        );
    }

    // dyld-order: constructors (dylibs bottom-up, then main) before LC_MAIN.
    let initializers_run = init::run_initializers(&session, sp)?;

    tracing::info!(
        entry = format_args!("{entry:#x}"),
        sp = format_args!("{sp:#x}"),
        slide,
        patched_svc,
        hypercall_wired,
        main_tls = format_args!("{main_tls:#x}"),
        initializers_run,
        images = session.images().len(),
        root = ?opts.root,
        "jumping to guest entry"
    );

    // Darwin `main(argc, argv, envp, apple)` register setup from the stack image:
    //   [sp+0] = argc, [sp+8] = argv[0], …, NULL, envp…, NULL, apple NULL.
    let argc = u64::try_from(argv_owned.len()).unwrap_or(0);
    let argv_ptr = sp.wrapping_add(8);
    let envp_ptr = argv_ptr.wrapping_add(argc.saturating_add(1).saturating_mul(8));
    let apple_ptr = envp_ptr.wrapping_add(8); // empty env → envp NULL then apple NULL

    // Resolve freestanding heap dump before forget (exports live on session).
    // `main` return never enters guest `_exit`, so dig counters need this call.
    let heap_dump_va = freestanding_export_va(&session, "_kh_heap_stats_dump")
        .or_else(|| freestanding_export_va(&session, "kh_heap_stats_dump"));

    // Keep stack / session alive across the call (may noreturn via guest exit).
    // `forget` retains all GuestMemory owners if exit traps.
    std::mem::forget(stack);
    std::mem::forget(session);

    // SAFETY: image is mapped RX, entry points into __TEXT, stack is bootstrapped,
    // trap handlers installed for Linux aarch64. Uses `blr` so `return` from
    // `main` resumes the host (dyld-equivalent); guest `exit` still `_exit`s.
    let status = unsafe {
        call_guest_args(entry, sp, argc, argv_ptr, envp_ptr, apple_ptr)
            .map_err(|err| LoadError::PageLayout(err.to_string()))?
    };

    // Dump freestanding heap stats (guest stderr) before host process exit.
    if let Some(va) = heap_dump_va {
        // SAFETY: VA is freestanding export; stack still mapped; may hypercall write(2).
        let _ = unsafe { call_guest(va, sp, 0) };
    }

    // dyld: exit(main(...)). Low 32 bits as signed process status (Darwin int).
    let low = u32::try_from(status & 0xffff_ffff).unwrap_or(0);
    let code = i32::from_ne_bytes(low.to_ne_bytes());
    finish_with_exit_code(code);
}

/// Guest VA of a freestanding `libSystem` export (nlist + slide), if present.
fn freestanding_export_va(session: &LoadSession, name: &str) -> Option<u64> {
    let mut any = None;
    for img in session.images() {
        let path = img.path.to_string_lossy();
        let is_libsystem = path.contains("libSystem") || path.contains("libkh_libsystem");
        for exp in &img.exports {
            if exp.name != name {
                continue;
            }
            let va = exp.value.saturating_add(img.slide());
            if is_libsystem {
                return Some(va);
            }
            if any.is_none() {
                any = Some(va);
            }
        }
    }
    any
}

fn stack_err_static(err: &kh_runtime::StackError) -> &'static str {
    match err {
        kh_runtime::StackError::TooSmall { .. } => "guest stack too small",
        kh_runtime::StackError::InvalidString => "invalid stack string",
    }
}

/// Guest `HOME=…` for the bootstrap env block.
///
/// Prefer host `$HOME` under the `/Volumes/linux` bridge so tools that honour
/// global config (Apple `git` → `~/.gitconfig`) see the same files as host CLI
/// config commands. Falls back to bottle `/var/root`.
fn guest_home_env() -> String {
    match std::env::var("HOME") {
        // Nested `kh run` (re-exec of a Mach-O helper) inherits the *guest*
        // env as host environ — HOME is already `/Volumes/linux…`. Do not
        // prefix again or `~/.gitconfig` resolves to a doubled path (G4).
        Ok(h) if h.starts_with("/Volumes/linux") && !h.contains('\0') => {
            format!("HOME={h}")
        }
        Ok(h) if h.starts_with('/') && !h.contains('\0') => {
            format!("HOME=/Volumes/linux{h}")
        }
        _ => "HOME=/var/root".to_owned(),
    }
}

fn trap_to_load(err: TrapError) -> LoadError {
    match err {
        TrapError::Map(map_err) => LoadError::Map(map_err),
        TrapError::UnsupportedArch => LoadError::PageLayout(
            "trap backend requires Linux aarch64 for live execution".to_owned(),
        ),
        TrapError::SignalSetup(io_err) => {
            LoadError::PageLayout(format!("trap signal setup: {io_err}"))
        }
    }
}

/// `KAKEHASHI_HYPERCALL=0` used to force freestanding `svc`→SIGTRAP for A/B
/// path digs. That opt-out is **removed**: production always wires hypercall.
/// Residual `svc`→`brk` still runs for fixtures; it is not a dual product path.
fn warn_if_hypercall_env_opt_out() {
    let Some(v) = std::env::var_os("KAKEHASHI_HYPERCALL") else {
        return;
    };
    let off = v == "0"
        || v.eq_ignore_ascii_case("false")
        || v.eq_ignore_ascii_case("no")
        || v.eq_ignore_ascii_case("off");
    if off {
        tracing::warn!(
            "KAKEHASHI_HYPERCALL={v:?} is ignored; freestanding hypercall is always wired \
             (use residual svc→brk only for unpatched fixtures, not as a product path)"
        );
    }
}

/// Point freestanding `libSystem`'s `_kh_bsd_hypercall` at host dispatch.
///
/// Returns whether the slot was found and written. On non-Linux hosts this is a
/// no-op (`false`).
fn install_libsystem_hypercall(session: &mut LoadSession) -> bool {
    #[cfg(not(all(target_arch = "aarch64", target_os = "linux")))]
    {
        let _ = session;
        false
    }
    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    {
        install_libsystem_hypercall_linux(session)
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
fn install_libsystem_hypercall_linux(session: &mut LoadSession) -> bool {
    // Freestanding thin call → host alt stack + NEON tramp + dispatch.
    let entry_u64 = kh_runtime::hypercall_entry_addr();
    if entry_u64 == 0 {
        return false;
    }

    let mut wired_entry = false;
    for img in session.images_mut() {
        let slide = img.slide();
        let exports: Vec<_> = img.exports.clone();
        for exp in exports {
            let slot = exp.name.as_str();
            if slot != "_kh_bsd_hypercall" && slot != "kh_bsd_hypercall" {
                continue;
            }
            let va = exp.value.saturating_add(slide);
            if !write_libsystem_u64(img, va, entry_u64) {
                continue;
            }
            wired_entry = true;
            tracing::info!(
                va = format_args!("{va:#x}"),
                entry = format_args!("{entry_u64:#x}"),
                "wired libSystem BSD hypercall"
            );
        }
    }
    wired_entry
}

/// Write 8 little-endian bytes at guest VA in an image mapping (mprotect if needed).
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
fn write_libsystem_u64(img: &mut crate::session::ProcessImage, va: u64, value: u64) -> bool {
    let Some(memory) = img.memory.as_mut() else {
        return false;
    };
    let Some(region_idx) = memory.regions().iter().position(|region| {
        let start = region.guest_addr;
        let end = start.saturating_add(u64::try_from(region.host_len()).unwrap_or(0));
        va >= start && va.saturating_add(8) <= end
    }) else {
        return false;
    };
    let Some(region) = memory.regions().get(region_idx) else {
        return false;
    };
    let old_prot = region.prot;
    let need_rw = old_prot & VM_PROT_WRITE == 0;
    if need_rw {
        let Some(region) = memory.regions_mut().get_mut(region_idx) else {
            return false;
        };
        if mprotect_rw(region).is_err() {
            return false;
        }
    }
    let ok = memory.write_u64_le(va, value).is_some();
    if need_rw {
        let mut restore = (old_prot | VM_PROT_READ) & !VM_PROT_WRITE;
        if old_prot & VM_PROT_EXECUTE != 0 {
            restore |= VM_PROT_EXECUTE;
        }
        if let Some(region) = memory.regions_mut().get_mut(region_idx) {
            drop(mprotect_darwin(region, restore));
            region.prot = restore;
        }
    }
    ok
}
