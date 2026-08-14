//! Micro execution: map, patch traps, bootstrap stack, jump to entry.
#![allow(unsafe_code)]

use std::path::{Path, PathBuf};

use kh_runtime::bottle::host_path_to_guest;
use kh_runtime::process as proc_state;
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

    crate::load_timing::begin_run();
    crate::load_timing::note(format!("executable={}", path.display()));

    kh_runtime::set_dlopen_loader(load_dylib_on_demand);
    set_bottle_root(opts.root.clone());
    // Guest-visible main path for `_NSGetExecutablePath` (clang -cc1 re-spawn).
    let guest_exec = host_path_to_guest(path).or_else(|| {
        // Bare host path outside bottle: still prefer an absolute guest-ish form.
        path.to_str().map(str::to_owned)
    });
    proc_state::set_guest_executable_path(guest_exec.clone());
    // Drop any previous active address space (unmaps owned guest mmaps).
    drop(registry_take());

    let mut session = crate::load_timing::time_result("open_session", || {
        LoadSession::open_with_guest(path, opts.root.clone(), opts.guest_page_size)
    })?;
    // `otool-classic -t -v` `dlopen`s sibling `libLTO` for `LLVMCreateDisasm`.
    // Mid-run map of that image faults (RX TEXT bind). Seed it here so it
    // takes the same startup `map_process` path that already works for `ld`.
    maybe_seed_otool_liblto(&mut session, path, &opts.guest_args);
    // Sub-phases recorded inside `map_process` (map_main / walk_deps / rebase / bind).
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

    let mut stack =
        crate::load_timing::time_result("map_stack", || map_stack(host, DEFAULT_STACK_SIZE))?;

    // Prefer full guest absolute path as argv0 (Darwin-style); basename fallback.
    let argv0 = guest_exec.as_deref().filter(|s| !s.is_empty()).map_or_else(
        || {
            path.file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("guest")
                .to_owned()
        },
        str::to_owned,
    );
    let mut argv_owned = Vec::with_capacity(opts.guest_args.len().saturating_add(1));
    argv_owned.push(argv0);
    argv_owned.extend(opts.guest_args.iter().cloned());
    let argv_refs: Vec<&str> = argv_owned.iter().map(String::as_str).collect();
    // Minimal macOS-like environment so guests see a real PATH under the bottle.
    // HOME bridges the host home via `/Volumes/linux…` so host
    // `git config --global` (and `~/.gitconfig`) is visible to Apple git under
    // `kh run`. Fall back to bottle `/var/root` when host HOME is unset/odd.
    let home = guest_home_env();
    // Base env + host `GIT_*` (nested re-exec of git-remote-* inherits
    // `GIT_DIR` / `GIT_OBJECT_DIRECTORY` via inject_kh_env → host environ).
    // Without this, clone dies: "remote-curl: fetch attempted without a local repo".
    let mut env_owned = vec![
        // git-core first so `execvp("git-remote-https")` finds CLT helpers (G4).
        // CLT usr/bin next: guest make/cc look up gcc/clang via PATH (bottle
        // has no /usr/bin gcc shim — only git is symlinked there).
        "PATH=/Library/Developer/CommandLineTools/usr/libexec/git-core:\
/Library/Developer/CommandLineTools/usr/bin:\
/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
            .to_owned(),
        home,
        // Match Darwin `confstr(_CS_DARWIN_USER_TEMP_DIR)` length class
        // (`/var/folders/…/T/`, ~49 chars). Soft `/tmp` made clang `-flto`
        // `-object_path_lto` paths too short for freestanding LTO materialize.
        "TMPDIR=/var/folders/xx/kakehashi_default_user_temp000/T/".to_owned(),
    ];
    // Apple clang without a working `xcrun` does not auto-pick
    // `…/SDKs/MacOSX.sdk` (see `clang -v`: only CLT usr/include). Point the
    // driver at the bottle SDK when `kh install xcode-tools` laid it down.
    if let Some(sdk_env) = guest_sdk_env(opts.root.as_deref()) {
        env_owned.extend(sdk_env);
    }
    for (k, v) in std::env::vars() {
        // Nested re-exec: pass through GIT_* and DYLD_* so guest `main` envp and
        // freestanding soft-seed (via host getenv) see the same values. Modern
        // `ld` stages `libLTO` under `/tmp/ld-support-*` and re-execs with
        // `DYLD_LIBRARY_PATH` set; dropping that var caused an infinite re-exec.
        let keep = k.starts_with("GIT_")
            || k == "DYLD_LIBRARY_PATH"
            || k == "DYLD_FALLBACK_LIBRARY_PATH"
            || k == "DYLD_FRAMEWORK_PATH";
        if !keep || k.contains('\0') || v.contains('\0') {
            continue;
        }
        // Soft-cap: skip absurdly large values.
        if k.len().saturating_add(v.len()) > 512 {
            continue;
        }
        env_owned.push(format!("{k}={v}"));
    }
    let env_refs: Vec<&str> = env_owned.iter().map(String::as_str).collect();

    let stack_base = stack.guest_addr;
    let sp = crate::load_timing::time_result("bootstrap_stack", || {
        bootstrap_stack(stack.host_bytes_mut(), stack_base, &argv_refs, &env_refs)
            .map_err(|err| LoadError::NotImplemented(stack_err_static(&err)))
    })?;

    // Build process address space, then install for trap-path checks / mmap bookkeeping.
    // Hypercall NEON tramp is mapped separately (once, process-local); residual `svc`→`brk`
    // needs the registry only for later mmap bookkeeping and SIGTRAP translation.
    crate::load_timing::time("registry_install", || {
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
    });

    // Wire freestanding libSystem → `kh_hypercall_entry` (sole production BSD path).
    // Residual Darwin `svc` is always rewritten to `brk` below;
    // that is *not* a second production path (see invariants 7, 12).
    warn_if_hypercall_env_opt_out();
    let hypercall_wired = crate::load_timing::time("wire_hypercall", || {
        install_libsystem_hypercall(&mut session)
    });
    // Rewrite any leftover Darwin `svc` so Linux never executes them as host syscalls.
    let mut patched_svc = 0usize;
    crate::load_timing::time_result("patch_svc", || {
        for memory in session.mapped_memories_mut() {
            patched_svc = patched_svc
                .saturating_add(patch_svc_to_brk(memory.regions_mut()).map_err(trap_to_load)?);
        }
        Ok::<(), LoadError>(())
    })?;

    crate::load_timing::time_result("install_traps", || {
        install_trap_handlers(&TrapConfig {
            max_events: opts.max_events,
            max_syscalls: opts.max_syscalls,
        })
        .map_err(trap_to_load)
    })?;

    // Main-thread guest TLS (TPIDR_EL0) before constructors / LC_MAIN touch errno.
    let main_tls = crate::load_timing::time("main_tls", install_main_guest_tls);
    if main_tls != 0 {
        tracing::debug!(
            main_tls = format_args!("{main_tls:#x}"),
            "installed main guest TLS (TPIDR_EL0)"
        );
    }

    // dyld-order: constructors (dylibs bottom-up, then main) before LC_MAIN.
    let initializers_run =
        crate::load_timing::time_result("initializers", || init::run_initializers(&session, sp))?;

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

    // Darwin crt0: `setprogname(argv[0])` before main so `___progname` /
    // `getprogname()` match the invoked basename. CLT multi-call tools
    // (`ranlib` → `libtool`) branch on progname; freestanding default
    // `"kh-guest"` made `ar`'s internal `ranlib -q` fail with "unknown option -q".
    let setprogname_va = freestanding_export_va(&session, "_setprogname")
        .or_else(|| freestanding_export_va(&session, "setprogname"));

    // Publish mapped images for freestanding `dlopen`/`dlsym` (e.g. clang's
    // `-lto_library` re-open of already-loaded `@rpath/libLTO.dylib`).
    crate::load_timing::time("dyld_table", || register_dyld_images(&session));

    // Dump load phases before guest entry (guest may noreturn via `_exit`).
    crate::load_timing::dump("pre-entry");

    // Call setprogname while stack is still a live MappedRegion (read argv[0]).
    if let Some(va) = setprogname_va {
        let argv0_cstr = {
            let rel = sp.wrapping_sub(stack_base).wrapping_add(8);
            let off = usize::try_from(rel).unwrap_or(usize::MAX);
            stack
                .host_bytes()
                .get(off..off.saturating_add(8))
                .and_then(|b| <[u8; 8]>::try_from(b).ok())
                .map(u64::from_le_bytes)
                .filter(|&p| p != 0)
        };
        if let Some(ptr) = argv0_cstr {
            // SAFETY: freestanding `_setprogname`; `ptr` is a stack C string.
            let _ = unsafe { call_guest(va, sp, ptr) };
        }
    }

    // Keep stack / session alive across the call (may noreturn via guest exit).
    // `forget` retains all GuestMemory owners if exit traps.
    std::mem::forget(stack);
    std::mem::forget(session);

    // SAFETY: image is mapped RX, entry points into __TEXT, stack is bootstrapped,
    // trap handlers installed for Linux aarch64. Uses `blr` so `return` from
    // `main` resumes the host (dyld-equivalent); guest `exit` still `_exit`s.
    let guest_t0 = std::time::Instant::now();
    let status = unsafe {
        call_guest_args(entry, sp, argc, argv_ptr, envp_ptr, apple_ptr)
            .map_err(|err| LoadError::PageLayout(err.to_string()))?
    };
    let guest_ns = u64::try_from(guest_t0.elapsed().as_nanos()).unwrap_or(u64::MAX);
    crate::load_timing::record("guest_main_return", guest_ns);
    crate::load_timing::dump("post-return");

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

/// Fill `kh_runtime::dyld_table` from every mapped image (path + slid exports).
fn register_dyld_images(session: &LoadSession) {
    use crate::session::ImageLoadStatus;
    for img in session.images() {
        if !matches!(img.status, ImageLoadStatus::Mapped) {
            continue;
        }
        let slide = img.slide();
        let exports = img
            .exports
            .iter()
            .map(|e| (e.name.clone(), e.value.wrapping_add(slide)));
        kh_runtime::dyld_register_image(img.path.clone(), img.install_name.clone(), exports);
    }
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

/// Seed sibling `libLTO.dylib` when `otool-classic` will ask LLVM for `-t -v`.
fn maybe_seed_otool_liblto(session: &mut LoadSession, path: &Path, argv: &[String]) {
    if !kh_runtime::otool_classic_wants_llvm_disasm(path, argv) {
        return;
    }
    let Some(guest) = liblto_install_name_for_otool(path) else {
        tracing::debug!(
            exe = %path.display(),
            "otool-classic -t -v: sibling libLTO.dylib not on disk"
        );
        return;
    };
    tracing::info!(liblto = %guest, "seed libLTO for otool-classic LLVM disasm");
    session.seed_dylib(guest);
}

/// Guest install name for `$exedir/../lib/libLTO.dylib` (cctools layout).
fn liblto_install_name_for_otool(otool: &Path) -> Option<String> {
    let lib = otool.parent()?.join("..").join("lib").join("libLTO.dylib");
    if !lib.is_file() {
        return None;
    }
    kh_runtime::bottle::host_path_to_guest(&lib).or_else(|| {
        Some("/Library/Developer/CommandLineTools/usr/lib/libLTO.dylib".to_owned())
    })
}

/// Late `dlopen` of a dylib that was not in the startup image set.
///
/// Maps one file, binds it against already-registered exports (libSystem /
/// libc++), runs its initializers, and publishes it in the dyld table.
fn load_dylib_on_demand(host: &Path, guest: &str) -> Option<u64> {
    match load_dylib_on_demand_inner(host, guest) {
        Ok(h) => Some(h),
        Err(err) => {
            tracing::warn!(
                path = %host.display(),
                guest,
                error = %err,
                "dlopen on-demand failed"
            );
            None
        }
    }
}

fn load_dylib_on_demand_inner(host: &Path, guest: &str) -> Result<u64, LoadError> {
    if let Some(h) = kh_runtime::dlopen_lookup(Some(host), guest) {
        return Ok(h);
    }
    let root = kh_runtime::bottle_root();
    let mut session = LoadSession::open_with_guest(host, root, GuestPageSize::default())?;
    session.map_standalone()?;
    let _ = crate::rebase::rebase_process(&mut session)?;
    let extra = kh_runtime::dyld_exports_flat();
    crate::bind::bind_process_with_flat(&mut session, &extra)?;

    for memory in session.mapped_memories_mut() {
        let _ = patch_svc_to_brk(memory.regions_mut()).map_err(trap_to_load)?;
    }
    for img in session.images() {
        if let Some(memory) = img.memory.as_ref() {
            for region in memory.regions() {
                kh_runtime::register_borrowed(region);
            }
        }
    }

    let host_pages = kh_runtime::HostPageSize::detect()
        .map_err(|err| LoadError::PageLayout(err.to_string()))?;
    let ctor_stack = map_stack(host_pages, 1024 * 1024).map_err(|err| {
        LoadError::PageLayout(format!("dlopen ctor stack: {err}"))
    })?;
    kh_runtime::register_borrowed(&ctor_stack);
    let sp = ctor_stack
        .guest_addr
        .saturating_add(ctor_stack.vmsize)
        .saturating_sub(16)
        & !15;
    let _ = init::run_initializers(&session, sp)?;
    std::mem::forget(ctor_stack);

    register_dyld_images(&session);
    std::mem::forget(session);
    kh_runtime::dlopen_lookup(Some(host), guest)
        .ok_or(LoadError::NotImplemented("dlopen: image not in table after map"))
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

/// Guest absolute default SDK path (CLT layout after `kh install xcode-tools`).
const GUEST_DEFAULT_SDKROOT: &str = "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk";

/// Guest absolute CLT developer dir.
const GUEST_DEFAULT_DEVELOPER_DIR: &str = "/Library/Developer/CommandLineTools";

/// `SDKROOT` + `DEVELOPER_DIR` when the bottle has MacOSX.sdk headers.
///
/// Apple clang's default search without a working `xcrun` omits the sysroot;
/// setting these matches what `xcode-select` + `xcrun --show-sdk-path` provide
/// on a real Mac with Command Line Tools only.
fn guest_sdk_env(bottle: Option<&Path>) -> Option<Vec<String>> {
    let bottle = bottle?;
    let stdio =
        bottle.join("Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/stdio.h");
    if !stdio.is_file() {
        // Fall back: any MacOSX*.sdk with headers (symlink missing).
        let sdks = bottle.join("Library/Developer/CommandLineTools/SDKs");
        let Ok(entries) = std::fs::read_dir(&sdks) else {
            return None;
        };
        let found = entries.flatten().any(|ent| {
            let name = ent.file_name();
            let name = name.to_string_lossy();
            name.starts_with("MacOSX")
                && name.contains(".sdk")
                && ent.path().join("usr/include/stdio.h").is_file()
        });
        if !found {
            return None;
        }
    }
    Some(vec![
        format!("SDKROOT={GUEST_DEFAULT_SDKROOT}"),
        format!("DEVELOPER_DIR={GUEST_DEFAULT_DEVELOPER_DIR}"),
    ])
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
