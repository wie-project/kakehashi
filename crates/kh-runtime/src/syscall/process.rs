//! Process-related BSD syscalls (`exit`, identity, **spawn**).

#![allow(unsafe_code)] // fork/waitpid/execve + CString pointer arrays

use std::ffi::CString;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use crate::bottle;
use crate::host;
use crate::mem::registry_check_range;

use super::common::{
    EFAULT, EINVAL, ENOENT, SyscallArgs, SyscallResult, exit_status, guest_read_u64, guest_write,
    reg_as_i32,
};

/// `exit`.
pub(crate) fn handle_exit(args: SyscallArgs) -> SyscallResult {
    SyscallResult::exit(exit_status(args.x0))
}

/// `fork` / `vfork` — host `fork`; parent gets child pid, child gets 0.
#[allow(unsafe_code)] // thin fork wrapper
pub(crate) fn handle_fork(_args: SyscallArgs) -> SyscallResult {
    let name = "fork";
    match host::fork_process() {
        Ok(pid) => {
            if pid > 0 {
                crate::process::child_born();
            }
            tracing::debug!(pid, "fork");
            SyscallResult::ok(name, u64::try_from(pid).unwrap_or(0))
        }
        Err(e) => SyscallResult::err(name, host_errno_to_darwin(e)),
    }
}

/// `wait4` — pid `x0`, status* `x1`, options `x2`, rusage* `x3` (ignored).
#[allow(unsafe_code)]
pub(crate) fn handle_wait4(args: SyscallArgs) -> SyscallResult {
    let name = "wait4";
    let pid = reg_as_i32(args.x0);
    let status_ptr = args.x1;
    let options = reg_as_i32(args.x2);
    if status_ptr != 0 && !registry_check_range(status_ptr, 4, true) {
        return SyscallResult::err(name, EFAULT);
    }
    match host::wait_pid(pid, options) {
        Ok((wpid, status)) => {
            // wpid == 0 with WNOHANG: no child ready (not a reap).
            if wpid > 0 {
                crate::process::child_reaped();
            }
            if status_ptr != 0 {
                guest_write(status_ptr, &status.to_ne_bytes());
            }
            // Soft-zero rusage if requested (guest may only check the pointer).
            if args.x3 != 0 && registry_check_range(args.x3, 128, true) {
                guest_write(args.x3, &[0_u8; 128]);
            }
            SyscallResult::ok(name, u64::try_from(wpid).unwrap_or(0))
        }
        Err(e) => SyscallResult::err(name, host_errno_to_darwin(e)),
    }
}

/// `execve` — path `x0`, argv `x1`, envp `x2`.
///
/// Mach-O guests are re-executed as `kh run <host-path> -- <args…>` so the
/// child stays inside the translator. Scripts with a shebang use the bottle
/// interpreter when it exists as Mach-O; otherwise the host interpreter.
#[allow(unsafe_code)]
pub(crate) fn handle_execve(args: SyscallArgs) -> SyscallResult {
    let name = "execve";
    if args.x0 == 0 || !registry_check_range(args.x0, 1, false) {
        return SyscallResult::err(name, EFAULT);
    }
    let Some(path) = bottle::read_c_string(args.x0, 4096) else {
        return SyscallResult::err(name, EFAULT);
    };
    let Some(argv) = read_cstr_array(args.x1, 256) else {
        return SyscallResult::err(name, EFAULT);
    };
    let Some(envp) = read_cstr_array(args.x2, 512) else {
        return SyscallResult::err(name, EFAULT);
    };

    let Ok(host_path) = bottle::translate_path(&path) else {
        return SyscallResult::err(name, ENOENT);
    };
    if !host_path.is_file() {
        return SyscallResult::err(name, ENOENT);
    }

    tracing::debug!(
        guest = %path,
        host = %host_path.display(),
        argc = argv.len(),
        "execve"
    );
    let err = if is_macho(&host_path) {
        reexec_kh_macho(&host_path, &argv, &envp)
    } else if let Some(script_err) = try_exec_script(&host_path, &argv, &envp) {
        script_err
    } else {
        // Last resort: direct host exec (native Linux binary in the bottle/bridge).
        reexec_direct(&host_path, &argv, &envp)
    };
    SyscallResult::err(name, host_errno_to_darwin(err))
}

fn host_errno_to_darwin(e: i32) -> i64 {
    // Common overlap for ENOENT/EACCES/ENOMEM/EINVAL; map a few Linux-only.
    match e {
        e if e == libc::ENOENT => ENOENT,
        e if e == libc::EINVAL => EINVAL,
        e if e == libc::EFAULT => EFAULT,
        e if e == libc::ENOMEM => 12,
        e if e == libc::EACCES => 13,
        e if e == libc::EPERM => 1,
        e if e == libc::EAGAIN || e == libc::EWOULDBLOCK => 35,
        e if e == libc::ENOEXEC => 8,
        e if e == libc::ECHILD => 10,
        other => i64::from(other.unsigned_abs().min(u32::from(u16::MAX))),
    }
}

fn read_cstr_array(ptr: u64, max: usize) -> Option<Vec<String>> {
    if ptr == 0 {
        // Empty env/argv is represented as a single NULL pointer at a valid address
        // in normal libc; a null array pointer means "use empty".
        return Some(Vec::new());
    }
    if !registry_check_range(ptr, 8, false) {
        return None;
    }
    let mut out = Vec::new();
    for i in 0..max {
        let slot = ptr.wrapping_add(u64::try_from(i).unwrap_or(0).saturating_mul(8));
        if !registry_check_range(slot, 8, false) {
            return None;
        }
        let p = guest_read_u64(slot);
        if p == 0 {
            return Some(out);
        }
        let s = bottle::read_c_string(p, 1 << 16)?;
        out.push(s);
    }
    Some(out)
}

fn is_macho(path: &Path) -> bool {
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    let mut magic = [0_u8; 4];
    if f.read_exact(&mut magic).is_err() {
        return false;
    }
    // MH_MAGIC_64 / MH_MAGIC, MH_CIGAM_*, FAT_MAGIC / FAT_CIGAM
    matches!(
        magic,
        [0xfe, 0xed, 0xfa, 0xcf | 0xce]
            | [0xcf | 0xce, 0xfa, 0xed, 0xfe]
            | [0xca, 0xfe, 0xba, 0xbe]
            | [0xbe, 0xba, 0xfe, 0xca]
    )
}

/// Whether the post-`execve` image is still a guest under `kh` or a host binary.
#[derive(Clone, Copy)]
enum ExecEnvKind {
    /// Nested `kh run` (Mach-O helper): keep guest `/Volumes/linux…` paths.
    NestedKh,
    /// Host ELF / host shell script: rewrite bridge paths so OpenSSH etc. see
    /// real host `HOME` (`~/.ssh`, `~/.gitconfig` layout on the host FS).
    HostNative,
}

fn inject_kh_env(envp: &[String], kind: ExecEnvKind) -> Vec<CString> {
    let mut out: Vec<CString> = Vec::with_capacity(envp.len().saturating_add(8));
    let mut have_data = false;
    let mut have_config = false;
    let mut have_root = false;
    for e in envp {
        let e = match kind {
            ExecEnvKind::NestedKh => e.clone(),
            ExecEnvKind::HostNative => rewrite_guest_bridge_env(e),
        };
        if e.starts_with("KAKEHASHI_DATA_DIR=") {
            have_data = true;
        }
        if e.starts_with("KAKEHASHI_CONFIG_DIR=") {
            have_config = true;
        }
        if e.starts_with("KAKEHASHI_ROOT=") {
            have_root = true;
        }
        if let Ok(c) = CString::new(e.as_str()) {
            out.push(c);
        }
    }
    // Nested `kh run` inherits the *guest* env (HOME=/Volumes/linux…). Host
    // `kh` then resolves config/data via $HOME and misses the real registry →
    // no bottle → hard unresolved CoreServices symbols. Always inject host
    // paths resolved in *this* process (still has the real host HOME / env).
    if !have_config {
        let cfg = std::env::var("KAKEHASHI_CONFIG_DIR")
            .ok()
            .or_else(|| bottle::config_dir().ok().map(|p| p.display().to_string()));
        if let Some(v) = cfg
            && let Ok(c) = CString::new(format!("KAKEHASHI_CONFIG_DIR={v}"))
        {
            out.push(c);
        }
    }
    if !have_data {
        let data = std::env::var("KAKEHASHI_DATA_DIR")
            .ok()
            .or_else(|| bottle::data_dir().ok().map(|p| p.display().to_string()));
        if let Some(v) = data
            && let Ok(c) = CString::new(format!("KAKEHASHI_DATA_DIR={v}"))
        {
            out.push(c);
        }
    }
    if !have_root {
        let root = std::env::var("KAKEHASHI_ROOT")
            .ok()
            .or_else(|| bottle::bottle_root().map(|p| p.display().to_string()))
            .or_else(|| {
                bottle::active_root()
                    .ok()
                    .flatten()
                    .map(|p| p.display().to_string())
            });
        if let Some(v) = root
            && let Ok(c) = CString::new(format!("KAKEHASHI_ROOT={v}"))
        {
            out.push(c);
        }
    }
    // Preserve log level for nested runs when guest env stripped it.
    if !envp.iter().any(|e| e.starts_with("KAKEHASHI_LOG="))
        && let Ok(v) = std::env::var("KAKEHASHI_LOG")
        && let Ok(c) = CString::new(format!("KAKEHASHI_LOG={v}"))
    {
        out.push(c);
    }
    // Nested re-exec (e.g. modern `ld` `-lto_library`, clang `-cc1`) drops the
    // host analysis flags unless we re-inject them. Without this, only the
    // outermost process dumps `KAKEHASHI_BOUNDARY_STATS`.
    for key in [
        "KAKEHASHI_BOUNDARY_STATS",
        "KAKEHASHI_FUTEX_STATS",
        "KAKEHASHI_HEAP_STATS",
        "KAKEHASHI_LOAD_TIMING",
    ] {
        let prefix = format!("{key}=");
        if envp.iter().any(|e| e.starts_with(&prefix)) {
            continue;
        }
        if let Ok(v) = std::env::var(key)
            && let Ok(c) = CString::new(format!("{key}={v}"))
        {
            out.push(c);
        }
    }
    out
}

/// Map a single `KEY=value` entry: if `value` is a guest host-bridge path
/// (`/Volumes/linux…`), rewrite to the real host absolute path.
///
/// Only whole-value rewrites (not embedded substrings) so we never mangle
/// odd config strings. Used for host-native `execve` (OpenSSH, host shells).
fn rewrite_guest_bridge_env(entry: &str) -> String {
    let Some((key, val)) = entry.split_once('=') else {
        return entry.to_owned();
    };
    match guest_bridge_value_to_host(val) {
        Some(host) => format!("{key}={host}"),
        None => entry.to_owned(),
    }
}

fn guest_bridge_value_to_host(val: &str) -> Option<String> {
    const VOL: &str = "/Volumes/linux";
    if val == VOL {
        return Some("/".to_owned());
    }
    val.strip_prefix("/Volumes/linux/")
        .map(|rest| format!("/{rest}"))
}

fn env_ptrs(env: &[CString]) -> Vec<*const libc::c_char> {
    let mut v: Vec<*const libc::c_char> = env.iter().map(|c| c.as_ptr()).collect();
    v.push(core::ptr::null());
    v
}

/// True when `otool-classic` will `dlopen` `libLTO` for `LLVMCreateDisasm`.
///
/// Combined `-t`/`-x` plus `-v`/`-V` (and glued `-tv`) on arm64. The loader
/// seeds sibling `libLTO.dylib` at process start so the C API is already
/// mapped; mid-run bind of that image still faults.
#[must_use]
pub fn otool_classic_wants_llvm_disasm(host_path: &Path, argv: &[String]) -> bool {
    let Some(name) = host_path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    if name != "otool-classic" {
        return false;
    }
    otool_args_want_llvm_disasm(argv)
}

fn otool_args_want_llvm_disasm(argv: &[String]) -> bool {
    let mut text = false;
    let mut verbose = false;
    for a in argv {
        if a == "-t" || a == "-x" {
            text = true;
        }
        if a == "-v" || a == "-V" {
            verbose = true;
        }
        if matches!(a.as_str(), "-tv" | "-vt" | "-xv" | "-vx") {
            return true;
        }
    }
    text && verbose
}

fn reexec_kh_macho(host_path: &Path, argv: &[String], envp: &[String]) -> i32 {
    let Some((args_c, env_c)) = kh_run_argv_env(host_path, argv, envp) else {
        return libc::EINVAL;
    };
    let mut argv_ptrs: Vec<*const libc::c_char> = args_c.iter().map(|c| c.as_ptr()).collect();
    argv_ptrs.push(core::ptr::null());
    let env_ptrs = env_ptrs(&env_c);
    let Some(path0) = args_c.first() else {
        return libc::EINVAL;
    };
    // SAFETY: NUL-terminated argv/envp; path is CString.
    unsafe { host::execve_host(path0.as_c_str(), &argv_ptrs, &env_ptrs) }
}

/// Build `kh run <host_path> -- [guest argv without argv0]` + injected env.
///
/// Host path is already bottle-translated; the child opens it via `kh run`.
fn kh_run_argv_env(
    host_path: &Path,
    argv: &[String],
    envp: &[String],
) -> Option<(Vec<CString>, Vec<CString>)> {
    let kh = std::env::current_exe().ok()?;
    let kh_c = CString::new(kh.as_os_str().as_bytes()).ok()?;
    let path_c = CString::new(host_path.as_os_str().as_bytes()).ok()?;
    let run = CString::new("run").ok()?;
    let dd = CString::new("--").ok()?;
    let mut args_c: Vec<CString> = vec![kh_c, run, path_c, dd];
    for a in argv.iter().skip(1) {
        args_c.push(CString::new(a.as_str()).ok()?);
    }
    let env_c = inject_kh_env(envp, ExecEnvKind::NestedKh);
    Some((args_c, env_c))
}

/// Nested Mach-O spawn without forking the current guest address space.
///
/// Used by freestanding `posix_spawn` (`KH_HELPER_SPAWN`): host `posix_spawn` of
/// `kh run <path> -- …` so large CLT parents do not CoW-duplicate their maps.
pub(crate) fn spawn_kh_macho(
    host_path: &Path,
    argv: &[String],
    envp: &[String],
) -> Result<i32, i32> {
    let (args_c, env_c) = kh_run_argv_env(host_path, argv, envp).ok_or(libc::EINVAL)?;
    let mut argv_ptrs: Vec<*const libc::c_char> = args_c.iter().map(|c| c.as_ptr()).collect();
    argv_ptrs.push(core::ptr::null());
    let env_ptrs = env_ptrs(&env_c);
    let path0 = args_c.first().ok_or(libc::EINVAL)?;
    // SAFETY: NUL-terminated argv/envp live for the call; owned by `args_c`/`env_c`.
    let pid = unsafe { host::posix_spawn_host(path0.as_c_str(), &argv_ptrs, &env_ptrs) }?;
    if pid > 0 {
        crate::process::child_born();
    }
    Ok(pid)
}

/// `KH_HELPER_SPAWN`: direct nested spawn (path, argv, envp guest VAs).
///
/// Returns child pid on success. Avoids guest `fork` of multi-hundred-MiB images.
pub(crate) fn handle_spawn_helper(args: SyscallArgs) -> SyscallResult {
    let name = "kh_spawn";
    if args.x0 == 0 || !registry_check_range(args.x0, 1, false) {
        return SyscallResult::err(name, EFAULT);
    }
    let Some(path) = bottle::read_c_string(args.x0, 4096) else {
        return SyscallResult::err(name, EFAULT);
    };
    let Some(argv) = read_cstr_array(args.x1, 256) else {
        return SyscallResult::err(name, EFAULT);
    };
    let Some(envp) = read_cstr_array(args.x2, 512) else {
        return SyscallResult::err(name, EFAULT);
    };
    let Ok(host_path) = bottle::translate_path(&path) else {
        return SyscallResult::err(name, ENOENT);
    };
    if !host_path.is_file() {
        return SyscallResult::err(name, ENOENT);
    }
    tracing::debug!(
        guest = %path,
        host = %host_path.display(),
        argc = argv.len(),
        "kh_spawn"
    );
    if !is_macho(&host_path) {
        // Non-Mach-O: fall back to host posix_spawn of the path directly
        // (script / ELF). Nested shell scripts still get HostNative env.
        return spawn_host_path(&host_path, &argv, &envp, name);
    }
    match spawn_kh_macho(&host_path, &argv, &envp) {
        Ok(pid) => SyscallResult::ok(name, u64::try_from(pid).unwrap_or(0)),
        Err(e) => SyscallResult::err(name, host_errno_to_darwin(e)),
    }
}

fn spawn_host_path(
    host_path: &Path,
    argv: &[String],
    envp: &[String],
    name: &'static str,
) -> SyscallResult {
    let Ok(path_c) = CString::new(host_path.as_os_str().as_bytes()) else {
        return SyscallResult::err(name, EINVAL);
    };
    let mut args_c: Vec<CString> = Vec::new();
    if argv.is_empty() {
        args_c.push(path_c.clone());
    } else {
        for a in argv {
            match CString::new(a.as_str()) {
                Ok(c) => args_c.push(c),
                Err(_) => return SyscallResult::err(name, EINVAL),
            }
        }
    }
    let env_c = inject_kh_env(envp, ExecEnvKind::HostNative);
    let mut argv_ptrs: Vec<*const libc::c_char> = args_c.iter().map(|c| c.as_ptr()).collect();
    argv_ptrs.push(core::ptr::null());
    let env_ptrs = env_ptrs(&env_c);
    match unsafe { host::posix_spawn_host(path_c.as_c_str(), &argv_ptrs, &env_ptrs) } {
        Ok(pid) => {
            if pid > 0 {
                crate::process::child_born();
            }
            SyscallResult::ok(name, u64::try_from(pid).unwrap_or(0))
        }
        Err(e) => SyscallResult::err(name, host_errno_to_darwin(e)),
    }
}

fn try_exec_script(host_path: &Path, argv: &[String], envp: &[String]) -> Option<i32> {
    let Ok(mut f) = std::fs::File::open(host_path) else {
        return Some(libc::ENOENT);
    };
    let mut head = [0_u8; 256];
    let n = f.read(&mut head).unwrap_or(0);
    let bytes = head.get(..n)?;
    if bytes.first().copied() != Some(b'#') || bytes.get(1).copied() != Some(b'!') {
        return None; // not a script
    }
    let line_end = bytes
        .iter()
        .position(|&b| b == b'\n')
        .unwrap_or(bytes.len());
    let line = bytes.get(2..line_end)?;
    let line = std::str::from_utf8(line).ok()?.trim();
    if line.is_empty() {
        return Some(libc::ENOEXEC);
    }
    // Optional: "#!/usr/bin/env bash" → interpreter env, arg bash
    let mut parts = line.split_whitespace();
    let interp = parts.next()?;
    let interp_arg = parts.next();

    let host_interp = map_interpreter(interp);
    let Ok(interp_c) = CString::new(host_interp.as_os_str().as_bytes()) else {
        return Some(libc::EINVAL);
    };
    let Ok(script_c) = CString::new(host_path.as_os_str().as_bytes()) else {
        return Some(libc::EINVAL);
    };

    let mut args_c: Vec<CString> = vec![interp_c];
    if let Some(a) = interp_arg
        && let Ok(c) = CString::new(a)
    {
        args_c.push(c);
    }
    args_c.push(script_c);
    for a in argv.iter().skip(1) {
        if let Ok(c) = CString::new(a.as_str()) {
            args_c.push(c);
        }
    }
    let mut argv_ptrs: Vec<*const libc::c_char> = args_c.iter().map(|c| c.as_ptr()).collect();
    argv_ptrs.push(core::ptr::null());
    // Host shell + host script path (or nested Mach-O handled below).
    let env_c = inject_kh_env(envp, ExecEnvKind::HostNative);
    let env_ptrs = env_ptrs(&env_c);

    // If interpreter is itself Mach-O in the bottle, re-exec via kh.
    if is_macho(&host_interp) {
        let mut nested_argv = vec![host_interp.display().to_string()];
        if let Some(a) = interp_arg {
            nested_argv.push(a.to_owned());
        }
        nested_argv.push(host_path.display().to_string());
        for a in argv.iter().skip(1) {
            nested_argv.push(a.clone());
        }
        return Some(reexec_kh_macho(&host_interp, &nested_argv, envp));
    }

    let path0 = args_c.first()?;
    Some(unsafe { host::execve_host(path0.as_c_str(), &argv_ptrs, &env_ptrs) })
}

/// Resolve a shebang interpreter to a host path.
///
/// Prefer the bottle file when it exists so `#!/bin/sh` stays Darwin `sh`
/// under `kh`. Fall back to the guest path as a host path (no bottle, or
/// the prefix was not copied).
fn map_interpreter(guest: &str) -> PathBuf {
    if let Ok(translated) = bottle::translate_path(guest)
        && translated.is_file()
    {
        return translated;
    }
    PathBuf::from(guest)
}

fn reexec_direct(host_path: &Path, argv: &[String], envp: &[String]) -> i32 {
    let Ok(path_c) = CString::new(host_path.as_os_str().as_bytes()) else {
        return libc::EINVAL;
    };
    let mut args_c: Vec<CString> = Vec::new();
    if argv.is_empty() {
        args_c.push(path_c.clone());
    } else {
        for a in argv {
            match CString::new(a.as_str()) {
                Ok(c) => args_c.push(c),
                Err(_) => return libc::EINVAL,
            }
        }
    }
    let mut argv_ptrs: Vec<*const libc::c_char> = args_c.iter().map(|c| c.as_ptr()).collect();
    argv_ptrs.push(core::ptr::null());
    // Host OpenSSH / other native ELFs: real host HOME for keys and config.
    let env_c = inject_kh_env(envp, ExecEnvKind::HostNative);
    let env_ptrs = env_ptrs(&env_c);
    unsafe { host::execve_host(path_c.as_c_str(), &argv_ptrs, &env_ptrs) }
}

/// `setsid` — host new session (git maintenance detaches).
pub(crate) fn handle_setsid() -> SyscallResult {
    let name = "setsid";
    // SAFETY: well-defined; may fail if already session leader.
    let rc = unsafe { libc::setsid() };
    if rc < 0 {
        SyscallResult::err(
            name,
            host_errno_to_darwin(std::io::Error::last_os_error().raw_os_error().unwrap_or(1)),
        )
    } else {
        SyscallResult::ok(name, u64::try_from(rc).unwrap_or(0))
    }
}

/// `setpgid`.
pub(crate) fn handle_setpgid(args: SyscallArgs) -> SyscallResult {
    let name = "setpgid";
    let pid = reg_as_i32(args.x0);
    let pgid = reg_as_i32(args.x1);
    // SAFETY: host setpgid.
    let rc = unsafe { libc::setpgid(pid, pgid) };
    if rc < 0 {
        SyscallResult::err(
            name,
            host_errno_to_darwin(std::io::Error::last_os_error().raw_os_error().unwrap_or(1)),
        )
    } else {
        SyscallResult::ok(name, 0)
    }
}

/// `getpgrp`.
pub(crate) fn handle_getpgrp() -> SyscallResult {
    let name = "getpgrp";
    // SAFETY: host getpgrp.
    let rc = unsafe { libc::getpgrp() };
    if rc < 0 {
        SyscallResult::err(
            name,
            host_errno_to_darwin(std::io::Error::last_os_error().raw_os_error().unwrap_or(1)),
        )
    } else {
        SyscallResult::ok(name, u64::try_from(rc).unwrap_or(0))
    }
}

/// `kill` — pid `x0`, sig `x1`.
pub(crate) fn handle_kill(args: SyscallArgs) -> SyscallResult {
    let name = "kill";
    let pid = reg_as_i32(args.x0);
    let sig = reg_as_i32(args.x1);
    // SAFETY: host kill; guest signals are best-effort.
    let rc = unsafe { libc::kill(pid, sig) };
    if rc < 0 {
        SyscallResult::err(
            name,
            host_errno_to_darwin(std::io::Error::last_os_error().raw_os_error().unwrap_or(1)),
        )
    } else {
        SyscallResult::ok(name, 0)
    }
}

/// `getuid` — host real user id (must match file owners for git safe.directory).
#[allow(unsafe_code)]
pub(crate) fn handle_getuid() -> SyscallResult {
    // SAFETY: host getuid has no preconditions.
    let uid = unsafe { libc::getuid() };
    SyscallResult::ok("getuid", u64::from(uid))
}

/// `geteuid`.
#[allow(unsafe_code)]
pub(crate) fn handle_geteuid() -> SyscallResult {
    let uid = unsafe { libc::geteuid() };
    SyscallResult::ok("geteuid", u64::from(uid))
}

/// `getgid`.
#[allow(unsafe_code)]
pub(crate) fn handle_getgid() -> SyscallResult {
    let gid = unsafe { libc::getgid() };
    SyscallResult::ok("getgid", u64::from(gid))
}

/// `getegid`.
#[allow(unsafe_code)]
pub(crate) fn handle_getegid() -> SyscallResult {
    let gid = unsafe { libc::getegid() };
    SyscallResult::ok("getegid", u64::from(gid))
}

pub(crate) fn handle_getpid() -> SyscallResult {
    SyscallResult::ok("getpid", u64::from(std::process::id()))
}

/// `getppid` — parent of the host process (same identity as guest under kh).
#[allow(unsafe_code)] // thin libc wrapper; no safer std equivalent
pub(crate) fn handle_getppid() -> SyscallResult {
    // SAFETY: `getppid` is always defined and has no preconditions.
    let ppid = unsafe { libc::getppid() };
    SyscallResult::ok("getppid", u64::try_from(ppid).unwrap_or(1))
}

/// `issetugid` — always 0 (not setuid in the translator).
pub(crate) fn handle_issetugid() -> SyscallResult {
    SyscallResult::ok("issetugid", 0)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod bridge_env_tests {
    use super::{guest_bridge_value_to_host, rewrite_guest_bridge_env};

    #[test]
    fn rewrites_home_under_volumes_linux() {
        assert_eq!(
            rewrite_guest_bridge_env("HOME=/Volumes/linux/root"),
            "HOME=/root"
        );
        assert_eq!(
            rewrite_guest_bridge_env("HOME=/Volumes/linux/Users/me"),
            "HOME=/Users/me"
        );
        assert_eq!(
            guest_bridge_value_to_host("/Volumes/linux"),
            Some("/".into())
        );
    }

    #[test]
    fn map_interpreter_prefers_bottle_file() {
        use super::map_interpreter;
        let _g = crate::process::test_lock();
        let tmp = std::env::temp_dir().join(format!(
            "kh-interp-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        drop(std::fs::remove_dir_all(&tmp));
        std::fs::create_dir_all(tmp.join("bin")).expect("mkdir");
        let sh = tmp.join("bin/sh");
        std::fs::write(&sh, b"not-a-real-sh").expect("write sh");
        crate::bottle::set_bottle_root(Some(tmp.clone()));
        assert_eq!(map_interpreter("/bin/sh"), sh);
        crate::bottle::set_bottle_root(None);
        drop(std::fs::remove_dir_all(&tmp));
    }

    #[test]
    fn map_interpreter_falls_back_to_guest_path() {
        use super::map_interpreter;
        let _g = crate::process::test_lock();
        crate::bottle::set_bottle_root(None);
        assert_eq!(
            map_interpreter("/bin/sh"),
            std::path::PathBuf::from("/bin/sh")
        );
    }

    #[test]
    fn leaves_guest_only_and_host_paths() {
        assert_eq!(
            rewrite_guest_bridge_env("PATH=/usr/bin:/bin"),
            "PATH=/usr/bin:/bin"
        );
        assert_eq!(rewrite_guest_bridge_env("HOME=/var/root"), "HOME=/var/root");
        // Embedded bridge substring must not be rewritten.
        assert_eq!(
            rewrite_guest_bridge_env("NOTE=see /Volumes/linux/tmp later"),
            "NOTE=see /Volumes/linux/tmp later"
        );
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod otool_disasm_flag_tests {
    use super::{otool_args_want_llvm_disasm, otool_classic_wants_llvm_disasm};
    use std::path::Path;

    #[test]
    fn detects_text_plus_verbose() {
        assert!(otool_args_want_llvm_disasm(&[
            "otool-classic".into(),
            "-t".into(),
            "-v".into(),
            "a".into()
        ]));
        assert!(otool_args_want_llvm_disasm(&["-tv".into(), "a".into()]));
        assert!(otool_args_want_llvm_disasm(&["-x".into(), "-V".into()]));
        assert!(!otool_args_want_llvm_disasm(&["-t".into(), "a".into()]));
        assert!(!otool_args_want_llvm_disasm(&["-h".into(), "a".into()]));
    }

    #[test]
    fn only_classic_binary() {
        let argv = ["-t".into(), "-v".into()];
        assert!(otool_classic_wants_llvm_disasm(
            Path::new("/usr/bin/otool-classic"),
            &argv
        ));
        assert!(!otool_classic_wants_llvm_disasm(
            Path::new("/usr/bin/otool"),
            &argv
        ));
    }
}
