//! Runtime execution commands.

use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

#[cfg(unix)]
use std::os::unix::process::{CommandExt, ExitStatusExt};

use anyhow::{Context, Result};
use kh_loader::{LoadSession, RunOptions, run_micro};
use kh_runtime::GuestPageSize;
use kh_runtime::bottle::{
    bottle_has_macos_prefix, guest_path_to_host, macos_prefix_hint, resolve_guest_program,
};
use serde_json::json;

use super::util::{
    format_optional_hex, format_prot, map_live_exec_error, resolve_root, write_line,
};

/// Arguments for `kh run`.
pub(crate) struct RunArgs<'a> {
    pub path: &'a Path,
    pub root: Option<&'a Path>,
    pub max_syscalls: usize,
    pub expect_code: i32,
    pub guest_page_size: Option<u32>,
    pub dry_load: bool,
    pub guest_args: &'a [String],
    pub json: bool,
    /// When true, any guest/host exit code is propagated (PATH wrappers).
    pub passthrough_exit: bool,
}

/// Runs the run command.
pub(crate) fn run(args: &RunArgs<'_>) -> Result<()> {
    finish_exit(args, execute(args)?)
}

/// Propagate `code` or enforce `--expect-code`.
fn finish_exit(args: &RunArgs<'_>, code: i32) -> Result<()> {
    if !args.passthrough_exit && code != args.expect_code {
        anyhow::bail!("guest exit code {code} != expected {}", args.expect_code);
    }
    std::process::exit(code);
}

/// Load and run the guest; returns its exit code (does not `_exit`).
pub(crate) fn execute(args: &RunArgs<'_>) -> Result<i32> {
    let guest = match args.guest_page_size {
        Some(bytes) => GuestPageSize::try_explicit(bytes).ok_or_else(|| {
            anyhow::anyhow!("invalid --guest-page-size {bytes} (expected 4096 or 16384)")
        })?,
        None => GuestPageSize::default(),
    };

    let root = resolve_root(args.root);

    // Live execution needs the user-copied macOS prefix (bin / sbin / usr/bin).
    // Dry-load only maps the Mach-O and can run on any host without that tree.
    if !args.dry_load
        && let Some(bottle) = root.as_deref()
        && !bottle_has_macos_prefix(bottle)
    {
        anyhow::bail!("{}", macos_prefix_hint(bottle));
    }

    // Bare names (`7zz`) resolve under the bottle at macOS paths
    // (`/usr/local/bin/7zz`). Absolute guest paths stay as-is for translation.
    let program = resolve_guest_program(args.path, root.as_deref());
    let host_open = resolve_host_open_path(&program, root.as_deref());

    // Nested `kh run /…/cc -- -Wl,--as-needed …` (Linux rustc / rustc driver
    // re-exec) must not enter Darwin clang: guest open() cannot see `/home/…`.
    if !args.dry_load && looks_like_host_gnu_cc(args.guest_args) {
        let base = program.file_name().and_then(|s| s.to_str()).unwrap_or("cc");
        if looks_like_cc_name(base) {
            return spawn_host_cc(base, args.guest_args);
        }
    }

    if args.dry_load {
        dry_load(args, guest, root, &host_open)?;
        return Ok(0);
    }

    if !host_open.is_file() {
        anyhow::bail!(
            "guest program not found: {} (host {}){}",
            program.display(),
            host_open.display(),
            if root.is_some() {
                " — install tools into the bottle (`kh install 7zip`) or pass a host path"
            } else {
                " — create a bottle (`kh bottle ensure`) or pass an absolute host path"
            }
        );
    }

    // Residual host-ELF paths in the bottle (e.g. the OpenSSH bridge) are not
    // Mach-O. Nested guest `execve` already re-execs them on the host; top-level
    // `kh run` should do the same instead of failing with "Invalid magic".
    if !is_macho_file(&host_open) {
        if let Some(script) = parse_shebang(&host_open) {
            return run_shebang(&script, &program, &host_open, args, root.as_deref());
        }
        return run_host_native(&host_open, &program, args);
    }

    kh_runtime::clear_trace_on_exit();
    kh_runtime::set_expect_code(args.expect_code);

    let guest_args = guest_args_for(&program, args.guest_args);
    let opts = RunOptions {
        root,
        guest_page_size: guest,
        guest_args,
        // Plain `kh run` must not record trap events — max_syscalls is 50M+ and
        // each event is a String + Mutex push (catastrophic on archive I/O).
        max_events: 0,
        max_syscalls: args.max_syscalls,
        dry_load: false,
    };

    match run_micro(&host_open, &opts) {
        Ok(result) => {
            if let Some(code) = result.exit_code {
                return Ok(code);
            }
            anyhow::bail!(
                "guest returned without exit (entry={:#x}, sp={:#x}, patched_svc={})",
                result.entry,
                result.sp,
                result.patched_svc
            );
        }
        Err(err) => Err(map_live_exec_error(err)).context("micro run failed"),
    }
}

/// Shebang line: interpreter + optional one argument (`#!/usr/bin/env bash`).
struct Shebang {
    interp: String,
    interp_arg: Option<String>,
}

/// Read `#! interpreter [arg]` from the start of `path`.
fn parse_shebang(path: &Path) -> Option<Shebang> {
    let mut f = File::open(path).ok()?;
    let mut head = [0_u8; 256];
    let n = f.read(&mut head).ok()?;
    let bytes = head.get(..n)?;
    if bytes.first().copied() != Some(b'#') || bytes.get(1).copied() != Some(b'!') {
        return None;
    }
    let line_end = bytes
        .iter()
        .position(|&b| b == b'\n')
        .unwrap_or(bytes.len());
    let line = bytes.get(2..line_end)?;
    let line = core::str::from_utf8(line).ok()?.trim();
    if line.is_empty() {
        return None;
    }
    let mut parts = line.split_whitespace();
    let interp = parts.next()?.to_owned();
    let interp_arg = parts.next().map(str::to_owned);
    Some(Shebang { interp, interp_arg })
}

/// Guest-visible path for a host script so Darwin `open` hits `/Volumes/linux…`.
fn guest_script_path(host_open: &Path, program: &Path, bottle: Option<&Path>) -> String {
    let p = program.to_string_lossy();
    if p.starts_with("/Volumes/linux") {
        return p.into_owned();
    }
    if p.starts_with('/')
        && let Some(root) = bottle
    {
        let under = guest_path_to_host(root, program);
        if under.is_file() {
            return p.into_owned();
        }
    }
    let abs = std::fs::canonicalize(host_open).unwrap_or_else(|_| host_open.to_path_buf());
    let s = abs.to_string_lossy();
    if s.starts_with('/') {
        format!("/Volumes/linux{s}")
    } else {
        s.into_owned()
    }
}

/// Top-level `kh run ./configure`: honour `#!` like nested `execve`.
///
/// A script is not Mach-O; the previous path exec'd it on the host, so Wine
/// `./configure` saw `aarch64-unknown-linux-gnu` and the host `gcc`.
fn run_shebang(
    script: &Shebang,
    program: &Path,
    host_open: &Path,
    args: &RunArgs<'_>,
    bottle: Option<&Path>,
) -> Result<i32> {
    let interp_host = if let Some(root) = bottle {
        let under = guest_path_to_host(root, Path::new(&script.interp));
        if under.is_file() {
            under
        } else {
            PathBuf::from(&script.interp)
        }
    } else {
        PathBuf::from(&script.interp)
    };

    if !is_macho_file(&interp_host) {
        return run_host_native(host_open, program, args);
    }

    let script_guest = guest_script_path(host_open, program, bottle);
    let mut nested = Vec::with_capacity(args.guest_args.len().saturating_add(3));
    if let Some(a) = script.interp_arg.as_deref() {
        nested.push(a.to_owned());
    }
    nested.push(script_guest);
    nested.extend(args.guest_args.iter().cloned());

    execute(&RunArgs {
        path: Path::new(&script.interp),
        root: args.root,
        max_syscalls: args.max_syscalls,
        expect_code: args.expect_code,
        guest_page_size: args.guest_page_size,
        dry_load: false,
        guest_args: &nested,
        json: args.json,
        passthrough_exit: args.passthrough_exit,
    })
}

/// Thin/fat Mach-O magic (same set as nested `execve` classification).
fn is_macho_file(path: &Path) -> bool {
    let Ok(mut f) = File::open(path) else {
        return false;
    };
    let mut magic = [0_u8; 4];
    if f.read_exact(&mut magic).is_err() {
        return false;
    }
    matches!(
        magic,
        [0xfe, 0xed, 0xfa, 0xcf | 0xce]
            | [0xcf | 0xce, 0xfa, 0xed, 0xfe]
            | [0xca, 0xfe, 0xba, 0xbe]
            | [0xbe, 0xba, 0xfe, 0xca]
    )
}

/// Run a bottle host-bridge (ELF / script) without the Mach-O translator.
///
/// Mirrors nested `reexec_direct`: the process is native Linux. Exit code is
/// checked against `--expect-code` like a guest run.
fn run_host_native(host_open: &Path, program: &Path, args: &RunArgs<'_>) -> Result<i32> {
    // Prefer the real host path after symlink resolution so argv0 is a path
    // the kernel can exec (bottle `bin/rm` → `…/Volumes/linux/bin/rm` → `/bin/rm`).
    let exec_path = std::fs::canonicalize(host_open).unwrap_or_else(|_| host_open.to_path_buf());

    let mut cmd = Command::new(&exec_path);
    cmd.args(args.guest_args);
    // argv0: guest-facing name when available (e.g. `rm`), else basename.
    let argv0 = program
        .file_name()
        .and_then(|s| s.to_str())
        .or_else(|| exec_path.file_name().and_then(|s| s.to_str()))
        .unwrap_or("kh-host");
    #[cfg(unix)]
    {
        cmd.arg0(argv0);
    }

    let status = cmd
        .status()
        .with_context(|| format!("failed to exec host binary {}", exec_path.display()))?;

    let code = status.code().unwrap_or_else(|| {
        // Signal death on Unix: map to 128+sig like shells (best-effort).
        #[cfg(unix)]
        {
            status.signal().map_or(1, |s| 128_i32.saturating_add(s))
        }
        #[cfg(not(unix))]
        {
            1
        }
    });

    if !args.passthrough_exit && code != args.expect_code {
        anyhow::bail!(
            "host exit code {code} != expected {} ({})",
            args.expect_code,
            program.display()
        );
    }
    Ok(code)
}

/// `argv0` was a host-bin symlink (`sh`, `curl`, …): run that bottle program.
pub(crate) fn run_wrapper(name: &str) -> Result<()> {
    let guest_args: Vec<String> = std::env::args().skip(1).collect();
    // Linux rustc/cargo put `cc` on PATH. host-bin `cc` is Darwin clang; GNU
    // link lines (`-Wl,--as-needed`, linux-gnu rustlib) must use the host cc
    // or the objects/rlibs at `/home/…` are invisible to the guest.
    if looks_like_cc_name(name) && looks_like_host_gnu_cc(&guest_args) {
        std::process::exit(spawn_host_cc(name, &guest_args)?);
    }
    // `cargo` / `rustc` wrappers exist so a bottle rustup stays first. When the
    // Darwin tool is not installed, fall through to the next PATH entry so
    // `cargo install` of kakehashi itself still uses Linux rustc.
    if !bottle_has_named_tool(name) {
        std::process::exit(spawn_host_tool(name, &guest_args)?);
    }
    run(&RunArgs {
        path: Path::new(name),
        root: None,
        max_syscalls: 50_000_000,
        expect_code: 0,
        guest_page_size: None,
        dry_load: false,
        guest_args: &guest_args,
        json: false,
        passthrough_exit: true,
    })
}

/// True when `cc`/`clang` is being used as a GNU/Linux driver (not Apple).
pub(crate) fn looks_like_host_gnu_cc(args: &[String]) -> bool {
    args.iter().any(|a| {
        a.contains("unknown-linux-gnu")
            || a.contains("linux-gnu")
            || a.starts_with("-Wl,--")
            || a.starts_with("-Wl,-B")
            || a.starts_with("-Wl,-z")
            || Path::new(a)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("rlib"))
            || a.contains("/rustlib/")
    })
}

fn bottle_has_named_tool(name: &str) -> bool {
    let root = super::util::resolve_root(None);
    let program = resolve_guest_program(Path::new(name), root.as_deref());
    let host_open = resolve_host_open_path(&program, root.as_deref());
    host_open.is_file()
}

fn host_tool_path(name: &str) -> PathBuf {
    if name == "cc"
        && let Ok(p) = std::env::var("KH_HOST_CC")
        && !p.is_empty()
    {
        return PathBuf::from(p);
    }
    let skip = super::env::host_bin_dir().ok();
    if let Ok(path) = std::env::var("PATH") {
        for dir in path.split(':') {
            if skip.as_ref().is_some_and(|s| Path::new(dir) == s) {
                continue;
            }
            let cand = Path::new(dir).join(name);
            if cand.is_file() {
                return cand;
            }
        }
    }
    PathBuf::from(format!("/usr/bin/{name}"))
}

fn host_cc_path(name: &str) -> PathBuf {
    host_tool_path(name)
}

fn spawn_host_tool(name: &str, args: &[String]) -> Result<i32> {
    let path = host_tool_path(name);
    let status = Command::new(&path)
        .args(args)
        .status()
        .with_context(|| format!("failed to exec host {name} {}", path.display()))?;
    Ok(status.code().unwrap_or(1))
}

fn looks_like_cc_name(name: &str) -> bool {
    matches!(name, "cc" | "clang" | "clang++" | "gcc" | "c++" | "g++")
        || name.starts_with("clang-")
        || name.starts_with("gcc-")
}

fn spawn_host_cc(name: &str, args: &[String]) -> Result<i32> {
    let path = host_cc_path(name);
    let status = Command::new(&path)
        .args(args)
        .status()
        .with_context(|| format!("failed to exec host {name} {}", path.display()))?;
    Ok(status.code().unwrap_or(1))
}

/// Skip Linux `~/.bashrc` when the guest is bottle `sh`/`bash`.
///
/// Guest `HOME` is the host home (`/Volumes/linux…`). Apple bash 3.2 then
/// runs Ubuntu `~/.profile` / `~/.bashrc`; a non-interactive `return` from
/// that file exits 1 and never reaches `-c`.
fn guest_args_for(program: &Path, args: &[String]) -> Vec<String> {
    let Some(base) = program.file_name().and_then(|s| s.to_str()) else {
        return args.to_vec();
    };
    if !matches!(base, "sh" | "bash") {
        return args.to_vec();
    }
    if args.iter().any(|a| a == "--norc" || a == "--noprofile") {
        return args.to_vec();
    }
    let mut v = Vec::with_capacity(args.len().saturating_add(2));
    v.push("--norc".to_owned());
    v.push("--noprofile".to_owned());
    v.extend(args.iter().cloned());
    v
}

/// Host filesystem path used to open/map the Mach-O.
fn resolve_host_open_path(program: &Path, bottle: Option<&Path>) -> PathBuf {
    let Some(root) = bottle else {
        return program.to_path_buf();
    };
    let s = program.to_string_lossy();
    // Guest absolute path → under bottle. Host paths (dev fixtures) stay as-is.
    if s.starts_with('/') {
        let under = guest_path_to_host(root, program);
        if under.is_file() {
            return under;
        }
        // Fall back to treating the path as host absolute (e.g. /src/tests/…).
        if program.is_file() {
            return program.to_path_buf();
        }
        return under;
    }
    program.to_path_buf()
}

fn dry_load(
    args: &RunArgs<'_>,
    guest: GuestPageSize,
    root: Option<PathBuf>,
    host_open: &Path,
) -> Result<()> {
    let mut session = LoadSession::open_with_guest(host_open, root, guest)?;
    let report = session.dry_load()?;

    if args.json {
        let region_json = |r: &kh_loader::MappedRegionInfo| {
            json!({
                "name": r.name,
                "guest_addr": r.guest_addr,
                "host_addr": r.host_addr,
                "host_len": r.host_len,
                "vmsize": r.vmsize,
                "file_bytes": r.file_bytes,
                "prot": r.prot,
                "prot_str": format_prot(r.prot),
            })
        };
        let regions: Vec<_> = report.regions.iter().map(region_json).collect();
        let images: Vec<_> = report
            .images
            .iter()
            .map(|img| {
                json!({
                    "role": img.role,
                    "path": img.path.display().to_string(),
                    "install_name": img.install_name,
                    "status": img.status,
                    "slide": img.slide,
                    "preferred_base": img.preferred_base,
                    "regions": img.regions.iter().map(region_json).collect::<Vec<_>>(),
                })
            })
            .collect();
        let doc = json!({
            "path": report.path.display().to_string(),
            "slide": report.slide,
            "preferred_base": report.preferred_base,
            "guest_page_size": report.guest_page_size,
            "host_page_size": report.host_page_size,
            "entry": report.entry,
            "fully_guest_aligned": report.fully_guest_aligned,
            "regions": regions,
            "images": images,
        });
        println!("{doc}");
        return Ok(());
    }

    let mapped = report
        .images
        .iter()
        .filter(|i| i.status == "mapped")
        .count();
    let skipped = report.images.len().saturating_sub(mapped);

    let mut out = io::stdout().lock();
    if !write_line(&mut out, &format!("dry-load: {}", report.path.display()))? {
        return Ok(());
    }
    write_line(
        &mut out,
        &format!(
            "  host_page={} guest_page={} slide={:#x} preferred_base={:#x}",
            report.host_page_size, report.guest_page_size, report.slide, report.preferred_base
        ),
    )?;
    write_line(
        &mut out,
        &format!(
            "  entry={} fully_guest_aligned={}",
            format_optional_hex(report.entry),
            report.fully_guest_aligned
        ),
    )?;
    write_line(
        &mut out,
        &format!("  images: {mapped} mapped, {skipped} skipped"),
    )?;
    for img in &report.images {
        let role = match img.role {
            "main" => "main ",
            _ => "dylib",
        };
        write_line(
            &mut out,
            &format!(
                "    [{role}] {}  {}  install={} slide={:#x} base={:#x}",
                img.status,
                img.path.display(),
                img.install_name,
                img.slide,
                img.preferred_base
            ),
        )?;
        for r in &img.regions {
            write_line(
                &mut out,
                &format!(
                    "      {:<16} guest={:#018x} host={:#018x} len={:#x} vmsize={:#x} file={:#x} prot={}",
                    r.name,
                    r.guest_addr,
                    r.host_addr,
                    r.host_len,
                    r.vmsize,
                    r.file_bytes,
                    format_prot(r.prot)
                ),
            )?;
        }
    }
    drop(out.flush());
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::{
        guest_args_for, guest_script_path, looks_like_cc_name, looks_like_host_gnu_cc,
        parse_shebang,
    };
    use std::io::Write;
    use std::path::Path;

    #[test]
    fn sh_gets_norc_noprofile() {
        let args = guest_args_for(Path::new("/bin/sh"), &["-c".into(), "uname".into()]);
        assert_eq!(args, ["--norc", "--noprofile", "-c", "uname"]);
    }

    #[test]
    fn curl_args_are_untouched() {
        let args = guest_args_for(Path::new("curl"), &["-sSf".into(), "https://x".into()]);
        assert_eq!(args, ["-sSf", "https://x"]);
    }

    #[test]
    fn explicit_norc_is_kept() {
        let args = guest_args_for(
            Path::new("bash"),
            &["--norc".into(), "-c".into(), "x".into()],
        );
        assert_eq!(args, ["--norc", "-c", "x"]);
    }

    #[test]
    fn parse_shebang_sh_and_env() {
        let dir = std::env::temp_dir().join(format!(
            "kh-shebang-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let sh = dir.join("configure");
        std::fs::write(&sh, b"#!/bin/sh\necho hi\n").expect("write");
        let parsed = parse_shebang(&sh).expect("shebang");
        assert_eq!(parsed.interp, "/bin/sh");
        assert!(parsed.interp_arg.is_none());
        let envp = dir.join("envsh");
        std::fs::write(&envp, b"#!/usr/bin/env bash\n").expect("write env");
        let parsed = parse_shebang(&envp).expect("env shebang");
        assert_eq!(parsed.interp, "/usr/bin/env");
        assert_eq!(parsed.interp_arg.as_deref(), Some("bash"));
        let machoish = dir.join("bin");
        let mut f = std::fs::File::create(&machoish).expect("create");
        f.write_all(&[0xcf, 0xfa, 0xed, 0xfe]).expect("magic");
        assert!(parse_shebang(&machoish).is_none());
        drop(std::fs::remove_dir_all(&dir));
    }

    #[test]
    fn guest_script_path_bridges_host_abs() {
        let p = guest_script_path(Path::new("/tmp"), Path::new("./configure"), None);
        assert!(
            p.starts_with("/Volumes/linux/"),
            "expected linux bridge, got {p}"
        );
        assert_eq!(
            guest_script_path(
                Path::new("/tmp"),
                Path::new("/Volumes/linux/home/x/configure"),
                None
            ),
            "/Volumes/linux/home/x/configure"
        );
    }

    #[test]
    fn gnu_rustc_link_line_is_host_cc() {
        let args = [
            "/tmp/symbols.o".into(),
            "-Wl,--as-needed".into(),
            "-Wl,-Bstatic".into(),
            "/home/u/.rustup/toolchains/stable-aarch64-unknown-linux-gnu/lib/rustlib/aarch64-unknown-linux-gnu/lib/libstd.rlib".into(),
        ];
        assert!(looks_like_host_gnu_cc(&args));
        assert!(looks_like_cc_name("cc"));
        assert!(looks_like_cc_name("clang-16"));
    }

    #[test]
    fn apple_clang_flags_stay_guest() {
        let args = [
            "-arch".into(),
            "arm64".into(),
            "-isysroot".into(),
            "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk".into(),
            "-Wl,-syslibroot,/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk".into(),
        ];
        assert!(!looks_like_host_gnu_cc(&args));
    }
}
