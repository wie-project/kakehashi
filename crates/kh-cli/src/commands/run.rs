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
use kh_runtime::bottle::{guest_path_to_host, resolve_guest_program};
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
}

/// Runs the run command.
pub(crate) fn run(args: &RunArgs<'_>) -> Result<()> {
    let guest = match args.guest_page_size {
        Some(bytes) => GuestPageSize::try_explicit(bytes).ok_or_else(|| {
            anyhow::anyhow!("invalid --guest-page-size {bytes} (expected 4096 or 16384)")
        })?,
        None => GuestPageSize::default(),
    };

    let root = resolve_root(args.root);

    // Bare names (`7zz`) resolve under the bottle at macOS paths
    // (`/usr/local/bin/7zz`). Absolute guest paths stay as-is for translation.
    let program = resolve_guest_program(args.path, root.as_deref());
    let host_open = resolve_host_open_path(&program, root.as_deref());

    if args.dry_load {
        return dry_load(args, guest, root, &host_open);
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

    // Bottle host bridges (`/bin/rm`, `/bin/sh`, …) are native Linux ELF, not
    // Mach-O. Nested guest `execve` already re-execs them on the host; top-level
    // `kh run rm` should do the same instead of failing with "Invalid magic".
    if !is_macho_file(&host_open) {
        return run_host_native(&host_open, &program, args);
    }

    kh_runtime::clear_trace_on_exit();
    kh_runtime::set_expect_code(args.expect_code);

    let opts = RunOptions {
        root,
        guest_page_size: guest,
        guest_args: args.guest_args.to_vec(),
        // Plain `kh run` must not record trap events — max_syscalls is 50M+ and
        // each event is a String + Mutex push (catastrophic on archive I/O).
        // Use `kh trace` when you need a ring buffer of traps.
        max_events: 0,
        max_syscalls: args.max_syscalls,
        dry_load: false,
    };

    match run_micro(&host_open, &opts) {
        Ok(result) => {
            if let Some(code) = result.exit_code {
                if code != args.expect_code {
                    anyhow::bail!("guest exit code {code} != expected {}", args.expect_code);
                }
                std::process::exit(code);
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
fn run_host_native(host_open: &Path, program: &Path, args: &RunArgs<'_>) -> Result<()> {
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

    if code != args.expect_code {
        anyhow::bail!(
            "host exit code {code} != expected {} ({})",
            args.expect_code,
            program.display()
        );
    }
    std::process::exit(code);
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
