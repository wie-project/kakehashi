//! Runtime execution commands.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use kh_loader::{LoadSession, RunOptions, run_micro};
use kh_runtime::GuestPageSize;
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

    if args.dry_load {
        return dry_load(args, guest, root);
    }

    kh_runtime::clear_trace_on_exit();
    kh_runtime::set_expect_code(args.expect_code);

    let opts = RunOptions {
        root,
        guest_page_size: guest,
        guest_args: args.guest_args.to_vec(),
        max_events: args.max_syscalls,
        max_syscalls: args.max_syscalls,
        dry_load: false,
    };

    match run_micro(args.path, &opts) {
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

fn dry_load(args: &RunArgs<'_>, guest: GuestPageSize, root: Option<PathBuf>) -> Result<()> {
    let mut session = LoadSession::open_with_guest(args.path, root, guest)?;
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
