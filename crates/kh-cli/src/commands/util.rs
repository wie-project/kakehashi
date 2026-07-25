//! Shared CLI output helpers.

use std::io::{ErrorKind, Write};

use anyhow::{Context, Result};

/// Writes one line to `output`.
///
/// Returns `Ok(false)` on a broken pipe so callers can exit cleanly when
/// stdout is closed by a pager (`head`, `less`, …).
pub(crate) fn write_line(output: &mut impl Write, line: &str) -> Result<bool> {
    match writeln!(output, "{line}") {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == ErrorKind::BrokenPipe => Ok(false),
        Err(error) => Err(error).context("failed to write stdout"),
    }
}

/// Formats Darwin `VM_PROT_*` bits as `rwx` / `r-x` style.
#[must_use]
pub(crate) fn format_prot(bits: u32) -> String {
    let mut s = String::with_capacity(3);
    s.push(if bits & 1 != 0 { 'r' } else { '-' });
    s.push(if bits & 2 != 0 { 'w' } else { '-' });
    s.push(if bits & 4 != 0 { 'x' } else { '-' });
    s
}

/// Formats an optional address for human output (`"-"` when absent).
#[must_use]
pub(crate) fn format_optional_hex(value: Option<u64>) -> String {
    value.map_or_else(|| "-".to_owned(), |v| format!("{v:#018x}"))
}

/// Shared resolution of bottle root from CLI / env / active bottle registry.
///
/// Order: `--root` → `KAKEHASHI_ROOT` → registered bottle → **auto
/// `kh bottle ensure`** when none is registered (so first `kh run` can use
/// bottle paths when libSystem is discoverable).
#[must_use]
pub(crate) fn resolve_root(cli_root: Option<&std::path::Path>) -> Option<std::path::PathBuf> {
    if let Some(p) = cli_root {
        return Some(p.to_path_buf());
    }
    if let Some(p) = std::env::var_os("KAKEHASHI_ROOT") {
        return Some(std::path::PathBuf::from(p));
    }
    if let Ok(Some(p)) = kh_runtime::active_root() {
        return Some(p);
    }
    // First-run convenience: create managed bottle (embedded freestanding
    // libSystem is enough; no separate dylib on disk required).
    match kh_runtime::ensure_bottle(&kh_runtime::CreateOptions {
        path: None,
        libsystem: None,
        skip_libsystem: false,
    }) {
        Ok(created) => Some(created.path),
        Err(_) => None,
    }
}

/// Human-friendly error when live execution is unavailable off Linux aarch64.
pub(crate) fn map_live_exec_error(err: impl std::fmt::Display + std::fmt::Debug) -> anyhow::Error {
    let msg = format!("{err:#}");
    if msg.contains("Linux aarch64") || msg.contains("trap backend") {
        anyhow::anyhow!(
            "{msg}; live `kh run`/`kh trace` requires Linux aarch64 (use Docker/Colima). \
             `kh run --dry-load` works on any host."
        )
    } else {
        anyhow::anyhow!("{msg}")
    }
}
