//! `kh install` — install optional guest tools into the bottle at macOS paths.

use std::io::{self, Write};

use anyhow::{Context, Result, bail};
use kh_runtime::bottle;

/// Arguments for `kh install <package>`.
pub(crate) struct InstallArgs<'a> {
    /// Package name (`7zip`, `7zz`, …).
    pub package: &'a str,
    pub json: bool,
}

/// Install a package into the active bottle (creating it if needed).
pub(crate) fn run(args: &InstallArgs<'_>) -> Result<()> {
    if args.package.eq_ignore_ascii_case("list") || args.package == "--list" {
        return list_packages(args.json);
    }

    let report = bottle::install_package(args.package)
        .with_context(|| format!("install `{}` failed", args.package))?;

    if args.json {
        println!(
            "{}",
            serde_json::json!({
                "package": report.package,
                "guest_path": report.guest_path,
                "host_path": report.host_path.display().to_string(),
                "bottle": report.bottle.display().to_string(),
            })
        );
        return Ok(());
    }

    let mut out = io::stdout().lock();
    writeln!(out, "installed {}", report.package)?;
    writeln!(out, "  guest:  {}", report.guest_path)?;
    writeln!(out, "  host:   {}", report.host_path.display())?;
    writeln!(out, "  bottle: {}", report.bottle.display())?;
    writeln!(out)?;
    writeln!(out, "Run under kh (PATH search works for bare names):")?;
    writeln!(out, "  kh run {} -- …", report.guest_path)?;
    writeln!(out, "  kh run 7zz -- a /tmp/out.7z ./file")?;
    Ok(())
}

fn list_packages(json: bool) -> Result<()> {
    let items = [(
        "7zip",
        "/usr/local/bin/7zz",
        "Darwin 7-Zip console (official macOS build)",
    )];
    if json {
        let arr: Vec<_> = items
            .iter()
            .map(|(name, path, desc)| {
                serde_json::json!({ "name": name, "guest_path": path, "description": desc })
            })
            .collect();
        println!("{}", serde_json::json!({ "packages": arr }));
        return Ok(());
    }
    let mut out = io::stdout().lock();
    writeln!(
        out,
        "Installable packages (into the bottle at macOS paths):"
    )?;
    for (name, path, desc) in items {
        writeln!(out, "  {name:8} → {path}")?;
        writeln!(out, "           {desc}")?;
    }
    writeln!(out)?;
    writeln!(out, "  kh install 7zip")?;
    Ok(())
}

/// Fail fast when package string is empty.
pub(crate) fn require_package(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("package name required (try: kh install list)");
    }
    Ok(())
}
