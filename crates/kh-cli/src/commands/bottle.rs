//! `kh bottle` — create / destroy / inspect the single bottle.

use std::io::{self, Write};
use std::path::Path;

use anyhow::{Result, bail};
use kh_runtime::bottle::{self, BottleError, BottleStatus};
use serde_json::json;

/// Subcommands for bottle management.
pub(crate) enum BottleCmd<'a> {
    /// Materialize the macOS-like skeleton (optional custom path).
    Create { path: Option<&'a Path> },
    /// Remove the registered bottle after confirmation.
    Destroy { yes: bool },
    /// Print the registered path (empty / exit 1 when none).
    Path,
    /// Human or JSON status of the registered bottle.
    Status,
}

/// Runs a bottle subcommand.
pub(crate) fn run(cmd: &BottleCmd<'_>, json: bool) -> Result<()> {
    match cmd {
        BottleCmd::Create { path } => create(*path, json),
        BottleCmd::Destroy { yes } => destroy(*yes, json),
        BottleCmd::Path => print_path(json),
        BottleCmd::Status => print_status(json),
    }
}

fn create(path: Option<&Path>, json: bool) -> Result<()> {
    match bottle::create(path) {
        Ok(created) => {
            if json {
                println!(
                    "{}",
                    json!({
                        "action": "create",
                        "path": created.display().to_string(),
                    })
                );
            } else {
                println!("bottle created at {}", created.display());
                println!(
                    "  host Linux bridge: {}/{}",
                    created.display(),
                    bottle::VOLUMES_LINUX
                );
            }
            Ok(())
        }
        Err(BottleError::AlreadyExists { path }) => {
            if json {
                bail!(
                    "{}",
                    json!({
                        "error": "already_exists",
                        "path": path.display().to_string(),
                        "hint": "kh bottle destroy",
                    })
                );
            }
            bail!(
                "a bottle already exists at {}\n\
                 if you want a new one, delete the current bottle first:\n\
                   kh bottle destroy",
                path.display()
            );
        }
        Err(err) => Err(err.into()),
    }
}

fn destroy(yes: bool, json: bool) -> Result<()> {
    let status = bottle::status()?;
    let Some(st) = status else {
        bail!("{}", BottleError::NotRegistered);
    };

    if !yes {
        eprint!("Delete bottle at {}? [y/N] ", st.path.display());
        io::stderr().flush()?;
        let mut line = String::new();
        io::stdin().read_line(&mut line)?;
        let answer = line.trim();
        if !answer.eq_ignore_ascii_case("y") && !answer.eq_ignore_ascii_case("yes") {
            if json {
                println!("{}", json!({ "action": "destroy", "cancelled": true }));
                return Ok(());
            }
            println!("cancelled");
            return Ok(());
        }
    }

    match bottle::destroy(true) {
        Ok(path) => {
            if json {
                println!(
                    "{}",
                    json!({
                        "action": "destroy",
                        "path": path.display().to_string(),
                    })
                );
            } else {
                println!("bottle destroyed: {}", path.display());
            }
            Ok(())
        }
        Err(err) => Err(err.into()),
    }
}

fn print_path(json: bool) -> Result<()> {
    if let Some(st) = bottle::status()? {
        if json {
            println!(
                "{}",
                json!({
                    "path": st.path.display().to_string(),
                    "exists": st.exists,
                    "valid_marker": st.valid_marker,
                })
            );
        } else {
            println!("{}", st.path.display());
        }
        return Ok(());
    }
    if json {
        println!("{}", json!({ "path": null }));
        return Ok(());
    }
    bail!("no bottle is registered");
}

fn print_status(json: bool) -> Result<()> {
    if let Some(st) = bottle::status()? {
        if json {
            println!("{}", status_json(&st));
        } else {
            println!("path:   {}", st.path.display());
            println!("exists: {}", st.exists);
            println!("marker: {}", st.valid_marker);
            if st.exists && st.valid_marker {
                let bridge = st.path.join(bottle::VOLUMES_LINUX);
                println!("linux:  {} -> /", bridge.display());
            }
        }
        return Ok(());
    }
    if json {
        println!("{}", json!({ "registered": false }));
        return Ok(());
    }
    println!("no bottle registered");
    Ok(())
}

fn status_json(st: &BottleStatus) -> serde_json::Value {
    json!({
        "registered": true,
        "path": st.path.display().to_string(),
        "exists": st.exists,
        "valid_marker": st.valid_marker,
    })
}
