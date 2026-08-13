//! `kh bottle` — create / destroy / inspect the single bottle.

use std::io::{self, Write};
use std::path::Path;

use anyhow::{Result, bail};
use kh_runtime::bottle::{self, BottleError, BottleStatus, CreateOptions, LibsystemOrigin};
use serde_json::json;

/// Subcommands for bottle management.
pub(crate) enum BottleCmd<'a> {
    /// Materialize the macOS-like skeleton (optional custom path / libSystem).
    Create {
        path: Option<&'a Path>,
        libsystem: Option<&'a Path>,
        skip_libsystem: bool,
    },
    /// Create if missing, otherwise refresh libSystem in the active bottle.
    Ensure {
        path: Option<&'a Path>,
        libsystem: Option<&'a Path>,
        skip_libsystem: bool,
    },
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
        BottleCmd::Create {
            path,
            libsystem,
            skip_libsystem,
        } => create(*path, *libsystem, *skip_libsystem, json),
        BottleCmd::Ensure {
            path,
            libsystem,
            skip_libsystem,
        } => ensure(*path, *libsystem, *skip_libsystem, json),
        BottleCmd::Destroy { yes } => destroy(*yes, json),
        BottleCmd::Path => print_path(json),
        BottleCmd::Status => print_status(json),
    }
}

fn create(
    path: Option<&Path>,
    libsystem: Option<&Path>,
    skip_libsystem: bool,
    json: bool,
) -> Result<()> {
    match bottle::create_with(&CreateOptions {
        path,
        libsystem,
        skip_libsystem,
    }) {
        Ok(created) => {
            print_create_result("create", &created, skip_libsystem, json);
            Ok(())
        }
        Err(BottleError::AlreadyExists { path }) => {
            if json {
                bail!(
                    "{}",
                    json!({
                        "error": "already_exists",
                        "path": path.display().to_string(),
                        "hint": "kh bottle destroy  |  kh bottle ensure",
                    })
                );
            }
            bail!(
                "a bottle already exists at {}\n\
                 to refresh libSystem in place:  kh bottle ensure\n\
                 to replace the bottle entirely: kh bottle destroy",
                path.display()
            );
        }
        Err(err) => Err(err.into()),
    }
}

fn ensure(
    path: Option<&Path>,
    libsystem: Option<&Path>,
    skip_libsystem: bool,
    json: bool,
) -> Result<()> {
    let created = bottle::ensure(&CreateOptions {
        path,
        libsystem,
        skip_libsystem,
    })?;
    print_create_result("ensure", &created, skip_libsystem, json);
    Ok(())
}

fn print_create_result(
    action: &str,
    created: &bottle::CreateResult,
    skip_libsystem: bool,
    json: bool,
) {
    if json {
        let libsystem = created.libsystem.as_ref().map(|ls| {
            json!({
                "source": ls.source.display().to_string(),
                "dest": ls.dest.display().to_string(),
                "origin": origin_str(ls.origin),
                "id_rewritten": ls.id_rewritten,
            })
        });
        println!(
            "{}",
            json!({
                "action": action,
                "path": created.path.display().to_string(),
                "libsystem": libsystem,
                "prefix_macos": bottle::bottle_has_macos_prefix(&created.path),
            })
        );
        return;
    }
    let verb = if action == "ensure" {
        "bottle ready at"
    } else {
        "bottle created at"
    };
    println!("{verb} {}", created.path.display());
    println!(
        "  host Linux bridge: {}/{}",
        created.path.display(),
        bottle::VOLUMES_LINUX
    );
    if let Some(ls) = &created.libsystem {
        println!(
            "  libSystem: {} → {}",
            ls.source.display(),
            ls.dest.display()
        );
        println!(
            "    origin: {}, LC_ID_DYLIB rewritten: {}",
            origin_str(ls.origin),
            ls.id_rewritten
        );
    } else if skip_libsystem {
        println!("  libSystem: skipped (--skip-libsystem)");
    } else {
        // Should not happen once resources/libSystem.B.dylib is packaged;
        // keep recovery hints for stripped/custom builds.
        println!("  libSystem: not found (bottle skeleton only)");
        println!("    expected: freestanding dylib embedded in kh-runtime");
        println!(
            "    rebuild:  cargo build -p kh-libsystem --release --target aarch64-apple-darwin"
        );
        println!("    stage:    ./scripts/stage-libsystem.sh  # → crates/kh-runtime/resources/");
        println!("    or:       kh bottle ensure --libsystem /path/to/libSystem.B.dylib");
        println!(
            "    or:       place libSystem.B.dylib next to `kh` / set {env}",
            env = bottle::ENV_LIBSYSTEM
        );
    }
    if bottle::bottle_has_macos_prefix(&created.path) {
        println!("  prefix:    macOS bin/sbin/usr/bin present");
    } else {
        println!("  prefix:    missing — copy bin, sbin, usr/bin from macOS 26+ Apple Silicon");
        println!("    /bin     → {}/bin/", created.path.display());
        println!("    /sbin    → {}/sbin/", created.path.display());
        println!("    /usr/bin → {}/usr/bin/", created.path.display());
    }
}

fn origin_str(o: LibsystemOrigin) -> &'static str {
    match o {
        LibsystemOrigin::Explicit => "explicit",
        LibsystemOrigin::Env => "env",
        LibsystemOrigin::Adjacent => "adjacent",
        LibsystemOrigin::DevTarget => "dev_target",
        LibsystemOrigin::Embedded => "embedded (crates.io)",
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
                    "libsystem": st.libsystem,
                    "libcxx_alias": st.libcxx_alias,
                    "libcurl_alias": st.libcurl_alias,
                    "prefix_macos": st.prefix_macos,
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
            println!("path:      {}", st.path.display());
            println!("exists:    {}", st.exists);
            println!("marker:    {}", st.valid_marker);
            println!("libSystem: {}", st.libsystem);
            println!("libc++:    {}", st.libcxx_alias);
            println!("libcurl:   {}", st.libcurl_alias);
            println!("prefix:    {}", st.prefix_macos);
            if st.exists && st.valid_marker {
                let bridge = st.path.join(bottle::VOLUMES_LINUX);
                println!("linux:     {} -> /", bridge.display());
                if st.libsystem {
                    println!(
                        "dylib:     {}/{}",
                        st.path.display(),
                        bottle::GUEST_LIBSYSTEM_REL
                    );
                }
                if st.libcxx_alias {
                    println!(
                        "alias:     {}/{} -> {}",
                        st.path.display(),
                        bottle::GUEST_LIBCXX_REL,
                        bottle::GUEST_LIBCXX_TARGET
                    );
                }
                if st.libcurl_alias {
                    println!(
                        "alias:     {}/{} -> {}",
                        st.path.display(),
                        bottle::GUEST_LIBCURL_REL,
                        bottle::GUEST_LIBCURL_TARGET
                    );
                }
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
        "libsystem": st.libsystem,
        "libcxx_alias": st.libcxx_alias,
        "libcurl_alias": st.libcurl_alias,
        "prefix_macos": st.prefix_macos,
    })
}
