//! `kh` — Kakehashi CLI (inspect, run, trace).

mod commands;

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(name = "kh")]
#[command(about = "Kakehashi — run macOS ARM64 binaries on Linux aarch64")]
#[command(long_about = "\
Userspace macOS translation layer for Linux ARM64 (no JIT).\n\
\n\
Commands: inspect | run | trace | bottle.\n\
Env: KAKEHASHI_LOG, KAKEHASHI_ROOT, KAKEHASHI_CONFIG_DIR, KAKEHASHI_DATA_DIR.\
")]
struct Cli {
    /// Increase log verbosity (repeatable). Overrides `KAKEHASHI_LOG` when set.
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    /// Emit JSON where supported.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Static Mach-O inspection (no execution).
    Inspect {
        /// Path to a Mach-O binary (thin arm64 or fat containing arm64).
        /// Optional when only `--host-page-size` is requested.
        path: Option<PathBuf>,

        /// List segments and sections.
        #[arg(long)]
        sections: bool,

        /// List `LC_LOAD_*DYLIB` dependencies.
        #[arg(long)]
        imports: bool,

        /// Filter imports by substring (implies `--imports`).
        #[arg(long)]
        find: Option<String>,

        /// Dump load commands.
        #[arg(long)]
        load_commands: bool,

        /// Print planned VA layout (guest page policy).
        #[arg(long)]
        image: bool,

        /// Guest page size for `--image` (4096 or 16384; default 16384).
        #[arg(long, value_name = "BYTES")]
        page_size: Option<u32>,

        /// Print detected host page size and exit.
        #[arg(long)]
        host_page_size: bool,
    },

    /// Run a Mach-O binary under the translation layer.
    Run {
        /// Path to the main executable.
        path: PathBuf,

        /// Bottle root (also `KAKEHASHI_ROOT`).
        #[arg(long)]
        root: Option<PathBuf>,

        /// Cap translated syscalls (micro default 65536).
        #[arg(long)]
        max_syscalls: Option<usize>,

        /// Expected process exit code (micro gate; default 0).
        #[arg(long, default_value_t = 0)]
        expect_code: i32,

        /// Guest page size (4096 or 16384; default 16384).
        #[arg(long, value_name = "BYTES")]
        guest_page_size: Option<u32>,

        /// Map and plan only; do not jump to entry.
        #[arg(long)]
        dry_load: bool,

        /// Guest argv after the program name.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        guest_args: Vec<String>,
    },

    /// Trace syscalls / traps for a Mach-O binary.
    Trace {
        /// Path to the main executable.
        path: PathBuf,

        /// Bottle root (also `KAKEHASHI_ROOT`).
        #[arg(long)]
        root: Option<PathBuf>,

        /// Maximum events to capture.
        #[arg(long, default_value_t = 256)]
        max_events: usize,

        /// Guest argv after the program name.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        guest_args: Vec<String>,
    },

    /// Manage the single macOS-like bottle (create / destroy / status).
    Bottle {
        #[command(subcommand)]
        action: BottleAction,
    },
}

#[derive(Debug, Subcommand)]
enum BottleAction {
    /// Create the bottle (fails if one is already registered).
    Create {
        /// Bottle directory (default: `$XDG_DATA_HOME/kakehashi/bottle`).
        ///
        /// The directory name is arbitrary — rename freely; the registry stores
        /// the absolute path.
        #[arg(long, short = 'p')]
        path: Option<PathBuf>,
        /// Guest `libSystem.B.dylib` (or `libkh_libsystem.dylib`) to install under
        /// `usr/lib/`. When omitted, searches `KAKEHASHI_LIBSYSTEM`, paths next to
        /// `kh`, then Cargo `target/` outputs.
        #[arg(long)]
        libsystem: Option<PathBuf>,
        /// Create the skeleton only (no libSystem install).
        #[arg(long)]
        skip_libsystem: bool,
    },
    /// Delete the registered bottle (prompts for y/N unless `--yes`).
    Destroy {
        /// Skip interactive confirmation.
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Print the registered bottle path.
    Path,
    /// Show bottle registration status.
    Status,
}

fn init_tracing(verbose: u8) {
    let filter = match verbose {
        0 => EnvFilter::try_from_env("KAKEHASHI_LOG").unwrap_or_else(|_| EnvFilter::new("warn")),
        1 => EnvFilter::new("info"),
        2 => EnvFilter::new("debug"),
        _ => EnvFilter::new("trace"),
    };
    drop(
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(std::io::stderr)
            .try_init(),
    );
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            let code = commands::inspect::exit_code_for(&err);
            eprintln!("error: {err:#}");
            ExitCode::from(code)
        }
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(cli.verbose);

    match cli.command {
        Command::Inspect {
            path,
            sections,
            imports,
            find,
            load_commands,
            image,
            page_size,
            host_page_size,
        } => commands::inspect::run(&commands::inspect::InspectArgs {
            path: path.as_deref(),
            sections,
            imports,
            find: find.as_deref(),
            load_commands,
            image,
            page_size,
            host_page_size,
            json: cli.json,
        }),
        Command::Run {
            path,
            root,
            max_syscalls,
            expect_code,
            guest_page_size,
            dry_load,
            guest_args,
        } => commands::run::run(&commands::run::RunArgs {
            path: &path,
            root: root.as_deref(),
            max_syscalls: max_syscalls.unwrap_or(65_536),
            expect_code,
            guest_page_size,
            dry_load,
            guest_args: &guest_args,
            json: cli.json,
        }),
        Command::Trace {
            path,
            root,
            max_events,
            guest_args,
        } => commands::trace::run(&commands::trace::TraceArgs {
            path: &path,
            root: root.as_deref(),
            max_events,
            guest_args: &guest_args,
            json: cli.json,
        }),
        Command::Bottle { action } => {
            let cmd = match &action {
                BottleAction::Create {
                    path,
                    libsystem,
                    skip_libsystem,
                } => commands::bottle::BottleCmd::Create {
                    path: path.as_deref(),
                    libsystem: libsystem.as_deref(),
                    skip_libsystem: *skip_libsystem,
                },
                BottleAction::Destroy { yes } => commands::bottle::BottleCmd::Destroy { yes: *yes },
                BottleAction::Path => commands::bottle::BottleCmd::Path,
                BottleAction::Status => commands::bottle::BottleCmd::Status,
            };
            commands::bottle::run(&cmd, cli.json)
        }
    }
}
