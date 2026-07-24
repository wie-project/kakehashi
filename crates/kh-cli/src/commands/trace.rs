//! Syscall / trap tracing command.

use std::io;
use std::path::Path;

use anyhow::{Context, Result};
use kh_loader::{RunOptions, run_micro};
use kh_runtime::GuestPageSize;

use super::util::{map_live_exec_error, resolve_root, write_line};

/// Arguments for `kh trace`.
pub(crate) struct TraceArgs<'a> {
    pub path: &'a Path,
    pub root: Option<&'a Path>,
    pub max_events: usize,
    pub guest_args: &'a [String],
    pub json: bool,
}

/// Runs the trace command.
///
/// On guest `exit`, events are printed from the trap handler then the process
/// exits with the guest status.
pub(crate) fn run(args: &TraceArgs<'_>) -> Result<()> {
    let root = resolve_root(args.root);

    kh_runtime::trap::set_trace_on_exit(args.json);

    let opts = RunOptions {
        root,
        guest_page_size: GuestPageSize::default(),
        guest_args: args.guest_args.to_vec(),
        max_events: args.max_events,
        max_syscalls: args.max_events,
        dry_load: false,
    };

    match run_micro(args.path, &opts) {
        Ok(result) => {
            // Guest did not `_exit`; print whatever we have.
            print_events(&result.events, args.json)?;
            Ok(())
        }
        Err(err) => Err(map_live_exec_error(err)).context("trace failed"),
    }
}

fn print_events(events: &[kh_runtime::TrapEvent], json: bool) -> Result<()> {
    if json {
        let list: Vec<_> = events
            .iter()
            .map(|e| {
                serde_json::json!({
                    "pc": e.pc,
                    "syscall": e.syscall,
                    "name": e.name,
                    "arg0": e.arg0,
                    "arg1": e.arg1,
                    "arg2": e.arg2,
                    "retval": e.retval,
                    "error": e.error,
                })
            })
            .collect();
        println!("{}", serde_json::json!({ "events": list }));
        return Ok(());
    }
    let mut out = io::stdout().lock();
    write_line(&mut out, &format!("trace events: {}", events.len()))?;
    for (i, e) in events.iter().enumerate() {
        let ret = e
            .retval
            .map_or_else(|| "-".to_owned(), |v| format!("{v:#x}"));
        let err = if e.error { " err" } else { "" };
        write_line(
            &mut out,
            &format!(
                "  [{i}] pc={:#x} {} sys={:?} args=({:#x}, {:#x}, {:#x}) ret={ret}{err}",
                e.pc, e.name, e.syscall, e.arg0, e.arg1, e.arg2
            ),
        )?;
    }
    Ok(())
}
