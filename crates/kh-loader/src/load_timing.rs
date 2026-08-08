//! Opt-in load-path phase timings (`KAKEHASHI_LOAD_TIMING`).
//!
//! Roadmap2-style: **default off**. Hot path when off is one atomic mode load
//! per phase start/end. When on, records wall `Instant` deltas and dumps to
//! stderr before guest entry (and again on host-side return if any).
//!
//! Values: unset/`0`/`off` = off; `1`/`on`/`true` = on.

use std::fmt::Write as _;
use std::io::{self, Write as IoWrite};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Instant;

const MODE_UNINIT: u8 = 0;
const MODE_OFF: u8 = 1;
const MODE_ON: u8 = 2;

static MODE: AtomicU8 = AtomicU8::new(MODE_UNINIT);

struct State {
    run_start: Option<Instant>,
    phases: Vec<(&'static str, u64)>,
    /// Extra one-line notes (image counts, etc.).
    notes: Vec<String>,
}

static STATE: Mutex<Option<State>> = Mutex::new(None);

fn mode_from_env() -> u8 {
    match std::env::var_os("KAKEHASHI_LOAD_TIMING") {
        None => MODE_OFF,
        Some(v) => {
            if v == "0"
                || v.eq_ignore_ascii_case("false")
                || v.eq_ignore_ascii_case("no")
                || v.eq_ignore_ascii_case("off")
            {
                MODE_OFF
            } else {
                MODE_ON
            }
        }
    }
}

#[inline]
fn resolved_mode() -> u8 {
    let m = MODE.load(Ordering::Relaxed);
    if m != MODE_UNINIT {
        return m;
    }
    let parsed = mode_from_env();
    let _ = MODE.compare_exchange(MODE_UNINIT, parsed, Ordering::Relaxed, Ordering::Relaxed);
    MODE.load(Ordering::Relaxed)
}

/// Whether load timing is enabled (after first resolve).
#[inline]
#[must_use]
pub fn enabled() -> bool {
    resolved_mode() == MODE_ON
}

/// Start a new timed run (clears previous phases). No-op when off.
pub fn begin_run() {
    if !enabled() {
        return;
    }
    if let Ok(mut g) = STATE.lock() {
        *g = Some(State {
            run_start: Some(Instant::now()),
            phases: Vec::with_capacity(16),
            notes: Vec::new(),
        });
    }
}

/// Record a completed phase duration in nanoseconds.
pub fn record(name: &'static str, ns: u64) {
    if !enabled() {
        return;
    }
    if let Ok(mut g) = STATE.lock()
        && let Some(st) = g.as_mut()
    {
        st.phases.push((name, ns));
    }
}

/// Time a closure and record it under `name`.
#[inline]
pub fn time<T>(name: &'static str, f: impl FnOnce() -> T) -> T {
    if !enabled() {
        return f();
    }
    let t0 = Instant::now();
    let out = f();
    let ns = u64::try_from(t0.elapsed().as_nanos()).unwrap_or(u64::MAX);
    record(name, ns);
    out
}

/// Time a fallible closure.
#[inline]
pub fn time_result<T, E>(name: &'static str, f: impl FnOnce() -> Result<T, E>) -> Result<T, E> {
    if !enabled() {
        return f();
    }
    let t0 = Instant::now();
    let out = f();
    let ns = u64::try_from(t0.elapsed().as_nanos()).unwrap_or(u64::MAX);
    record(name, ns);
    out
}

/// Attach a free-form note (image counts, paths, …).
pub fn note(msg: impl Into<String>) {
    if !enabled() {
        return;
    }
    if let Ok(mut g) = STATE.lock()
        && let Some(st) = g.as_mut()
    {
        st.notes.push(msg.into());
    }
}

#[allow(clippy::integer_division, clippy::arithmetic_side_effects)]
fn ns_to_ms_tenths(ns: u64) -> (u64, u64) {
    // ms and tenths: ns / 1_000_000, (ns % 1_000_000) / 100_000
    let ms = ns / 1_000_000;
    let tenths = (ns % 1_000_000) / 100_000;
    (ms, tenths)
}

#[allow(clippy::integer_division, clippy::arithmetic_side_effects)]
fn pct_tenths(part: u64, whole: u64) -> (u64, u64) {
    if whole == 0 {
        return (0, 0);
    }
    // 1000 * part / whole → whole% * 10
    let x = part.saturating_mul(1000) / whole;
    (x / 10, x % 10)
}

/// Dump phase table to stderr. Safe before guest entry / after guest return.
pub fn dump(label: &str) {
    if !enabled() {
        return;
    }
    let Ok(g) = STATE.lock() else {
        return;
    };
    let Some(st) = g.as_ref() else {
        return;
    };
    let total_ns = st.run_start.map_or(0, |t| {
        u64::try_from(t.elapsed().as_nanos()).unwrap_or(u64::MAX)
    });
    let sum_phases: u64 = st.phases.iter().map(|(_, ns)| *ns).sum();
    let (tw, tt) = ns_to_ms_tenths(total_ns);
    let (sw, stt) = ns_to_ms_tenths(sum_phases);
    let mut out = format!(
        "kh load timing ({label}): wall_ms={tw}.{tt}  sum_phases_ms={sw}.{stt}  phases={}\n",
        st.phases.len()
    );
    for (i, (name, ns)) in st.phases.iter().enumerate() {
        let (ms, tenths) = ns_to_ms_tenths(*ns);
        let (pw, pt) = pct_tenths(*ns, total_ns);
        let rank = i.saturating_add(1);
        let _ = writeln!(
            out,
            "  {rank:>2}  {ms:>5}.{tenths} ms  {pw:>3}.{pt}%  {name}"
        );
    }
    let unaccounted = total_ns.saturating_sub(sum_phases);
    if unaccounted > 0 {
        let (ms, tenths) = ns_to_ms_tenths(unaccounted);
        let (pw, pt) = pct_tenths(unaccounted, total_ns);
        let _ = writeln!(
            out,
            "       {ms:>5}.{tenths} ms  {pw:>3}.{pt}%  (unaccounted)"
        );
    }
    for n in &st.notes {
        out.push_str("  note: ");
        out.push_str(n);
        out.push('\n');
    }
    drop(io::stderr().write_all(out.as_bytes())); // IoWrite
}
