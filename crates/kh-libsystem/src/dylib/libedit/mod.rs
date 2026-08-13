//! Soft libedit / readline-compat surface.
//!
//! Observed: guest `clang` + `LUA_USE_MACOSX` (`LUA_USE_READLINE`) imports
//! `_readline`, `_add_history`, `_rl_readline_name`. Darwin ships those via
//! libedit; the bottle aliases that install name to this dylib.
//!
//! Contracts from public man pages (`readline(3)`, `add_history(3)`):
//! - `readline` writes `prompt` to stdout, reads one line from stdin, returns
//!   a malloc'd string without the newline (caller `free`s), or null on EOF.
//! - `add_history` records a line for later recall (soft: no-op).
//! - `rl_readline_name` is a writable `char*` the guest may set.

use core::ffi::{c_char, c_void};

use crate::dylib::libsystem_c::posix::read;
use crate::dylib::libsystem_c::stdio::{strlen, write};
use crate::kh_core::heap::{free, malloc, realloc};

const LINE_CAP0: usize = 128;
const LINE_CAP_MAX: usize = 1 << 20;

/// `rl_readline_name` → nlist `_rl_readline_name`.
#[unsafe(export_name = "rl_readline_name")]
#[used]
pub(crate) static mut RL_READLINE_NAME: *mut c_char = core::ptr::null_mut();

/// `add_history` → nlist `_add_history`.
#[unsafe(export_name = "add_history")]
pub(crate) unsafe extern "C" fn add_history(_line: *const c_char) {
    // Soft: no history file / recall yet. Enough for link + non-interactive use.
}

/// `readline` → nlist `_readline`.
#[unsafe(export_name = "readline")]
pub(crate) unsafe extern "C" fn readline(prompt: *const c_char) -> *mut c_char {
    if !prompt.is_null() {
        let n = unsafe { strlen(prompt) };
        if n > 0 {
            let _ = unsafe { write(1, prompt.cast::<c_void>(), n) };
        }
    }

    let mut cap = LINE_CAP0;
    let mut buf = unsafe { malloc(cap) }.cast::<u8>();
    if buf.is_null() {
        return core::ptr::null_mut();
    }
    let mut len = 0_usize;
    loop {
        let mut byte = 0_u8;
        let n = unsafe { read(0, core::ptr::from_mut(&mut byte).cast(), 1) };
        if n <= 0 {
            if len == 0 {
                unsafe {
                    free(buf.cast());
                }
                return core::ptr::null_mut();
            }
            break;
        }
        if byte == b'\n' {
            break;
        }
        if byte == b'\r' {
            continue;
        }
        let need = len.saturating_add(1);
        if need >= cap {
            let new_cap = cap.saturating_mul(2);
            if new_cap > LINE_CAP_MAX || new_cap <= cap {
                unsafe {
                    free(buf.cast());
                }
                return core::ptr::null_mut();
            }
            let grown = unsafe { realloc(buf.cast(), new_cap) }.cast::<u8>();
            if grown.is_null() {
                unsafe {
                    free(buf.cast());
                }
                return core::ptr::null_mut();
            }
            buf = grown;
            cap = new_cap;
        }
        unsafe {
            buf.add(len).write(byte);
        }
        len = need;
    }
    unsafe {
        buf.add(len).write(0);
    }
    buf.cast()
}
