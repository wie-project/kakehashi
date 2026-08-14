//! CommonCrypto random fill (soft).

use core::ffi::{c_int, c_void};

/// `CCRandomGenerateBytes` → nlist `_CCRandomGenerateBytes`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn CCRandomGenerateBytes(bytes: *mut c_void, count: usize) -> c_int {
    if bytes.is_null() || count == 0 {
        return 0;
    }
    unsafe { crate::dylib::libsystem_c::net::arc4random_buf(bytes, count) };
    0
}
