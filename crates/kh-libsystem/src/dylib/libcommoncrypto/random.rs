//! CommonCrypto random fill (soft).

use core::ffi::{c_int, c_void};

/// `CCRandomGenerateBytes` → nlist `_CCRandomGenerateBytes` (fill with zeros).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn CCRandomGenerateBytes(bytes: *mut c_void, count: usize) -> c_int {
    if bytes.is_null() || count == 0 {
        return 0;
    }
    // SAFETY: caller buffer; deterministic zero fill (not crypto-grade).
    unsafe {
        let p = bytes.cast::<u8>();
        let mut i = 0_usize;
        while i < count {
            p.add(i).write(0);
            i = i.saturating_add(1);
        }
    }
    0
}
