//! Freestanding `std::__1::__sort` instantiations for Apple clang.
//!
//! Observed imports (clang driver / -cc1):
//! `__sort<__less<T>&, T*>` for `char`, `int`, `unsigned`, `unsigned short`.
//! Comparator is unused (always `__less`); we sort ascending in-place.
//!
//! Clean-room heapsort — not a paste of libc++.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_ptr_alignment,
    clippy::cast_sign_loss,
    clippy::integer_division,
    clippy::ptr_as_ptr
)]

use core::ffi::c_void;

/// In-place heapsort for `Copy + Ord` elements.
unsafe fn heapsort<T: Copy + Ord>(first: *mut T, last: *mut T) {
    if first.is_null() || last.is_null() || last <= first {
        return;
    }
    let n = unsafe { last.offset_from(first) };
    if n <= 1 {
        return;
    }
    let n = n as usize;
    // Build heap.
    let mut i = n / 2;
    while i > 0 {
        i -= 1;
        unsafe {
            sift_down(first, n, i);
        }
    }
    // Extract.
    let mut end = n;
    while end > 1 {
        end -= 1;
        unsafe {
            let a = first.add(0).read();
            let b = first.add(end).read();
            first.add(0).write(b);
            first.add(end).write(a);
            sift_down(first, end, 0);
        }
    }
}

unsafe fn sift_down<T: Copy + Ord>(base: *mut T, n: usize, mut root: usize) {
    loop {
        let left = root.saturating_mul(2).saturating_add(1);
        if left >= n {
            break;
        }
        let mut swap = root;
        unsafe {
            if base.add(swap).read() < base.add(left).read() {
                swap = left;
            }
            let right = left.saturating_add(1);
            if right < n && base.add(swap).read() < base.add(right).read() {
                swap = right;
            }
            if swap == root {
                break;
            }
            let a = base.add(root).read();
            let b = base.add(swap).read();
            base.add(root).write(b);
            base.add(swap).write(a);
        }
        root = swap;
    }
}

/// `void std::__sort<__less<unsigned short>&, unsigned short*>(…)`
#[unsafe(export_name = "_ZNSt3__16__sortIRNS_6__lessIttEEPtEEvT0_S5_T_")]
pub(crate) unsafe extern "C" fn sort_ushort(first: *mut u16, last: *mut u16, _comp: *mut c_void) {
    unsafe {
        heapsort(first, last);
    }
}

/// `void std::__sort<__less<int>&, int*>(…)`
#[unsafe(export_name = "_ZNSt3__16__sortIRNS_6__lessIiiEEPiEEvT0_S5_T_")]
pub(crate) unsafe extern "C" fn sort_int(first: *mut i32, last: *mut i32, _comp: *mut c_void) {
    unsafe {
        heapsort(first, last);
    }
}

/// `void std::__sort<__less<unsigned>&, unsigned*>(…)`
#[unsafe(export_name = "_ZNSt3__16__sortIRNS_6__lessIjjEEPjEEvT0_S5_T_")]
pub(crate) unsafe extern "C" fn sort_uint(first: *mut u32, last: *mut u32, _comp: *mut c_void) {
    unsafe {
        heapsort(first, last);
    }
}

/// `void std::__sort<__less<char>&, char*>(…)`
#[unsafe(export_name = "_ZNSt3__16__sortIRNS_6__lessIccEEPcEEvT0_S5_T_")]
pub(crate) unsafe extern "C" fn sort_char(first: *mut i8, last: *mut i8, _comp: *mut c_void) {
    unsafe {
        heapsort(first, last);
    }
}
