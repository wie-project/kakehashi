//! UTF-8 encode/decode (RFC 3629). Used by `mbrtowc` / `wcrtomb` / `mbstowcs`.
//!
//! Public encoding rules only — not Apple locale source.

/// Darwin `wchar_t` / `wint_t` (32-bit).
pub(crate) type Wchar = i32;

/// `mbrtowc` incomplete sequence (`(size_t)-2`).
pub(crate) const MB_INCOMPLETE: usize = usize::MAX - 1;
/// `mbrtowc` illegal sequence (`(size_t)-1`).
pub(crate) const MB_ILLEGAL: usize = usize::MAX;

/// Bytes of UTF-8 state packed in the first 8 bytes of Darwin `mbstate_t`.
#[derive(Clone, Copy)]
pub(crate) struct MbState {
    /// Remaining continuation bytes (0 = initial).
    pub expect: u8,
    /// Lead + cont bytes already consumed.
    pub have: u8,
    /// Accumulated code point.
    pub acc: u32,
}

impl MbState {
    pub(crate) const fn initial() -> Self {
        Self {
            expect: 0,
            have: 0,
            acc: 0,
        }
    }

    pub(crate) fn load(ps: *const core::ffi::c_void) -> Self {
        if ps.is_null() {
            return Self::initial();
        }
        // SAFETY: Darwin `mbstate_t` is ≥8 bytes; we own the first word.
        let w = unsafe { ps.cast::<u64>().read() };
        Self {
            expect: u8::try_from(w & 0xff).unwrap_or(0),
            have: u8::try_from((w >> 8) & 0xff).unwrap_or(0),
            acc: u32::try_from((w >> 16) & 0xffff_ffff).unwrap_or(0),
        }
    }

    pub(crate) fn store(self, ps: *mut core::ffi::c_void) {
        if ps.is_null() {
            return;
        }
        let w = u64::from(self.expect) | (u64::from(self.have) << 8) | (u64::from(self.acc) << 16);
        // SAFETY: same 8-byte prefix as [`Self::load`].
        unsafe {
            ps.cast::<u64>().write(w);
        }
    }
}

fn valid_scalar(cp: u32, nbytes: u8) -> bool {
    if (0xd800..=0xdfff).contains(&cp) || cp > 0x10_ffff {
        return false;
    }
    let min = match nbytes {
        1 => 0_u32,
        2 => 0x80,
        3 => 0x800,
        4 => 0x1_0000,
        _ => return false,
    };
    cp >= min
}

/// Decode one UTF-8 scalar from `s[..n]`, updating `st`.
///
/// Returns bytes consumed from this call, [`MB_INCOMPLETE`], or [`MB_ILLEGAL`].
/// NUL → 0 and resets state.
pub(crate) fn mbrtowc(s: &[u8], st: &mut MbState) -> (usize, Option<Wchar>) {
    if s.is_empty() {
        return (MB_INCOMPLETE, None);
    }
    let mut i = 0_usize;
    while i < s.len() {
        let Some(&b) = s.get(i) else {
            break;
        };
        i = i.saturating_add(1);
        if st.expect == 0 {
            if b < 0x80 {
                *st = MbState::initial();
                return (if b == 0 { 0 } else { i }, Some(i32::from(b)));
            }
            let (exp, acc) = if b & 0xe0 == 0xc0 {
                if b < 0xc2 {
                    *st = MbState::initial();
                    return (MB_ILLEGAL, None);
                }
                (1_u8, u32::from(b & 0x1f))
            } else if b & 0xf0 == 0xe0 {
                (2, u32::from(b & 0x0f))
            } else if b & 0xf8 == 0xf0 {
                if b > 0xf4 {
                    *st = MbState::initial();
                    return (MB_ILLEGAL, None);
                }
                (3, u32::from(b & 0x07))
            } else {
                *st = MbState::initial();
                return (MB_ILLEGAL, None);
            };
            st.expect = exp;
            st.have = 1;
            st.acc = acc;
        } else {
            if b & 0xc0 != 0x80 {
                *st = MbState::initial();
                return (MB_ILLEGAL, None);
            }
            st.acc = (st.acc << 6) | u32::from(b & 0x3f);
            st.expect = st.expect.saturating_sub(1);
            st.have = st.have.saturating_add(1);
            if st.expect == 0 {
                let n = st.have;
                let cp = st.acc;
                *st = MbState::initial();
                if !valid_scalar(cp, n) {
                    return (MB_ILLEGAL, None);
                }
                let wc = i32::try_from(cp).unwrap_or(-1);
                return (i, Some(wc));
            }
        }
    }
    (MB_INCOMPLETE, None)
}

/// Encode one scalar to UTF-8. `None` if `wc` is not a Unicode scalar.
pub(crate) fn encode(wc: Wchar, out: &mut [u8; 4]) -> Option<usize> {
    if wc < 0 {
        return None;
    }
    let cp = u32::try_from(wc).ok()?;
    if (0xd800..=0xdfff).contains(&cp) || cp > 0x10_ffff {
        return None;
    }
    if cp < 0x80 {
        out[0] = u8::try_from(cp).unwrap_or(0);
        return Some(1);
    }
    if cp < 0x800 {
        out[0] = 0xc0 | u8::try_from(cp >> 6).unwrap_or(0);
        out[1] = 0x80 | u8::try_from(cp & 0x3f).unwrap_or(0);
        return Some(2);
    }
    if cp < 0x1_0000 {
        out[0] = 0xe0 | u8::try_from(cp >> 12).unwrap_or(0);
        out[1] = 0x80 | u8::try_from((cp >> 6) & 0x3f).unwrap_or(0);
        out[2] = 0x80 | u8::try_from(cp & 0x3f).unwrap_or(0);
        return Some(3);
    }
    out[0] = 0xf0 | u8::try_from(cp >> 18).unwrap_or(0);
    out[1] = 0x80 | u8::try_from((cp >> 12) & 0x3f).unwrap_or(0);
    out[2] = 0x80 | u8::try_from((cp >> 6) & 0x3f).unwrap_or(0);
    out[3] = 0x80 | u8::try_from(cp & 0x3f).unwrap_or(0);
    Some(4)
}

/// Printable for zle / `wcwidth` (ASCII + Unicode scalars except C0/C1/surrogates).
#[must_use]
pub(crate) fn is_print(wc: Wchar) -> bool {
    if wc < 0 {
        return false;
    }
    let u = wc.cast_unsigned();
    if u <= 0x7f {
        return (0x20..=0x7e).contains(&u);
    }
    if (0x80..0xa0).contains(&u) {
        return false;
    }
    if (0xd800..=0xdfff).contains(&u) || u > 0x10_ffff {
        return false;
    }
    true
}

/// Column width: 0 NUL, −1 non-print, 1 otherwise (Cyrillic / Latin).
#[must_use]
pub(crate) fn width(wc: Wchar) -> i32 {
    if wc == 0 {
        return 0;
    }
    if is_print(wc) { 1 } else { -1 }
}

/// Alpha for word motion: ASCII letters + Cyrillic blocks + Latin-1/extended.
#[must_use]
pub(crate) fn is_alpha(wc: Wchar) -> bool {
    if wc < 0 {
        return false;
    }
    let u = wc.cast_unsigned();
    if u <= 0x7f {
        let b = u8::try_from(u).unwrap_or(0);
        return b.is_ascii_alphabetic();
    }
    (0x00c0..=0x024f).contains(&u)
        || (0x0370..=0x03ff).contains(&u)
        || (0x0400..=0x052f).contains(&u)
        || (0x2de0..=0x2dff).contains(&u)
        || (0xa640..=0xa69f).contains(&u)
}

#[must_use]
pub(crate) fn is_digit(wc: Wchar) -> bool {
    (i32::from(b'0')..=i32::from(b'9')).contains(&wc)
}

/// Russian / ASCII case fold (Ё/ё included).
#[must_use]
pub(crate) fn to_lower(wc: Wchar) -> Wchar {
    if (i32::from(b'A')..=i32::from(b'Z')).contains(&wc) {
        return wc.wrapping_add(32);
    }
    if (0x0410..=0x042f).contains(&wc) {
        return wc.wrapping_add(0x20);
    }
    if wc == 0x0401 {
        return 0x0451;
    }
    wc
}

#[must_use]
pub(crate) fn to_upper(wc: Wchar) -> Wchar {
    if (i32::from(b'a')..=i32::from(b'z')).contains(&wc) {
        return wc.wrapping_sub(32);
    }
    if (0x0430..=0x044f).contains(&wc) {
        return wc.wrapping_sub(0x20);
    }
    if wc == 0x0451 {
        return 0x0401;
    }
    wc
}
