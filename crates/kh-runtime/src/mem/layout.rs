//! Page-size policy used when planning and mapping Mach-O segments.
//!
//! Apple Silicon macOS uses 16 KiB pages. Linux aarch64 is often 4 KiB (Colima /
//! stock Ubuntu) or 16 KiB (Asahi and some server configs). Mapping always uses
//! host-page multiples; guest alignment defaults to 16 KiB for Darwin arm64.

use thiserror::Error;

/// Default guest page size for arm64 Darwin images (bytes).
pub const DARWIN_ARM64_PAGE_SIZE: u32 = 16_384;

/// Supported host page sizes we handle explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HostPageSize {
    /// Standard Linux aarch64 (and most containers).
    FourK,
    /// Asahi Linux and some aarch64 kernels.
    SixteenK,
}

impl HostPageSize {
    /// Size in bytes.
    #[inline]
    pub const fn bytes(self) -> u32 {
        match self {
            Self::FourK => 4_096,
            Self::SixteenK => 16_384,
        }
    }

    /// Detects the host page size via `libc::sysconf(_SC_PAGESIZE)`.
    ///
    /// Returns [`PageError::UnsupportedHostPageSize`] when the value is not
    /// 4096 or 16384.
    pub fn detect() -> Result<Self, PageError> {
        detect_host_page_size()
    }

    /// Maps a raw byte size to a known host page size.
    #[inline]
    pub const fn from_bytes(bytes: u32) -> Option<Self> {
        match bytes {
            4_096 => Some(Self::FourK),
            16_384 => Some(Self::SixteenK),
            _ => None,
        }
    }
}

/// Guest page size policy for image planning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum GuestPageSize {
    /// 16 KiB — default for arm64 Darwin.
    #[default]
    Darwin16K,
    /// Explicit size (must be a power of two, currently 4K or 16K).
    Explicit(u32),
}

impl GuestPageSize {
    /// Size in bytes.
    #[inline]
    pub const fn bytes(self) -> u32 {
        match self {
            Self::Darwin16K => DARWIN_ARM64_PAGE_SIZE,
            Self::Explicit(n) => n,
        }
    }

    /// Builds an explicit size if it is 4096 or 16384.
    pub const fn try_explicit(bytes: u32) -> Option<Self> {
        match bytes {
            4_096 | 16_384 => Some(Self::Explicit(bytes)),
            _ => None,
        }
    }
}

/// Combined host + guest geometry for one process session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageLayout {
    /// Detected or configured host page size.
    pub host: HostPageSize,
    /// Guest alignment / protection planning size.
    pub guest: GuestPageSize,
}

impl PageLayout {
    /// Creates a layout from host detection and a guest policy.
    pub fn new(host: HostPageSize, guest: GuestPageSize) -> Self {
        Self { host, guest }
    }

    /// Detects host page size and uses the default Darwin guest size.
    pub fn detect_host_default_guest() -> Result<Self, PageError> {
        Ok(Self {
            host: HostPageSize::detect()?,
            guest: GuestPageSize::default(),
        })
    }

    /// Host page size in bytes.
    #[inline]
    pub const fn host_bytes(self) -> u32 {
        self.host.bytes()
    }

    /// Guest page size in bytes.
    #[inline]
    pub const fn guest_bytes(self) -> u32 {
        self.guest.bytes()
    }

    /// Rounds `value` up to a multiple of `page`.
    ///
    /// Returns `None` if `page` is zero or the result would overflow.
    #[inline]
    #[allow(clippy::arithmetic_side_effects)]
    pub fn align_up(value: u64, page: u32) -> Option<u64> {
        if page == 0 {
            return None;
        }
        let page_u = u64::from(page);
        let rem = value % page_u;
        if rem == 0 {
            Some(value)
        } else {
            value.checked_add(page_u - rem)
        }
    }

    /// Rounds `value` down to a multiple of `page`.
    #[inline]
    #[allow(clippy::arithmetic_side_effects)]
    pub fn align_down(value: u64, page: u32) -> Option<u64> {
        if page == 0 {
            return None;
        }
        let page_u = u64::from(page);
        Some(value - (value % page_u))
    }

    /// Number of whole `page`-sized units needed to cover `length` bytes.
    #[inline]
    #[allow(clippy::arithmetic_side_effects, clippy::integer_division)]
    pub fn page_count(length: u64, page: u32) -> Option<u64> {
        let aligned = Self::align_up(length, page)?;
        Some(aligned / u64::from(page))
    }

    /// True if `addr` is aligned to the guest page size.
    #[inline]
    pub fn is_guest_aligned(self, addr: u64) -> bool {
        let page = u64::from(self.guest_bytes());
        page != 0 && addr.is_multiple_of(page)
    }

    /// True if `addr` is aligned to the host page size.
    #[inline]
    pub fn is_host_aligned(self, addr: u64) -> bool {
        let page = u64::from(self.host_bytes());
        page != 0 && addr.is_multiple_of(page)
    }
}

/// Errors from page-size detection or validation.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PageError {
    /// `sysconf(_SC_PAGESIZE)` failed.
    #[error("failed to detect host page size")]
    DetectFailed,

    /// Host page size is not 4 KiB or 16 KiB.
    #[error("unsupported host page size: {bytes} bytes (expected 4096 or 16384)")]
    UnsupportedHostPageSize {
        /// Raw size reported by the host (may not fit in `u32`).
        bytes: i64,
    },
}

/// Queries the OS page size. Isolated so `unsafe` does not spread.
#[allow(unsafe_code)]
fn detect_host_page_size() -> Result<HostPageSize, PageError> {
    // SAFETY: `sysconf(_SC_PAGESIZE)` takes no pointers and only returns a
    // scalar page size or -1 on error. No memory is dereferenced.
    let raw = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if raw <= 0 {
        return Err(PageError::DetectFailed);
    }
    let Ok(bytes) = u32::try_from(raw) else {
        return Err(PageError::UnsupportedHostPageSize { bytes: raw });
    };
    HostPageSize::from_bytes(bytes).ok_or(PageError::UnsupportedHostPageSize {
        bytes: i64::from(bytes),
    })
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn align_up_down_4k() {
        assert_eq!(PageLayout::align_up(0, 4096), Some(0));
        assert_eq!(PageLayout::align_up(1, 4096), Some(4096));
        assert_eq!(PageLayout::align_up(4096, 4096), Some(4096));
        assert_eq!(PageLayout::align_up(4097, 4096), Some(8192));
        assert_eq!(PageLayout::align_down(4097, 4096), Some(4096));
        assert_eq!(PageLayout::align_down(4096, 4096), Some(4096));
    }

    #[test]
    fn align_up_down_16k() {
        assert_eq!(PageLayout::align_up(1, 16_384), Some(16_384));
        assert_eq!(PageLayout::align_up(16_384, 16_384), Some(16_384));
        assert_eq!(PageLayout::align_down(16_385, 16_384), Some(16_384));
    }

    #[test]
    fn page_count_covers_partial() {
        assert_eq!(PageLayout::page_count(0, 4096), Some(0));
        assert_eq!(PageLayout::page_count(1, 4096), Some(1));
        assert_eq!(PageLayout::page_count(4096, 4096), Some(1));
        assert_eq!(PageLayout::page_count(4097, 4096), Some(2));
        assert_eq!(PageLayout::page_count(16_384, 16_384), Some(1));
    }

    #[test]
    fn zero_page_rejected() {
        assert_eq!(PageLayout::align_up(1, 0), None);
        assert_eq!(PageLayout::align_down(1, 0), None);
        assert_eq!(PageLayout::page_count(1, 0), None);
    }

    #[test]
    fn host_from_bytes() {
        assert_eq!(HostPageSize::from_bytes(4096), Some(HostPageSize::FourK));
        assert_eq!(
            HostPageSize::from_bytes(16_384),
            Some(HostPageSize::SixteenK)
        );
        assert_eq!(HostPageSize::from_bytes(8192), None);
    }

    #[test]
    fn guest_default_is_darwin_16k() {
        assert_eq!(GuestPageSize::default().bytes(), 16_384);
    }

    #[test]
    fn detect_host_succeeds_on_this_machine() {
        let host = HostPageSize::detect().expect("host page size should be 4K or 16K");
        assert!(matches!(host, HostPageSize::FourK | HostPageSize::SixteenK));
        let layout = PageLayout::detect_host_default_guest().expect("layout");
        assert_eq!(layout.guest_bytes(), 16_384);
        assert_eq!(layout.host_bytes(), host.bytes());
    }

    #[test]
    fn layout_alignment_helpers() {
        let layout = PageLayout::new(HostPageSize::FourK, GuestPageSize::Darwin16K);
        assert!(layout.is_guest_aligned(0));
        assert!(layout.is_guest_aligned(16_384));
        assert!(!layout.is_guest_aligned(4096));
        assert!(layout.is_host_aligned(4096));
        assert!(!layout.is_host_aligned(2048));
    }
}
