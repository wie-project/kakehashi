//! Loader and image-planning errors.

use thiserror::Error;

use kh_runtime::MapError;

/// Failures while reading or validating a Mach-O image.
#[derive(Debug, Error)]
pub enum LoadError {
    /// Filesystem or I/O failure.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Bytes are not a recognized Mach-O (or supported fat) image.
    #[error("not a supported Mach-O binary: {0}")]
    NotMachO(String),

    /// Image architecture is not arm64.
    #[error("unsupported architecture: {0}")]
    UnsupportedArch(String),

    /// Host/guest page geometry could not be established.
    #[error("page layout error: {0}")]
    PageLayout(String),

    /// Guest memory mapping failed.
    #[error("map error: {0}")]
    Map(#[from] MapError),

    /// Install-name resolution failed hard (e.g. invalid encoding).
    #[error("path resolve: {0}")]
    Resolve(String),

    /// Dependency graph exceeded the dylib cap.
    #[error("too many dylibs (limit {0})")]
    TooManyDylibs(usize),

    /// A dependency path existed but is not `MH_DYLIB`.
    #[error("dependent image is not MH_DYLIB: {0}")]
    NotDylib(String),

    /// Strong undefined symbol with no export in the process set (PR2 bind).
    #[error("unresolved symbol {name}")]
    UnresolvedSymbol {
        /// Symbol name (nlist spelling).
        name: String,
    },

    /// GOT section missing or too small for undefined imports (PR2 bind).
    #[error("GOT section missing or too small for {count} undefined symbols")]
    MissingGot {
        /// Number of undefined external symbols that needed GOT slots.
        count: usize,
    },

    /// Main image slid but fixed `adrp` GOT addressing requires preferred base.
    #[error("main image slid ({slide:#x}) but GOT adrp requires preferred placement: {path}")]
    ImageSlid {
        /// Host path of the main image.
        path: String,
        /// Applied slide.
        slide: u64,
    },

    /// Feature not implemented yet (scaffolding).
    #[error("not implemented: {0}")]
    NotImplemented(&'static str),
}

impl LoadError {
    /// Process exit code for the CLI (`2` = wrong kind/arch, `1` = other).
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::NotMachO(_) | Self::UnsupportedArch(_) | Self::NotDylib(_) => 2,
            _ => 1,
        }
    }
}
