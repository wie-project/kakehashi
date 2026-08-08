//! On-disk Mach-O container bytes for parse → map → bind.
//!
//! Prefer a read-only file `mmap` so only pages actually touched by parse /
//! segment fill / bind enter RSS (large CLT tools, any guest). Fall back to
//! `fs::read` when mapping fails (empty path edge cases, exotic hosts).

use std::ops::Deref;
use std::path::Path;

use kh_runtime::MappedFile;

use crate::error::LoadError;

/// Full container of a guest Mach-O (thin or fat).
#[derive(Debug)]
pub enum FileImage {
    /// Lazy `mmap` of the whole file.
    Map(MappedFile),
    /// Eager heap copy (`fs::read` fallback).
    Heap(Vec<u8>),
}

impl FileImage {
    /// Open `path` via `mmap` when possible; otherwise `fs::read`.
    pub fn open(path: &Path) -> Result<Self, LoadError> {
        match MappedFile::open(path) {
            Ok(m) => Ok(Self::Map(m)),
            Err(_mmap_err) => {
                let bytes = std::fs::read(path)?;
                Ok(Self::Heap(bytes))
            }
        }
    }

    /// Contiguous container bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        match self {
            Self::Map(m) => m.as_slice(),
            Self::Heap(v) => v.as_slice(),
        }
    }

    /// Length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.as_slice().len()
    }

    /// Empty container.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.as_slice().is_empty()
    }
}

impl Deref for FileImage {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}
