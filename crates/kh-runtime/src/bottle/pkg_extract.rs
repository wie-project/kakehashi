//! Self-contained extract of Apple **flat `.pkg`** (XAR + pbzx + odc cpio).
//!
//! Software Update CLT packages are not plain tar/zip. The public layout is:
//!
//! 1. **XAR** container (`xar!`) with zlib-compressed TOC XML
//! 2. Member **`Payload`**: Apple **pbzx** (multi-stream xz)
//! 3. Concatenated xz streams → **odc cpio** (`070707…`) file tree
//!
//! We own this path so install does not depend on p7zip/bsdtar quirks.

use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use flate2::read::ZlibDecoder;
use liblzma::read::XzDecoder;

/// Extract an Apple flat package into `dest` (creates `dest` if needed).
///
/// After success, `dest` contains the package root (typically
/// `Library/Developer/CommandLineTools/…`).
pub(crate) fn extract_apple_pkg(pkg: &Path, dest: &Path) -> Result<(), PkgError> {
    fs::create_dir_all(dest).map_err(PkgError::Io)?;
    let mut file = File::open(pkg).map_err(PkgError::Io)?;
    let payload = xar_locate_member(&mut file, "Payload")?;
    file.seek(SeekFrom::Start(payload.offset))
        .map_err(PkgError::Io)?;
    let limited = file.take(payload.length);
    extract_pbzx_odc(limited, dest)?;
    Ok(())
}

/// One file member inside a XAR archive.
#[derive(Debug, Clone)]
struct XarMember {
    offset: u64,
    length: u64,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum PkgError {
    #[error("pkg I/O: {0}")]
    Io(#[from] io::Error),
    #[error("{0}")]
    Format(String),
}

fn xar_locate_member(file: &mut File, want: &str) -> Result<XarMember, PkgError> {
    let mut hdr = [0_u8; 28];
    file.read_exact(&mut hdr).map_err(PkgError::Io)?;
    if hdr.get(0..4) != Some(b"xar!") {
        return Err(PkgError::Format(
            "not a XAR package (missing xar! magic): expected Apple flat .pkg".into(),
        ));
    }
    let header_size = u16::from_be_bytes([
        *hdr.get(4).unwrap_or(&0),
        *hdr.get(5).unwrap_or(&0),
    ]);
    let toc_compressed = {
        let mut a = [0_u8; 8];
        if let Some(s) = hdr.get(8..16) {
            a.copy_from_slice(s);
        }
        u64::from_be_bytes(a)
    };
    let toc_uncompressed = {
        let mut a = [0_u8; 8];
        if let Some(s) = hdr.get(16..24) {
            a.copy_from_slice(s);
        }
        u64::from_be_bytes(a)
    };
    let _ = toc_uncompressed;
    if header_size < 28 {
        return Err(PkgError::Format(format!(
            "xar header_size too small ({header_size})"
        )));
    }
    // Skip any extra header bytes beyond the 28 we already read.
    let extra = u64::from(header_size).saturating_sub(28);
    if extra > 0 {
        file.seek(SeekFrom::Current(i64::try_from(extra).map_err(|_| {
            PkgError::Format("xar header_size overflow".into())
        })?))
        .map_err(PkgError::Io)?;
    }

    let mut toc_z = vec![
        0_u8;
        usize::try_from(toc_compressed).map_err(|_| {
            PkgError::Format("toc_compressed too large".into())
        })?
    ];
    file.read_exact(&mut toc_z).map_err(PkgError::Io)?;
    let mut decoder = ZlibDecoder::new(toc_z.as_slice());
    let mut toc = Vec::new();
    decoder.read_to_end(&mut toc).map_err(|e| {
        PkgError::Format(format!("xar TOC zlib decompress failed: {e}"))
    })?;
    let toc_str = String::from_utf8_lossy(&toc);
    let heap_base = u64::from(header_size).saturating_add(toc_compressed);
    let member = parse_xar_toc_member(&toc_str, want).ok_or_else(|| {
        PkgError::Format(format!(
            "xar TOC has no member {want:?} (need CLTools flat package Payload)"
        ))
    })?;
    Ok(XarMember {
        offset: heap_base.saturating_add(member.offset),
        length: member.length,
    })
}

fn parse_xar_toc_member(toc: &str, want: &str) -> Option<XarMember> {
    // Minimal XML scan: <file …> … <name>Payload</name> … <offset>N</offset><length>M</length>
    let mut search = toc;
    while let Some(file_start) = search.find("<file") {
        let rest = search.get(file_start..)?;
        let end_rel = rest.find("</file>")?;
        let block = rest.get(..end_rel.saturating_add(7))?;
        search = rest.get(end_rel.saturating_add(7)..)?;

        let name = xml_tag_text(block, "name")?;
        if name != want {
            continue;
        }
        let offset: u64 = xml_tag_text(block, "offset")?.parse().ok()?;
        let length: u64 = xml_tag_text(block, "length")?.parse().ok()?;
        return Some(XarMember { offset, length });
    }
    None
}

fn xml_tag_text<'a>(block: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = block.find(&open)?.saturating_add(open.len());
    let rest = block.get(start..)?;
    let end = rest.find(&close)?;
    rest.get(..end).map(str::trim)
}

/// pbzx → stream of odc cpio bytes → extract into `dest`.
fn extract_pbzx_odc<R: Read>(mut input: R, dest: &Path) -> Result<(), PkgError> {
    let mut magic = [0_u8; 4];
    input.read_exact(&mut magic).map_err(PkgError::Io)?;
    if &magic != b"pbzx" {
        return Err(PkgError::Format(format!(
            "Payload is not pbzx (got {magic:02x?}); unsupported package compression"
        )));
    }
    let mut flags = [0_u8; 8];
    input.read_exact(&mut flags).map_err(PkgError::Io)?;
    let _ = flags;

    // Feed decompressed xz chunks into a single odc parser.
    let mut parser = OdcCpioExtractor::new(dest);
    let mut chunks = 0_u32;
    loop {
        let mut hdr = [0_u8; 16];
        match input.read_exact(&mut hdr) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(PkgError::Io(e)),
        }
        let xz_size = {
            let mut a = [0_u8; 8];
            a.copy_from_slice(hdr.get(8..16).ok_or_else(|| {
                PkgError::Format("pbzx chunk header truncated".into())
            })?);
            u64::from_be_bytes(a)
        };
        if xz_size == 0 {
            break;
        }
        let xz_len = usize::try_from(xz_size).map_err(|_| {
            PkgError::Format(format!("pbzx xz chunk too large ({xz_size})"))
        })?;

        // Read exactly one xz frame and decompress.
        let mut xz_buf = vec![0_u8; xz_len];
        input.read_exact(&mut xz_buf).map_err(PkgError::Io)?;
        if xz_buf.get(..6) != Some(&[0xfd, b'7', b'z', b'X', b'Z', 0x00]) {
            return Err(PkgError::Format(format!(
                "pbzx chunk {chunks} is not xz (head {:02x?})",
                xz_buf.get(..6).unwrap_or(&[])
            )));
        }
        let mut decoder = XzDecoder::new(xz_buf.as_slice());
        let mut plain = Vec::new();
        decoder.read_to_end(&mut plain).map_err(|e| {
            PkgError::Format(format!("xz decompress chunk {chunks}: {e}"))
        })?;
        parser.push(&plain)?;
        chunks = chunks.saturating_add(1);
    }
    parser.finish()?;
    if chunks == 0 {
        return Err(PkgError::Format(
            "pbzx contained no xz chunks".into(),
        ));
    }
    Ok(())
}

/// Streaming extractor for **odc** (`070707`) cpio archives.
struct OdcCpioExtractor {
    dest: PathBuf,
    /// Bytes not yet consumed (header/name/data spanning push boundaries).
    buf: Vec<u8>,
    entries: u32,
}

impl OdcCpioExtractor {
    fn new(dest: &Path) -> Self {
        Self {
            dest: dest.to_path_buf(),
            buf: Vec::new(),
            entries: 0,
        }
    }

    fn push(&mut self, data: &[u8]) -> Result<(), PkgError> {
        self.buf.extend_from_slice(data);
        loop {
            if !self.consume_one()? {
                break;
            }
        }
        Ok(())
    }

    fn finish(&mut self) -> Result<(), PkgError> {
        while self.consume_one()? {}
        if self.entries == 0 {
            return Err(PkgError::Format(
                "odc cpio produced zero entries".into(),
            ));
        }
        Ok(())
    }

    /// Returns true if one full entry was consumed.
    fn consume_one(&mut self) -> Result<bool, PkgError> {
        // odc header is 76 bytes of ASCII octal fields.
        const HDR: usize = 76;
        if self.buf.len() < HDR {
            return Ok(false);
        }
        let magic = self.buf.get(0..6).unwrap_or(b"");
        if magic != b"070707" {
            // TRAILER!!! ends archive; ignore trailing garbage.
            if self.buf.windows(6).any(|w| w == b"070707") {
                return Err(PkgError::Format(format!(
                    "odc cpio desync (magic {:02x?}) after {} entries",
                    magic, self.entries
                )));
            }
            self.buf.clear();
            return Ok(false);
        }

        let namesize = oct_field(&self.buf, 59, 6)?;
        let filesize = oct_field(&self.buf, 65, 11)?;
        let mode = oct_field(&self.buf, 18, 6)?;
        let name_len = usize::try_from(namesize).map_err(|_| {
            PkgError::Format("odc namesize overflow".into())
        })?;
        let data_len = usize::try_from(filesize).map_err(|_| {
            PkgError::Format("odc filesize overflow".into())
        })?;
        let total = HDR
            .checked_add(name_len)
            .and_then(|n| n.checked_add(data_len))
            .ok_or_else(|| PkgError::Format("odc entry size overflow".into()))?;
        if self.buf.len() < total {
            return Ok(false);
        }

        let name_bytes = self.buf.get(HDR..HDR.saturating_add(name_len)).ok_or_else(|| {
            PkgError::Format("odc name slice".into())
        })?;
        // namesize includes trailing NUL
        let name_end = name_bytes
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(name_bytes.len());
        let name = std::str::from_utf8(name_bytes.get(..name_end).unwrap_or(b""))
            .map_err(|e| PkgError::Format(format!("odc name utf-8: {e}")))?;

        if name == "TRAILER!!!" {
            self.buf.drain(..total);
            return Ok(true);
        }

        let data_start = HDR.saturating_add(name_len);
        let data = self
            .buf
            .get(data_start..data_start.saturating_add(data_len))
            .ok_or_else(|| PkgError::Format("odc data slice".into()))?
            .to_vec();

        self.write_entry(name, mode, &data)?;
        self.buf.drain(..total);
        self.entries = self.entries.saturating_add(1);
        Ok(true)
    }

    fn write_entry(&self, name: &str, mode: u64, data: &[u8]) -> Result<(), PkgError> {
        // Skip unsafe paths.
        let rel = name.trim_start_matches("./");
        if rel.is_empty() || rel.starts_with('/') || rel.contains("..") {
            return Ok(());
        }
        let path = self.dest.join(rel);
        let file_type = mode & 0o170_000;
        match file_type {
            0o040_000 => {
                fs::create_dir_all(&path).map_err(PkgError::Io)?;
            }
            0o120_000 => {
                // symlink: data is target path
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent).map_err(PkgError::Io)?;
                }
                let target = std::str::from_utf8(data).map_err(|e| {
                    PkgError::Format(format!("symlink target utf-8: {e}"))
                })?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::symlink;
                    if path.exists() || path.symlink_metadata().is_ok() {
                        drop(fs::remove_file(&path));
                    }
                    symlink(target, &path).map_err(PkgError::Io)?;
                }
                #[cfg(not(unix))]
                {
                    let _ = target;
                    fs::write(&path, data).map_err(PkgError::Io)?;
                }
            }
            _ => {
                // regular file (and treat others as files)
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent).map_err(PkgError::Io)?;
                }
                let mut f = File::create(&path).map_err(PkgError::Io)?;
                f.write_all(data).map_err(PkgError::Io)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mode_bits = u32::try_from(mode & 0o7777).unwrap_or(0o644);
                    let perms = fs::Permissions::from_mode(mode_bits);
                    fs::set_permissions(&path, perms).map_err(PkgError::Io)?;
                }
            }
        }
        Ok(())
    }
}

fn oct_field(buf: &[u8], start: usize, len: usize) -> Result<u64, PkgError> {
    let end = start.saturating_add(len);
    let slice = buf.get(start..end).ok_or_else(|| {
        PkgError::Format("odc field out of range".into())
    })?;
    let s = std::str::from_utf8(slice)
        .map_err(|e| PkgError::Format(format!("odc field utf-8: {e}")))?
        .trim();
    if s.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(s, 8).map_err(|e| {
        PkgError::Format(format!("odc octal parse {s:?}: {e}"))
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn parse_toc_payload_member() {
        let toc = r#"
        <xar><toc>
          <file id="1">
            <name>Payload</name>
            <type>file</type>
            <offset>276</offset>
            <length>100</length>
          </file>
          <file id="2">
            <name>Bom</name>
            <offset>400</offset>
            <length>10</length>
          </file>
        </toc></xar>
        "#;
        let m = parse_xar_toc_member(toc, "Payload").expect("payload");
        assert_eq!(m.offset, 276);
        assert_eq!(m.length, 100);
    }

    fn push_odc_hdr(out: &mut Vec<u8>, mode: &str, name: &str, data: &[u8]) {
        let namesize = u32::try_from(name.len().saturating_add(1)).expect("namesize");
        let filesize = u32::try_from(data.len()).expect("filesize");
        let mode_v = u32::from_str_radix(mode, 8).expect("mode");
        let h = format!(
            "070707{:06o}{:06o}{:06o}{:06o}{:06o}{:06o}{:06o}{:011o}{:06o}{:011o}",
            0u32, 1u32, mode_v, 0u32, 0u32, 1u32, 0u32, 0u32, namesize, filesize,
        );
        assert_eq!(h.len(), 76, "hdr len {}", h.len());
        out.extend_from_slice(h.as_bytes());
        out.extend_from_slice(name.as_bytes());
        out.push(0);
        out.extend_from_slice(data);
    }

    /// Real CLT package from cache (when present after swscan download).
    #[test]
    #[ignore = "slow: full CLTools_Executables extract ~3GB"]
    fn extract_cached_cltools_pkg() {
        let pkg = PathBuf::from(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../.kh/data/cache/downloads/CLTools_Executables_Universal.pkg"
        ));
        if !pkg.is_file() {
            eprintln!("skip: no cached pkg at {}", pkg.display());
            return;
        }
        let dest = std::env::temp_dir().join(format!(
            "kh-clt-extract-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs())
        ));
        drop(fs::remove_dir_all(&dest));
        extract_apple_pkg(&pkg, &dest).expect("extract");
        let git = dest.join("Library/Developer/CommandLineTools/usr/bin/git");
        assert!(git.is_file(), "missing {}", git.display());
        eprintln!("ok git at {}", git.display());
        drop(fs::remove_dir_all(&dest));
    }

    #[test]
    fn odc_extract_tiny_archive() {
        let mut arc = Vec::new();
        push_odc_hdr(&mut arc, "040755", "./tiny-dir", b"");
        push_odc_hdr(&mut arc, "100644", "./tiny-dir/hello.txt", b"hi\n");
        push_odc_hdr(&mut arc, "000000", "TRAILER!!!", b"");

        let dest = std::env::temp_dir().join(format!(
            "kh-odc-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs())
        ));
        drop(fs::remove_dir_all(&dest));
        fs::create_dir_all(&dest).expect("dest");
        let mut p = OdcCpioExtractor::new(&dest);
        p.push(&arc).expect("push");
        p.finish().expect("finish");
        assert_eq!(
            fs::read_to_string(dest.join("tiny-dir/hello.txt")).expect("read"),
            "hi\n"
        );
        drop(fs::remove_dir_all(&dest));
    }
}
