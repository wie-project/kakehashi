//! Synthetic license-clean Mach-O arm64 fixtures (generated, not from Apple).
//!
//! Used by unit tests and to produce checked-in binaries under `tests/fixtures/`.

/// Builds a minimal little-endian `MH_EXECUTE` arm64 Mach-O with custom text.
///
/// Layout:
/// - `mach_header_64`
/// - `LC_SEGMENT_64` `__PAGEZERO` (null-catch, 4 GiB)
/// - `LC_SEGMENT_64` `__TEXT` with one `__text` section
/// - `LC_UUID`
/// - `LC_LOAD_DYLIB` `/usr/lib/libSystem.B.dylib`
/// - `LC_MAIN`
///
/// `text` is raw AArch64 machine code (+ optional embedded data) placed at the
/// start of the `__text` section. Not a full dyld-linked macOS binary.
#[must_use]
#[allow(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::items_after_statements
)]
pub fn arm64_execute_with_text(text: &[u8]) -> Vec<u8> {
    const MH_MAGIC_64: u32 = 0xfeed_facf;
    const CPU_TYPE_ARM64: u32 = 0x0100_000c;
    const CPU_SUBTYPE_ARM64_ALL: u32 = 0;
    const MH_EXECUTE: u32 = 0x2;
    const MH_NOUNDEFS: u32 = 0x1;
    const MH_PIE: u32 = 0x0020_0000;
    const LC_SEGMENT_64: u32 = 0x19;
    const LC_UUID: u32 = 0x1b;
    const LC_LOAD_DYLIB: u32 = 0xc;
    const LC_MAIN: u32 = 0x28 | 0x8000_0000;
    const VM_PROT_READ: u32 = 0x1;
    const VM_PROT_EXECUTE: u32 = 0x4;
    const SEG_CMD: u32 = 72;
    const SECT_64: u32 = 80;

    let dylib_path = b"/usr/lib/libSystem.B.dylib\0";
    let dylib_path_pad = align8(dylib_path.len());
    let dylib_cmdsize = 24 + dylib_path_pad;

    let text_seg_cmdsize = SEG_CMD + SECT_64;
    let pagezero_cmdsize = SEG_CMD;
    let uuid_cmdsize: u32 = 24;
    let main_cmdsize: u32 = 24;

    let ncmds = 5_u32;
    let sizeofcmds = pagezero_cmdsize
        + text_seg_cmdsize
        + uuid_cmdsize
        + u32::try_from(dylib_cmdsize).unwrap_or(0)
        + main_cmdsize;

    let header_size = 32_u64;
    let load_end = header_size + u64::from(sizeofcmds);
    let text_fileoff = align_u64(load_end, 16);
    let text_filesize = u64::try_from(text.len()).unwrap_or(0);
    // Pad section to at least 16 bytes for alignment friendliness.
    let text_filesize = text_filesize.max(16);
    let file_end = text_fileoff + text_filesize;

    let text_vmaddr = 0x0000_0001_0000_0000_u64;
    let text_vmsize = 0x4000_u64;
    let entryoff = text_fileoff;

    let mut buf = Vec::with_capacity(usize::try_from(file_end).unwrap_or(512));

    write_u32(&mut buf, MH_MAGIC_64);
    write_u32(&mut buf, CPU_TYPE_ARM64);
    write_u32(&mut buf, CPU_SUBTYPE_ARM64_ALL);
    write_u32(&mut buf, MH_EXECUTE);
    write_u32(&mut buf, ncmds);
    write_u32(&mut buf, sizeofcmds);
    write_u32(&mut buf, MH_NOUNDEFS | MH_PIE);
    write_u32(&mut buf, 0);

    write_u32(&mut buf, LC_SEGMENT_64);
    write_u32(&mut buf, pagezero_cmdsize);
    write_segname(&mut buf, b"__PAGEZERO");
    write_u64(&mut buf, 0);
    write_u64(&mut buf, 0x0000_0001_0000_0000);
    write_u64(&mut buf, 0);
    write_u64(&mut buf, 0);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0);

    write_u32(&mut buf, LC_SEGMENT_64);
    write_u32(&mut buf, text_seg_cmdsize);
    write_segname(&mut buf, b"__TEXT");
    write_u64(&mut buf, text_vmaddr);
    write_u64(&mut buf, text_vmsize);
    write_u64(&mut buf, 0);
    write_u64(&mut buf, file_end);
    write_u32(&mut buf, VM_PROT_READ | VM_PROT_EXECUTE);
    write_u32(&mut buf, VM_PROT_READ | VM_PROT_EXECUTE);
    write_u32(&mut buf, 1);
    write_u32(&mut buf, 0);

    write_sectname(&mut buf, b"__text");
    write_segname(&mut buf, b"__TEXT");
    write_u64(&mut buf, text_vmaddr);
    write_u64(&mut buf, text_filesize);
    write_u32(&mut buf, u32::try_from(text_fileoff).unwrap_or(0));
    write_u32(&mut buf, 2);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0x8000_0400);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0);

    write_u32(&mut buf, LC_UUID);
    write_u32(&mut buf, uuid_cmdsize);
    buf.extend_from_slice(&[
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF,
    ]);

    write_u32(&mut buf, LC_LOAD_DYLIB);
    write_u32(&mut buf, u32::try_from(dylib_cmdsize).unwrap_or(0));
    write_u32(&mut buf, 24);
    write_u32(&mut buf, 2);
    write_u32(&mut buf, 0x0001_0000);
    write_u32(&mut buf, 0x0001_0000);
    buf.extend_from_slice(dylib_path);
    while !buf.len().is_multiple_of(8) {
        buf.push(0);
    }

    write_u32(&mut buf, LC_MAIN);
    write_u32(&mut buf, main_cmdsize);
    write_u64(&mut buf, entryoff);
    write_u64(&mut buf, 0);

    let target = usize::try_from(text_fileoff).unwrap_or(buf.len());
    if buf.len() < target {
        buf.resize(target, 0);
    }
    buf.extend_from_slice(text);
    let target = usize::try_from(file_end).unwrap_or(buf.len());
    if buf.len() < target {
        buf.resize(target, 0);
    }
    buf
}

/// Preferred TEXT VA of [`arm64_dylib_add`] (and `_kh_add` n_value).
pub const LIBKH_ADD_TEXT_VA: u64 = 0x0000_0002_0000_0000;

/// Preferred GOT VA of [`call_dylib_exit`] (`__DATA,__got`).
pub const CALL_DYLIB_GOT_VA: u64 = 0x0000_0001_0000_4000;

/// Install name / sibling path for the synthetic add dylib.
pub const LIBKH_ADD_INSTALL_NAME: &str = "@executable_path/libkh_add.dylib";

/// Symbol name exported by [`arm64_dylib_add`] and imported by [`call_dylib_exit`].
pub const KH_ADD_SYMBOL: &str = "_kh_add";

/// Synthetic `MH_DYLIB`: exports `_kh_add` as `add w0,w0,w1; ret`.
///
/// Preferred load base [`LIBKH_ADD_TEXT_VA`]. Leaf — no `LC_LOAD_DYLIB`.
#[must_use]
#[allow(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::items_after_statements,
    clippy::too_many_lines
)]
pub fn arm64_dylib_add() -> Vec<u8> {
    const MH_MAGIC_64: u32 = 0xfeed_facf;
    const CPU_TYPE_ARM64: u32 = 0x0100_000c;
    const MH_DYLIB: u32 = 0x6;
    const MH_NOUNDEFS: u32 = 0x1;
    const MH_DYLDLINK: u32 = 0x4;
    const LC_SEGMENT_64: u32 = 0x19;
    const LC_ID_DYLIB: u32 = 0xd;
    const LC_SYMTAB: u32 = 0x2;
    const LC_DYSYMTAB: u32 = 0xb;
    const LC_UUID: u32 = 0x1b;
    const VM_PROT_READ: u32 = 0x1;
    const VM_PROT_EXECUTE: u32 = 0x4;
    const SEG_CMD: u32 = 72;
    const SECT_64: u32 = 80;
    const NLIST64: u32 = 16;

    let id_path = LIBKH_ADD_INSTALL_NAME.as_bytes();
    let id_path_nul = {
        let mut v = id_path.to_vec();
        v.push(0);
        v
    };
    let id_path_pad = align8(id_path_nul.len());
    let id_cmdsize = 24 + id_path_pad;

    let text_seg_cmdsize = SEG_CMD + SECT_64;
    let uuid_cmdsize: u32 = 24;
    let symtab_cmdsize: u32 = 24;
    let dysymtab_cmdsize: u32 = 80;

    let ncmds = 5_u32;
    let sizeofcmds = text_seg_cmdsize
        + u32::try_from(id_cmdsize).unwrap_or(0)
        + uuid_cmdsize
        + symtab_cmdsize
        + dysymtab_cmdsize;

    let header_size = 32_u64;
    let load_end = header_size + u64::from(sizeofcmds);
    let text_fileoff = align_u64(load_end, 16);
    // add w0,w0,w1; ret
    let text_code: [u8; 8] = {
        let mut t = [0_u8; 8];
        t[..4].copy_from_slice(&0x0b01_0000_u32.to_le_bytes()); // ADD W0, W0, W1
        t[4..].copy_from_slice(&0xd65f_03c0_u32.to_le_bytes()); // RET
        t
    };
    let text_filesize = 16_u64; // pad to 16 like execute fixtures
    let text_end = text_fileoff + text_filesize;

    // nlist + strtab after text (not necessarily mapped; offsets only).
    let symoff = align_u64(text_end, 8);
    let nsyms = 1_u32;
    let stroff = symoff + u64::from(NLIST64) * u64::from(nsyms);
    // strtab: leading NUL then "_kh_add\0"
    let mut strtab = vec![0_u8];
    strtab.extend_from_slice(KH_ADD_SYMBOL.as_bytes());
    strtab.push(0);
    let strsize = u32::try_from(strtab.len()).unwrap_or(0);
    let file_end = stroff + u64::from(strsize);

    let text_vmaddr = LIBKH_ADD_TEXT_VA;
    let text_vmsize = 0x4000_u64;
    // Section starts at text_fileoff within segment (fileoff 0).
    let text_sect_addr = text_vmaddr + text_fileoff;
    let export_va = text_sect_addr; // first instruction

    let mut buf = Vec::with_capacity(usize::try_from(file_end).unwrap_or(512));

    write_u32(&mut buf, MH_MAGIC_64);
    write_u32(&mut buf, CPU_TYPE_ARM64);
    write_u32(&mut buf, 0); // subtype
    write_u32(&mut buf, MH_DYLIB);
    write_u32(&mut buf, ncmds);
    write_u32(&mut buf, sizeofcmds);
    write_u32(&mut buf, MH_NOUNDEFS | MH_DYLDLINK);
    write_u32(&mut buf, 0);

    // LC_SEGMENT_64 __TEXT
    write_u32(&mut buf, LC_SEGMENT_64);
    write_u32(&mut buf, text_seg_cmdsize);
    write_segname(&mut buf, b"__TEXT");
    write_u64(&mut buf, text_vmaddr);
    write_u64(&mut buf, text_vmsize);
    write_u64(&mut buf, 0); // fileoff
    write_u64(&mut buf, file_end); // include symtab for simple single-file layout
    write_u32(&mut buf, VM_PROT_READ | VM_PROT_EXECUTE);
    write_u32(&mut buf, VM_PROT_READ | VM_PROT_EXECUTE);
    write_u32(&mut buf, 1); // nsects
    write_u32(&mut buf, 0);

    write_sectname(&mut buf, b"__text");
    write_segname(&mut buf, b"__TEXT");
    write_u64(&mut buf, text_sect_addr);
    write_u64(&mut buf, text_filesize);
    write_u32(&mut buf, u32::try_from(text_fileoff).unwrap_or(0));
    write_u32(&mut buf, 2); // align 4
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0x8000_0400); // S_REGULAR | S_ATTR_PURE_INSTRUCTIONS
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0);

    // LC_ID_DYLIB
    write_u32(&mut buf, LC_ID_DYLIB);
    write_u32(&mut buf, u32::try_from(id_cmdsize).unwrap_or(0));
    write_u32(&mut buf, 24); // name offset
    write_u32(&mut buf, 1); // timestamp
    write_u32(&mut buf, 0x0001_0000);
    write_u32(&mut buf, 0x0001_0000);
    buf.extend_from_slice(&id_path_nul);
    while !buf.len().is_multiple_of(8) {
        buf.push(0);
    }

    // LC_UUID
    write_u32(&mut buf, LC_UUID);
    write_u32(&mut buf, uuid_cmdsize);
    buf.extend_from_slice(&[
        0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18, 0x29, 0x3A, 0x4B, 0x5C, 0x6D, 0x7E, 0x8F,
        0x90,
    ]);

    // LC_SYMTAB
    write_u32(&mut buf, LC_SYMTAB);
    write_u32(&mut buf, symtab_cmdsize);
    write_u32(&mut buf, u32::try_from(symoff).unwrap_or(0));
    write_u32(&mut buf, nsyms);
    write_u32(&mut buf, u32::try_from(stroff).unwrap_or(0));
    write_u32(&mut buf, strsize);

    // LC_DYSYMTAB (zeros — realism only)
    write_u32(&mut buf, LC_DYSYMTAB);
    write_u32(&mut buf, dysymtab_cmdsize);
    for _ in 0..18 {
        write_u32(&mut buf, 0);
    }

    // Text payload
    let target = usize::try_from(text_fileoff).unwrap_or(buf.len());
    if buf.len() < target {
        buf.resize(target, 0);
    }
    buf.extend_from_slice(&text_code);
    let target = usize::try_from(text_end).unwrap_or(buf.len());
    if buf.len() < target {
        buf.resize(target, 0);
    }

    // nlist_64 for _kh_add
    let target = usize::try_from(symoff).unwrap_or(buf.len());
    if buf.len() < target {
        buf.resize(target, 0);
    }
    write_u32(&mut buf, 1); // n_strx → "_kh_add"
    buf.push(0x0f); // N_SECT | N_EXT
    buf.push(1); // n_sect = 1 (__text)
    write_u16(&mut buf, 0); // n_desc
    write_u64(&mut buf, export_va);

    let target = usize::try_from(stroff).unwrap_or(buf.len());
    if buf.len() < target {
        buf.resize(target, 0);
    }
    buf.extend_from_slice(&strtab);

    let target = usize::try_from(file_end).unwrap_or(buf.len());
    if buf.len() < target {
        buf.resize(target, 0);
    }
    buf
}

/// Synthetic `MH_EXECUTE`: load `@executable_path/libkh_add.dylib`, call `_kh_add(20,22)`,
/// `exit` with the sum (**42**). Also declares decorative `/usr/lib/libSystem.B.dylib`.
///
/// Requires a sibling `libkh_add.dylib` next to this binary on disk. Main must map at
/// preferred base (slide 0) so fixed `adrp` to [`CALL_DYLIB_GOT_VA`] is valid.
///
/// Includes `LC_DYLD_INFO_ONLY` with a classic non-lazy POINTER bind of `_kh_add`
/// into `__DATA` (segment index 2, offset 0). Nlist undef is retained for tools.
#[must_use]
#[allow(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::items_after_statements,
    clippy::too_many_lines
)]
pub fn call_dylib_exit() -> Vec<u8> {
    const MH_MAGIC_64: u32 = 0xfeed_facf;
    const CPU_TYPE_ARM64: u32 = 0x0100_000c;
    const MH_EXECUTE: u32 = 0x2;
    const MH_NOUNDEFS: u32 = 0x1;
    const MH_PIE: u32 = 0x0020_0000;
    const LC_SEGMENT_64: u32 = 0x19;
    const LC_UUID: u32 = 0x1b;
    const LC_LOAD_DYLIB: u32 = 0xc;
    const LC_SYMTAB: u32 = 0x2;
    const LC_DYLD_INFO_ONLY: u32 = 0x22 | 0x8000_0000;
    const LC_MAIN: u32 = 0x28 | 0x8000_0000;
    const VM_PROT_READ: u32 = 0x1;
    const VM_PROT_WRITE: u32 = 0x2;
    const VM_PROT_EXECUTE: u32 = 0x4;
    const SEG_CMD: u32 = 72;
    const SECT_64: u32 = 80;
    const NLIST64: u32 = 16;
    const DYLD_INFO_CMDSIZE: u32 = 48;

    let kh_path = LIBKH_ADD_INSTALL_NAME.as_bytes();
    let sys_path = b"/usr/lib/libSystem.B.dylib\0";
    let kh_pad = align8(kh_path.len() + 1);
    let sys_pad = align8(sys_path.len());
    let kh_cmdsize = 24 + kh_pad;
    let sys_cmdsize = 24 + sys_pad;

    let pagezero_cmdsize = SEG_CMD;
    let text_seg_cmdsize = SEG_CMD + SECT_64;
    let data_seg_cmdsize = SEG_CMD + SECT_64;
    let uuid_cmdsize: u32 = 24;
    let symtab_cmdsize: u32 = 24;
    let main_cmdsize: u32 = 24;

    // ordinal 1 = libkh_add, seg 2 = __DATA, offset 0 → GOT
    let bind_stream = crate::bind::encode_pointer_bind(1, KH_ADD_SYMBOL, 2, 0);
    let bind_size = u32::try_from(bind_stream.len()).unwrap_or(0);

    let ncmds = 9_u32;
    let sizeofcmds = pagezero_cmdsize
        + text_seg_cmdsize
        + data_seg_cmdsize
        + uuid_cmdsize
        + u32::try_from(kh_cmdsize).unwrap_or(0)
        + u32::try_from(sys_cmdsize).unwrap_or(0)
        + DYLD_INFO_CMDSIZE
        + symtab_cmdsize
        + main_cmdsize;

    let header_size = 32_u64;
    let load_end = header_size + u64::from(sizeofcmds);
    let text_fileoff = align_u64(load_end, 16);

    // Program (7 insns = 28 bytes), pad to 32:
    //   movz w0, #20
    //   movz w1, #22
    //   adrp x16, __got@page
    //   ldr  x16, [x16, __got@pageoff]
    //   blr  x16
    //   movz x16, #1
    //   svc  #0x80
    let text_len = 32_u64;
    let text_end = text_fileoff + text_len;

    let data_fileoff = align_u64(text_end, 8);
    let got_filesize = 8_u64;
    let data_end = data_fileoff + got_filesize;

    let bind_off = align_u64(data_end, 8);
    let bind_end = bind_off + u64::from(bind_size);

    let symoff = align_u64(bind_end, 8);
    let nsyms = 1_u32;
    let stroff = symoff + u64::from(NLIST64) * u64::from(nsyms);
    let mut strtab = vec![0_u8];
    strtab.extend_from_slice(KH_ADD_SYMBOL.as_bytes());
    strtab.push(0);
    let strsize = u32::try_from(strtab.len()).unwrap_or(0);
    let file_end = stroff + u64::from(strsize);

    let text_vmaddr = 0x0000_0001_0000_0000_u64;
    let text_vmsize = 0x4000_u64;
    let data_vmaddr = CALL_DYLIB_GOT_VA;
    let data_vmsize = 0x4000_u64;
    let entryoff = text_fileoff;
    // ADRP is the 3rd instruction → PC = entry_va + 8.
    let entry_va = text_vmaddr + entryoff; // TEXT.fileoff == 0
    let adrp_pc = entry_va + 8;
    let adrp_insn = encode_adrp(16, adrp_pc, data_vmaddr);
    let pageoff = u32::try_from(data_vmaddr & 0xfff).unwrap_or(0);
    let ldr_insn = encode_ldr_x_uoff(16, 16, pageoff);

    let mut text = Vec::with_capacity(32);
    push_u32(&mut text, movz(0, 20));
    push_u32(&mut text, movz(1, 22));
    push_u32(&mut text, adrp_insn);
    push_u32(&mut text, ldr_insn);
    push_u32(&mut text, 0xd63f_0200); // blr x16
    push_u32(&mut text, movz(0x10, 1)); // exit
    push_u32(&mut text, svc80());
    while text.len() < usize::try_from(text_len).unwrap_or(32) {
        text.push(0);
    }

    let mut buf = Vec::with_capacity(usize::try_from(file_end).unwrap_or(512));

    write_u32(&mut buf, MH_MAGIC_64);
    write_u32(&mut buf, CPU_TYPE_ARM64);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, MH_EXECUTE);
    write_u32(&mut buf, ncmds);
    write_u32(&mut buf, sizeofcmds);
    write_u32(&mut buf, MH_NOUNDEFS | MH_PIE);
    write_u32(&mut buf, 0);

    // __PAGEZERO
    write_u32(&mut buf, LC_SEGMENT_64);
    write_u32(&mut buf, pagezero_cmdsize);
    write_segname(&mut buf, b"__PAGEZERO");
    write_u64(&mut buf, 0);
    write_u64(&mut buf, 0x0000_0001_0000_0000);
    write_u64(&mut buf, 0);
    write_u64(&mut buf, 0);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0);

    // __TEXT
    write_u32(&mut buf, LC_SEGMENT_64);
    write_u32(&mut buf, text_seg_cmdsize);
    write_segname(&mut buf, b"__TEXT");
    write_u64(&mut buf, text_vmaddr);
    write_u64(&mut buf, text_vmsize);
    write_u64(&mut buf, 0);
    write_u64(&mut buf, data_fileoff); // up to start of DATA file content
    write_u32(&mut buf, VM_PROT_READ | VM_PROT_EXECUTE);
    write_u32(&mut buf, VM_PROT_READ | VM_PROT_EXECUTE);
    write_u32(&mut buf, 1);
    write_u32(&mut buf, 0);

    write_sectname(&mut buf, b"__text");
    write_segname(&mut buf, b"__TEXT");
    write_u64(&mut buf, text_vmaddr + text_fileoff);
    write_u64(&mut buf, text_len);
    write_u32(&mut buf, u32::try_from(text_fileoff).unwrap_or(0));
    write_u32(&mut buf, 2);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0x8000_0400);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0);

    // __DATA with __got
    write_u32(&mut buf, LC_SEGMENT_64);
    write_u32(&mut buf, data_seg_cmdsize);
    write_segname(&mut buf, b"__DATA");
    write_u64(&mut buf, data_vmaddr);
    write_u64(&mut buf, data_vmsize);
    write_u64(&mut buf, data_fileoff);
    write_u64(&mut buf, got_filesize);
    write_u32(&mut buf, VM_PROT_READ | VM_PROT_WRITE);
    write_u32(&mut buf, VM_PROT_READ | VM_PROT_WRITE);
    write_u32(&mut buf, 1);
    write_u32(&mut buf, 0);

    write_sectname(&mut buf, b"__got");
    write_segname(&mut buf, b"__DATA");
    write_u64(&mut buf, data_vmaddr);
    write_u64(&mut buf, got_filesize);
    write_u32(&mut buf, u32::try_from(data_fileoff).unwrap_or(0));
    write_u32(&mut buf, 3); // align 8
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0x6); // S_NON_LAZY_SYMBOL_POINTERS (decorative)
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0);

    // LC_UUID
    write_u32(&mut buf, LC_UUID);
    write_u32(&mut buf, uuid_cmdsize);
    buf.extend_from_slice(&[
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0,
        0x01,
    ]);

    // LC_LOAD_DYLIB @executable_path/libkh_add.dylib
    write_u32(&mut buf, LC_LOAD_DYLIB);
    write_u32(&mut buf, u32::try_from(kh_cmdsize).unwrap_or(0));
    write_u32(&mut buf, 24);
    write_u32(&mut buf, 2);
    write_u32(&mut buf, 0x0001_0000);
    write_u32(&mut buf, 0x0001_0000);
    buf.extend_from_slice(kh_path);
    buf.push(0);
    while !buf.len().is_multiple_of(8) {
        buf.push(0);
    }

    // LC_LOAD_DYLIB libSystem (decorative)
    write_u32(&mut buf, LC_LOAD_DYLIB);
    write_u32(&mut buf, u32::try_from(sys_cmdsize).unwrap_or(0));
    write_u32(&mut buf, 24);
    write_u32(&mut buf, 2);
    write_u32(&mut buf, 0x0001_0000);
    write_u32(&mut buf, 0x0001_0000);
    buf.extend_from_slice(sys_path);
    while !buf.len().is_multiple_of(8) {
        buf.push(0);
    }

    // LC_DYLD_INFO_ONLY (bind stream only)
    write_u32(&mut buf, LC_DYLD_INFO_ONLY);
    write_u32(&mut buf, DYLD_INFO_CMDSIZE);
    write_u32(&mut buf, 0); // rebase_off
    write_u32(&mut buf, 0); // rebase_size
    write_u32(&mut buf, u32::try_from(bind_off).unwrap_or(0));
    write_u32(&mut buf, bind_size);
    write_u32(&mut buf, 0); // weak_bind_off
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0); // lazy_bind_off
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0); // export_off
    write_u32(&mut buf, 0);

    // LC_SYMTAB
    write_u32(&mut buf, LC_SYMTAB);
    write_u32(&mut buf, symtab_cmdsize);
    write_u32(&mut buf, u32::try_from(symoff).unwrap_or(0));
    write_u32(&mut buf, nsyms);
    write_u32(&mut buf, u32::try_from(stroff).unwrap_or(0));
    write_u32(&mut buf, strsize);

    // LC_MAIN
    write_u32(&mut buf, LC_MAIN);
    write_u32(&mut buf, main_cmdsize);
    write_u64(&mut buf, entryoff);
    write_u64(&mut buf, 0);

    // Text
    let target = usize::try_from(text_fileoff).unwrap_or(buf.len());
    if buf.len() < target {
        buf.resize(target, 0);
    }
    buf.extend_from_slice(&text);

    // GOT zeros
    let target = usize::try_from(data_fileoff).unwrap_or(buf.len());
    if buf.len() < target {
        buf.resize(target, 0);
    }
    buf.extend_from_slice(&[0_u8; 8]);

    // Classic bind opcodes
    let target = usize::try_from(bind_off).unwrap_or(buf.len());
    if buf.len() < target {
        buf.resize(target, 0);
    }
    buf.extend_from_slice(&bind_stream);

    // nlist undefined _kh_add
    let target = usize::try_from(symoff).unwrap_or(buf.len());
    if buf.len() < target {
        buf.resize(target, 0);
    }
    write_u32(&mut buf, 1); // n_strx
    buf.push(0x01); // N_UNDF | N_EXT
    buf.push(0); // NO_SECT
    write_u16(&mut buf, 0);
    write_u64(&mut buf, 0);

    let target = usize::try_from(stroff).unwrap_or(buf.len());
    if buf.len() < target {
        buf.resize(target, 0);
    }
    buf.extend_from_slice(&strtab);

    let target = usize::try_from(file_end).unwrap_or(buf.len());
    if buf.len() < target {
        buf.resize(target, 0);
    }
    buf
}

/// Same program as [`call_dylib_exit`], but linking uses `LC_DYLD_CHAINED_FIXUPS`
/// (`DYLD_CHAINED_PTR_64` bind of `_kh_add` into `__got`) instead of classic
/// bind opcodes.
///
/// GOT on disk holds a chain-encoded bind word (not zeros). Preferred VAs match
/// [`CALL_DYLIB_GOT_VA`] / [`call_dylib_exit`].
#[must_use]
#[allow(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::items_after_statements,
    clippy::too_many_lines
)]
pub fn call_dylib_chained_exit() -> Vec<u8> {
    const MH_MAGIC_64: u32 = 0xfeed_facf;
    const CPU_TYPE_ARM64: u32 = 0x0100_000c;
    const MH_EXECUTE: u32 = 0x2;
    const MH_NOUNDEFS: u32 = 0x1;
    const MH_PIE: u32 = 0x0020_0000;
    const LC_SEGMENT_64: u32 = 0x19;
    const LC_UUID: u32 = 0x1b;
    const LC_LOAD_DYLIB: u32 = 0xc;
    const LC_SYMTAB: u32 = 0x2;
    const LC_DYLD_CHAINED_FIXUPS: u32 = 0x34 | 0x8000_0000;
    const LC_MAIN: u32 = 0x28 | 0x8000_0000;
    const VM_PROT_READ: u32 = 0x1;
    const VM_PROT_WRITE: u32 = 0x2;
    const VM_PROT_EXECUTE: u32 = 0x4;
    const SEG_CMD: u32 = 72;
    const SECT_64: u32 = 80;
    const NLIST64: u32 = 16;
    const LINKEDIT_CMDSIZE: u32 = 16;

    let kh_path = LIBKH_ADD_INSTALL_NAME.as_bytes();
    let sys_path = b"/usr/lib/libSystem.B.dylib\0";
    let kh_pad = align8(kh_path.len() + 1);
    let sys_pad = align8(sys_path.len());
    let kh_cmdsize = 24 + kh_pad;
    let sys_cmdsize = 24 + sys_pad;

    let pagezero_cmdsize = SEG_CMD;
    let text_seg_cmdsize = SEG_CMD + SECT_64;
    let data_seg_cmdsize = SEG_CMD + SECT_64;
    let uuid_cmdsize: u32 = 24;
    let symtab_cmdsize: u32 = 24;
    let main_cmdsize: u32 = 24;

    let text_vmaddr = 0x0000_0001_0000_0000_u64;
    let data_vmaddr = CALL_DYLIB_GOT_VA;
    let preferred_base = text_vmaddr;
    let segment_offset = data_vmaddr.wrapping_sub(preferred_base);

    let fixups_blob = crate::chained::encode_chained_fixups_blob(
        3,
        2,
        segment_offset,
        0x4000,
        0,
        crate::chained::DYLD_CHAINED_PTR_64,
        1,
        KH_ADD_SYMBOL,
    );
    let fixups_size = u32::try_from(fixups_blob.len()).unwrap_or(0);
    let got_chain = crate::chained::encode_ptr_64_bind(0, 0, 0);

    let ncmds = 9_u32;
    let sizeofcmds = pagezero_cmdsize
        + text_seg_cmdsize
        + data_seg_cmdsize
        + uuid_cmdsize
        + u32::try_from(kh_cmdsize).unwrap_or(0)
        + u32::try_from(sys_cmdsize).unwrap_or(0)
        + LINKEDIT_CMDSIZE
        + symtab_cmdsize
        + main_cmdsize;

    let header_size = 32_u64;
    let load_end = header_size + u64::from(sizeofcmds);
    let text_fileoff = align_u64(load_end, 16);
    let text_len = 32_u64;
    let text_end = text_fileoff + text_len;

    let data_fileoff = align_u64(text_end, 8);
    let got_filesize = 8_u64;
    let data_end = data_fileoff + got_filesize;

    let fixups_off = align_u64(data_end, 8);
    let fixups_end = fixups_off + u64::from(fixups_size);

    let symoff = align_u64(fixups_end, 8);
    let nsyms = 1_u32;
    let stroff = symoff + u64::from(NLIST64) * u64::from(nsyms);
    let mut strtab = vec![0_u8];
    strtab.extend_from_slice(KH_ADD_SYMBOL.as_bytes());
    strtab.push(0);
    let strsize = u32::try_from(strtab.len()).unwrap_or(0);
    let file_end = stroff + u64::from(strsize);

    let text_vmsize = 0x4000_u64;
    let data_vmsize = 0x4000_u64;
    let entryoff = text_fileoff;
    let entry_va = text_vmaddr + entryoff;
    let adrp_pc = entry_va + 8;
    let adrp_insn = encode_adrp(16, adrp_pc, data_vmaddr);
    let pageoff = u32::try_from(data_vmaddr & 0xfff).unwrap_or(0);
    let ldr_insn = encode_ldr_x_uoff(16, 16, pageoff);

    let mut text = Vec::with_capacity(32);
    push_u32(&mut text, movz(0, 20));
    push_u32(&mut text, movz(1, 22));
    push_u32(&mut text, adrp_insn);
    push_u32(&mut text, ldr_insn);
    push_u32(&mut text, 0xd63f_0200);
    push_u32(&mut text, movz(0x10, 1));
    push_u32(&mut text, svc80());
    while text.len() < usize::try_from(text_len).unwrap_or(32) {
        text.push(0);
    }

    let mut buf = Vec::with_capacity(usize::try_from(file_end).unwrap_or(512));

    write_u32(&mut buf, MH_MAGIC_64);
    write_u32(&mut buf, CPU_TYPE_ARM64);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, MH_EXECUTE);
    write_u32(&mut buf, ncmds);
    write_u32(&mut buf, sizeofcmds);
    write_u32(&mut buf, MH_NOUNDEFS | MH_PIE);
    write_u32(&mut buf, 0);

    write_u32(&mut buf, LC_SEGMENT_64);
    write_u32(&mut buf, pagezero_cmdsize);
    write_segname(&mut buf, b"__PAGEZERO");
    write_u64(&mut buf, 0);
    write_u64(&mut buf, 0x0000_0001_0000_0000);
    write_u64(&mut buf, 0);
    write_u64(&mut buf, 0);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0);

    write_u32(&mut buf, LC_SEGMENT_64);
    write_u32(&mut buf, text_seg_cmdsize);
    write_segname(&mut buf, b"__TEXT");
    write_u64(&mut buf, text_vmaddr);
    write_u64(&mut buf, text_vmsize);
    write_u64(&mut buf, 0);
    write_u64(&mut buf, data_fileoff);
    write_u32(&mut buf, VM_PROT_READ | VM_PROT_EXECUTE);
    write_u32(&mut buf, VM_PROT_READ | VM_PROT_EXECUTE);
    write_u32(&mut buf, 1);
    write_u32(&mut buf, 0);

    write_sectname(&mut buf, b"__text");
    write_segname(&mut buf, b"__TEXT");
    write_u64(&mut buf, text_vmaddr + text_fileoff);
    write_u64(&mut buf, text_len);
    write_u32(&mut buf, u32::try_from(text_fileoff).unwrap_or(0));
    write_u32(&mut buf, 2);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0x8000_0400);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0);

    write_u32(&mut buf, LC_SEGMENT_64);
    write_u32(&mut buf, data_seg_cmdsize);
    write_segname(&mut buf, b"__DATA");
    write_u64(&mut buf, data_vmaddr);
    write_u64(&mut buf, data_vmsize);
    write_u64(&mut buf, data_fileoff);
    write_u64(&mut buf, got_filesize);
    write_u32(&mut buf, VM_PROT_READ | VM_PROT_WRITE);
    write_u32(&mut buf, VM_PROT_READ | VM_PROT_WRITE);
    write_u32(&mut buf, 1);
    write_u32(&mut buf, 0);

    write_sectname(&mut buf, b"__got");
    write_segname(&mut buf, b"__DATA");
    write_u64(&mut buf, data_vmaddr);
    write_u64(&mut buf, got_filesize);
    write_u32(&mut buf, u32::try_from(data_fileoff).unwrap_or(0));
    write_u32(&mut buf, 3);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0x6);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0);

    write_u32(&mut buf, LC_UUID);
    write_u32(&mut buf, uuid_cmdsize);
    buf.extend_from_slice(&[
        0xC1, 0xA1, 0xED, 0xF1, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0,
        0x11,
    ]);

    write_u32(&mut buf, LC_LOAD_DYLIB);
    write_u32(&mut buf, u32::try_from(kh_cmdsize).unwrap_or(0));
    write_u32(&mut buf, 24);
    write_u32(&mut buf, 2);
    write_u32(&mut buf, 0x0001_0000);
    write_u32(&mut buf, 0x0001_0000);
    buf.extend_from_slice(kh_path);
    buf.push(0);
    while !buf.len().is_multiple_of(8) {
        buf.push(0);
    }

    write_u32(&mut buf, LC_LOAD_DYLIB);
    write_u32(&mut buf, u32::try_from(sys_cmdsize).unwrap_or(0));
    write_u32(&mut buf, 24);
    write_u32(&mut buf, 2);
    write_u32(&mut buf, 0x0001_0000);
    write_u32(&mut buf, 0x0001_0000);
    buf.extend_from_slice(sys_path);
    while !buf.len().is_multiple_of(8) {
        buf.push(0);
    }

    write_u32(&mut buf, LC_DYLD_CHAINED_FIXUPS);
    write_u32(&mut buf, LINKEDIT_CMDSIZE);
    write_u32(&mut buf, u32::try_from(fixups_off).unwrap_or(0));
    write_u32(&mut buf, fixups_size);

    write_u32(&mut buf, LC_SYMTAB);
    write_u32(&mut buf, symtab_cmdsize);
    write_u32(&mut buf, u32::try_from(symoff).unwrap_or(0));
    write_u32(&mut buf, nsyms);
    write_u32(&mut buf, u32::try_from(stroff).unwrap_or(0));
    write_u32(&mut buf, strsize);

    write_u32(&mut buf, LC_MAIN);
    write_u32(&mut buf, main_cmdsize);
    write_u64(&mut buf, entryoff);
    write_u64(&mut buf, 0);

    let target = usize::try_from(text_fileoff).unwrap_or(buf.len());
    if buf.len() < target {
        buf.resize(target, 0);
    }
    buf.extend_from_slice(&text);

    let target = usize::try_from(data_fileoff).unwrap_or(buf.len());
    if buf.len() < target {
        buf.resize(target, 0);
    }
    buf.extend_from_slice(&got_chain.to_le_bytes());

    let target = usize::try_from(fixups_off).unwrap_or(buf.len());
    if buf.len() < target {
        buf.resize(target, 0);
    }
    buf.extend_from_slice(&fixups_blob);

    let target = usize::try_from(symoff).unwrap_or(buf.len());
    if buf.len() < target {
        buf.resize(target, 0);
    }
    write_u32(&mut buf, 1);
    buf.push(0x01);
    buf.push(0);
    write_u16(&mut buf, 0);
    write_u64(&mut buf, 0);

    let target = usize::try_from(stroff).unwrap_or(buf.len());
    if buf.len() < target {
        buf.resize(target, 0);
    }
    buf.extend_from_slice(&strtab);

    let target = usize::try_from(file_end).unwrap_or(buf.len());
    if buf.len() < target {
        buf.resize(target, 0);
    }
    buf
}

/// `ADRP Xd, #page_delta` where `page_delta` is computed from `pc` to `target`.
#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]
fn encode_adrp(rd: u32, pc: u64, target: u64) -> u32 {
    let page_pc = pc & !0xfff;
    let page_tgt = target & !0xfff;
    let imm = (page_tgt as i64 - page_pc as i64) >> 12;
    let imm_u = (imm as u32) & 0x001f_ffff;
    let immlo = imm_u & 0x3;
    let immhi = (imm_u >> 2) & 0x7_ffff;
    0x9000_0000 | (immlo << 29) | (immhi << 5) | (rd & 0x1f)
}

/// `LDR Xt, [Xn, #imm]` unsigned offset (byte offset, multiple of 8).
#[allow(clippy::integer_division)]
const fn encode_ldr_x_uoff(rt: u32, rn: u32, imm: u32) -> u32 {
    let imm12 = (imm / 8) & 0xfff;
    0xf940_0000 | (imm12 << 10) | ((rn & 0x1f) << 5) | (rt & 0x1f)
}

fn write_u16(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_le_bytes());
}

/// Preferred TEXT base of [`arm64_dylib_ctor`].
pub const LIBKH_CTOR_TEXT_VA: u64 = 0x0000_0003_0000_0000;

/// Install name for the constructor dylib fixture.
pub const LIBKH_CTOR_INSTALL_NAME: &str = "@executable_path/libkh_ctor.dylib";

/// Synthetic `MH_DYLIB` with one `S_MOD_INIT_FUNC_POINTERS` entry.
///
/// The constructor writes `"ctor\\n"` to fd 1 and returns (proves Phase 7
/// initializers run before `LC_MAIN`).
#[must_use]
#[allow(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::integer_division,
    clippy::items_after_statements,
    clippy::too_many_lines
)]
pub fn arm64_dylib_ctor() -> Vec<u8> {
    const MH_MAGIC_64: u32 = 0xfeed_facf;
    const CPU_TYPE_ARM64: u32 = 0x0100_000c;
    const MH_DYLIB: u32 = 0x6;
    const MH_NOUNDEFS: u32 = 0x1;
    const MH_DYLDLINK: u32 = 0x4;
    const LC_SEGMENT_64: u32 = 0x19;
    const LC_ID_DYLIB: u32 = 0xd;
    const LC_UUID: u32 = 0x1b;
    const VM_PROT_READ: u32 = 0x1;
    const VM_PROT_WRITE: u32 = 0x2;
    const VM_PROT_EXECUTE: u32 = 0x4;
    const SEG_CMD: u32 = 72;
    const SECT_64: u32 = 80;
    const S_MOD_INIT_FUNC_POINTERS: u32 = 0x9;

    let id_path = LIBKH_CTOR_INSTALL_NAME.as_bytes();
    let mut id_nul = id_path.to_vec();
    id_nul.push(0);
    let id_pad = align8(id_nul.len());
    let id_cmdsize = 24 + id_pad;

    let text_seg_cmdsize = SEG_CMD + SECT_64;
    let data_seg_cmdsize = SEG_CMD + SECT_64;
    let uuid_cmdsize: u32 = 24;

    let ncmds = 4_u32;
    let sizeofcmds =
        text_seg_cmdsize + data_seg_cmdsize + u32::try_from(id_cmdsize).unwrap_or(0) + uuid_cmdsize;

    let header_size = 32_u64;
    let load_end = header_size + u64::from(sizeofcmds);
    let text_fileoff = align_u64(load_end, 16);

    // write(1, "ctor\n", 5); ret
    // movz x0,#1; adr x1,msg; movz x2,#5; movz x16,#4; svc; ret; pad; "ctor\n"
    let mut text = Vec::with_capacity(48);
    push_u32(&mut text, movz(0, 1));
    let adr_idx = text.len() / 4;
    push_u32(&mut text, 0); // placeholder ADR x1
    push_u32(&mut text, movz(2, 5));
    push_u32(&mut text, movz(0x10, 4));
    push_u32(&mut text, svc80());
    push_u32(&mut text, 0xd65f_03c0); // ret
    while !text.len().is_multiple_of(4) {
        text.push(0);
    }
    let msg_off = text.len();
    text.extend_from_slice(b"ctor\n");
    while !text.len().is_multiple_of(8) {
        text.push(0);
    }
    let path_imm =
        i32::try_from(msg_off).unwrap_or(0) - i32::try_from(adr_idx.saturating_mul(4)).unwrap_or(0);
    patch_u32(&mut text, adr_idx, adr(1, path_imm));

    let text_len = u64::try_from(text.len()).unwrap_or(0);
    let text_end = text_fileoff + text_len;
    let data_fileoff = align_u64(text_end, 8);
    let init_filesize = 8_u64;
    let file_end = data_fileoff + init_filesize;

    let text_vmaddr = LIBKH_CTOR_TEXT_VA;
    let text_vmsize = 0x4000_u64;
    let data_vmaddr = LIBKH_CTOR_TEXT_VA + 0x4000;
    let data_vmsize = 0x4000_u64;
    let ctor_va = text_vmaddr + text_fileoff;

    let mut buf = Vec::with_capacity(usize::try_from(file_end).unwrap_or(512));

    write_u32(&mut buf, MH_MAGIC_64);
    write_u32(&mut buf, CPU_TYPE_ARM64);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, MH_DYLIB);
    write_u32(&mut buf, ncmds);
    write_u32(&mut buf, sizeofcmds);
    write_u32(&mut buf, MH_NOUNDEFS | MH_DYLDLINK);
    write_u32(&mut buf, 0);

    // __TEXT
    write_u32(&mut buf, LC_SEGMENT_64);
    write_u32(&mut buf, text_seg_cmdsize);
    write_segname(&mut buf, b"__TEXT");
    write_u64(&mut buf, text_vmaddr);
    write_u64(&mut buf, text_vmsize);
    write_u64(&mut buf, 0);
    write_u64(&mut buf, data_fileoff);
    write_u32(&mut buf, VM_PROT_READ | VM_PROT_EXECUTE);
    write_u32(&mut buf, VM_PROT_READ | VM_PROT_EXECUTE);
    write_u32(&mut buf, 1);
    write_u32(&mut buf, 0);

    write_sectname(&mut buf, b"__text");
    write_segname(&mut buf, b"__TEXT");
    write_u64(&mut buf, ctor_va);
    write_u64(&mut buf, text_len);
    write_u32(&mut buf, u32::try_from(text_fileoff).unwrap_or(0));
    write_u32(&mut buf, 2);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0x8000_0400);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0);

    // __DATA,__mod_init_func
    write_u32(&mut buf, LC_SEGMENT_64);
    write_u32(&mut buf, data_seg_cmdsize);
    write_segname(&mut buf, b"__DATA");
    write_u64(&mut buf, data_vmaddr);
    write_u64(&mut buf, data_vmsize);
    write_u64(&mut buf, data_fileoff);
    write_u64(&mut buf, init_filesize);
    write_u32(&mut buf, VM_PROT_READ | VM_PROT_WRITE);
    write_u32(&mut buf, VM_PROT_READ | VM_PROT_WRITE);
    write_u32(&mut buf, 1);
    write_u32(&mut buf, 0);

    write_sectname(&mut buf, b"__mod_init_func");
    write_segname(&mut buf, b"__DATA");
    write_u64(&mut buf, data_vmaddr);
    write_u64(&mut buf, init_filesize);
    write_u32(&mut buf, u32::try_from(data_fileoff).unwrap_or(0));
    write_u32(&mut buf, 3);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, S_MOD_INIT_FUNC_POINTERS);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0);

    // LC_ID_DYLIB
    write_u32(&mut buf, LC_ID_DYLIB);
    write_u32(&mut buf, u32::try_from(id_cmdsize).unwrap_or(0));
    write_u32(&mut buf, 24);
    write_u32(&mut buf, 1);
    write_u32(&mut buf, 0x0001_0000);
    write_u32(&mut buf, 0x0001_0000);
    buf.extend_from_slice(&id_nul);
    while !buf.len().is_multiple_of(8) {
        buf.push(0);
    }

    // LC_UUID
    write_u32(&mut buf, LC_UUID);
    write_u32(&mut buf, uuid_cmdsize);
    buf.extend_from_slice(&[
        0xC7, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F,
    ]);

    let target = usize::try_from(text_fileoff).unwrap_or(buf.len());
    if buf.len() < target {
        buf.resize(target, 0);
    }
    buf.extend_from_slice(&text);

    let target = usize::try_from(data_fileoff).unwrap_or(buf.len());
    if buf.len() < target {
        buf.resize(target, 0);
    }
    // preferred VA of ctor in the pointer slot
    write_u64(&mut buf, ctor_va);

    let target = usize::try_from(file_end).unwrap_or(buf.len());
    if buf.len() < target {
        buf.resize(target, 0);
    }
    buf
}

/// Synthetic `MH_EXECUTE` that loads [`LIBKH_CTOR_INSTALL_NAME`] then `exit(0)`.
///
/// Constructor of the dylib runs first (writes `ctor\\n`); main only exits.
#[must_use]
#[allow(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::items_after_statements,
    clippy::too_many_lines
)]
pub fn ctor_main_exit() -> Vec<u8> {
    const MH_MAGIC_64: u32 = 0xfeed_facf;
    const CPU_TYPE_ARM64: u32 = 0x0100_000c;
    const MH_EXECUTE: u32 = 0x2;
    const MH_NOUNDEFS: u32 = 0x1;
    const MH_PIE: u32 = 0x0020_0000;
    const LC_SEGMENT_64: u32 = 0x19;
    const LC_UUID: u32 = 0x1b;
    const LC_LOAD_DYLIB: u32 = 0xc;
    const LC_MAIN: u32 = 0x28 | 0x8000_0000;
    const VM_PROT_READ: u32 = 0x1;
    const VM_PROT_EXECUTE: u32 = 0x4;
    const SEG_CMD: u32 = 72;
    const SECT_64: u32 = 80;

    let ctor_path = LIBKH_CTOR_INSTALL_NAME.as_bytes();
    let sys_path = b"/usr/lib/libSystem.B.dylib\0";
    let ctor_pad = align8(ctor_path.len() + 1);
    let sys_pad = align8(sys_path.len());
    let ctor_cmdsize = 24 + ctor_pad;
    let sys_cmdsize = 24 + sys_pad;

    let pagezero_cmdsize = SEG_CMD;
    let text_seg_cmdsize = SEG_CMD + SECT_64;
    let uuid_cmdsize: u32 = 24;
    let main_cmdsize: u32 = 24;

    let ncmds = 6_u32;
    let sizeofcmds = pagezero_cmdsize
        + text_seg_cmdsize
        + uuid_cmdsize
        + u32::try_from(ctor_cmdsize).unwrap_or(0)
        + u32::try_from(sys_cmdsize).unwrap_or(0)
        + main_cmdsize;

    let header_size = 32_u64;
    let load_end = header_size + u64::from(sizeofcmds);
    let text_fileoff = align_u64(load_end, 16);

    // exit(0)
    let mut text = Vec::with_capacity(16);
    push_u32(&mut text, movz(0, 0));
    push_u32(&mut text, movz(0x10, 1));
    push_u32(&mut text, svc80());
    while text.len() < 16 {
        text.push(0);
    }
    let text_len = u64::try_from(text.len()).unwrap_or(16);
    let file_end = text_fileoff + text_len;

    let text_vmaddr = 0x0000_0001_0000_0000_u64;
    let text_vmsize = 0x4000_u64;
    let entryoff = text_fileoff;

    let mut buf = Vec::with_capacity(usize::try_from(file_end).unwrap_or(512));

    write_u32(&mut buf, MH_MAGIC_64);
    write_u32(&mut buf, CPU_TYPE_ARM64);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, MH_EXECUTE);
    write_u32(&mut buf, ncmds);
    write_u32(&mut buf, sizeofcmds);
    write_u32(&mut buf, MH_NOUNDEFS | MH_PIE);
    write_u32(&mut buf, 0);

    write_u32(&mut buf, LC_SEGMENT_64);
    write_u32(&mut buf, pagezero_cmdsize);
    write_segname(&mut buf, b"__PAGEZERO");
    write_u64(&mut buf, 0);
    write_u64(&mut buf, 0x0000_0001_0000_0000);
    write_u64(&mut buf, 0);
    write_u64(&mut buf, 0);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0);

    write_u32(&mut buf, LC_SEGMENT_64);
    write_u32(&mut buf, text_seg_cmdsize);
    write_segname(&mut buf, b"__TEXT");
    write_u64(&mut buf, text_vmaddr);
    write_u64(&mut buf, text_vmsize);
    write_u64(&mut buf, 0);
    write_u64(&mut buf, file_end);
    write_u32(&mut buf, VM_PROT_READ | VM_PROT_EXECUTE);
    write_u32(&mut buf, VM_PROT_READ | VM_PROT_EXECUTE);
    write_u32(&mut buf, 1);
    write_u32(&mut buf, 0);

    write_sectname(&mut buf, b"__text");
    write_segname(&mut buf, b"__TEXT");
    write_u64(&mut buf, text_vmaddr + text_fileoff);
    write_u64(&mut buf, text_len);
    write_u32(&mut buf, u32::try_from(text_fileoff).unwrap_or(0));
    write_u32(&mut buf, 2);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0x8000_0400);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0);

    write_u32(&mut buf, LC_UUID);
    write_u32(&mut buf, uuid_cmdsize);
    buf.extend_from_slice(&[
        0xD0, 0xE1, 0xF2, 0x03, 0x14, 0x25, 0x36, 0x47, 0x58, 0x69, 0x7A, 0x8B, 0x9C, 0xAD, 0xBE,
        0xCF,
    ]);

    write_u32(&mut buf, LC_LOAD_DYLIB);
    write_u32(&mut buf, u32::try_from(ctor_cmdsize).unwrap_or(0));
    write_u32(&mut buf, 24);
    write_u32(&mut buf, 2);
    write_u32(&mut buf, 0x0001_0000);
    write_u32(&mut buf, 0x0001_0000);
    buf.extend_from_slice(ctor_path);
    buf.push(0);
    while !buf.len().is_multiple_of(8) {
        buf.push(0);
    }

    write_u32(&mut buf, LC_LOAD_DYLIB);
    write_u32(&mut buf, u32::try_from(sys_cmdsize).unwrap_or(0));
    write_u32(&mut buf, 24);
    write_u32(&mut buf, 2);
    write_u32(&mut buf, 0x0001_0000);
    write_u32(&mut buf, 0x0001_0000);
    buf.extend_from_slice(sys_path);
    while !buf.len().is_multiple_of(8) {
        buf.push(0);
    }

    write_u32(&mut buf, LC_MAIN);
    write_u32(&mut buf, main_cmdsize);
    write_u64(&mut buf, entryoff);
    write_u64(&mut buf, 0);

    let target = usize::try_from(text_fileoff).unwrap_or(buf.len());
    if buf.len() < target {
        buf.resize(target, 0);
    }
    buf.extend_from_slice(&text);
    let target = usize::try_from(file_end).unwrap_or(buf.len());
    if buf.len() < target {
        buf.resize(target, 0);
    }
    buf
}

/// Absolute install name for the synthetic bottle libSystem stub.
pub const LIBSYSTEM_INSTALL_NAME: &str = "/usr/lib/libSystem.B.dylib";

/// Preferred TEXT base of [`arm64_libsystem_stub`].
pub const LIBSYSTEM_TEXT_VA: u64 = 0x0000_0004_0000_0000;

/// Preferred GOT VA of [`call_libsystem_exit`] (`__DATA,__got`).
pub const CALL_LIBSYSTEM_GOT_VA: u64 = 0x0000_0001_0000_4000;

/// Symbol exported by synthetic bottle libSystem and imported by
/// [`call_libsystem_exit`].
pub const KH_BOTTLE_MARK_SYMBOL: &str = "_kh_bottle_mark";

/// Darwin `write(2)` — C `write` → nlist `_write`.
pub const LIBSYSTEM_WRITE_SYMBOL: &str = "_write";

/// Darwin `_exit(2)` — C `_exit` → nlist `__exit`.
pub const LIBSYSTEM_EXIT_SYMBOL: &str = "__exit";

/// C `puts` → nlist `_puts` (host helper).
pub const LIBSYSTEM_PUTS_SYMBOL: &str = "_puts";

/// C `printf` → nlist `_printf` (host helper; no `%` conversions yet).
pub const LIBSYSTEM_PRINTF_SYMBOL: &str = "_printf";

/// Return value of `_kh_bottle_mark` / guest exit code of [`call_libsystem_exit`].
pub const KH_BOTTLE_MARK_VALUE: u32 = 77;

/// Host helper number for `_puts` (must match `kh_runtime` helpers).
const KH_HELPER_PUTS: u32 = 0x4B48_0001;
/// Host helper number for minimal `_printf`.
const KH_HELPER_PRINTF: u32 = 0x4B48_0002;

/// Synthetic bottle `libSystem.B.dylib` with a growing C-ABI surface:
///
/// | Symbol | Body |
/// |--------|------|
/// | `_write` | BSD `write` via `svc #0x80` |
/// | `__exit` | BSD `exit` via `svc #0x80` |
/// | `_puts` | host helper (write string + newline) |
/// | `_printf` | host helper (literal format only) |
/// | `_kh_bottle_mark` | `movz w0,#77; ret` (fixture probe) |
///
/// Real clang guests bind these via chained fixups. Syscall / helper bodies go
/// through the host trap translator. `LC_ID_DYLIB` is [`LIBSYSTEM_INSTALL_NAME`];
/// map only under `--root`. License-clean; not Apple code.
#[must_use]
#[allow(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::items_after_statements,
    clippy::too_many_lines
)]
pub fn arm64_libsystem_stub() -> Vec<u8> {
    const MH_MAGIC_64: u32 = 0xfeed_facf;
    const CPU_TYPE_ARM64: u32 = 0x0100_000c;
    const MH_DYLIB: u32 = 0x6;
    const MH_NOUNDEFS: u32 = 0x1;
    const MH_DYLDLINK: u32 = 0x4;
    const LC_SEGMENT_64: u32 = 0x19;
    const LC_ID_DYLIB: u32 = 0xd;
    const LC_SYMTAB: u32 = 0x2;
    const LC_DYSYMTAB: u32 = 0xb;
    const LC_UUID: u32 = 0x1b;
    const VM_PROT_READ: u32 = 0x1;
    const VM_PROT_EXECUTE: u32 = 0x4;
    const SEG_CMD: u32 = 72;
    const SECT_64: u32 = 80;
    const NLIST64: u32 = 16;
    const RET: u32 = 0xd65f_03c0;

    let id_path = LIBSYSTEM_INSTALL_NAME.as_bytes();
    let id_path_nul = {
        let mut v = id_path.to_vec();
        v.push(0);
        v
    };
    let id_path_pad = align8(id_path_nul.len());
    let id_cmdsize = 24 + id_path_pad;

    let text_seg_cmdsize = SEG_CMD + SECT_64;
    let uuid_cmdsize: u32 = 24;
    let symtab_cmdsize: u32 = 24;
    let dysymtab_cmdsize: u32 = 80;

    let ncmds = 5_u32;
    let sizeofcmds = text_seg_cmdsize
        + u32::try_from(id_cmdsize).unwrap_or(0)
        + uuid_cmdsize
        + symtab_cmdsize
        + dysymtab_cmdsize;

    let header_size = 32_u64;
    let load_end = header_size + u64::from(sizeofcmds);
    let text_fileoff = align_u64(load_end, 16);

    // Layout (pad to 64):
    //   +0  _write           movz x16,#4; svc; ret              (12)
    //   +12 __exit           movz x16,#1; svc                   (8)
    //   +20 _kh_bottle_mark  movz w0,#77; ret                   (8)
    //   +28 _puts            movz/movk x16,helper; svc; ret     (16)
    //   +44 _printf          movz/movk x16,helper; svc; ret     (16)
    let mut text_code = Vec::with_capacity(64);
    push_u32(&mut text_code, movz(16, 4)); // _write @0
    push_u32(&mut text_code, svc80());
    push_u32(&mut text_code, RET);
    push_u32(&mut text_code, movz(16, 1)); // __exit @12
    push_u32(&mut text_code, svc80());
    push_u32(&mut text_code, movz(0, KH_BOTTLE_MARK_VALUE)); // mark @20
    push_u32(&mut text_code, RET);
    push_helper_call(&mut text_code, KH_HELPER_PUTS); // _puts @28
    push_helper_call(&mut text_code, KH_HELPER_PRINTF); // _printf @44
    while text_code.len() < 64 {
        text_code.push(0);
    }
    let text_filesize = 64_u64;
    let text_end = text_fileoff + text_filesize;

    let exports: [(&str, u64); 5] = [
        (LIBSYSTEM_WRITE_SYMBOL, 0),
        (LIBSYSTEM_EXIT_SYMBOL, 12),
        (KH_BOTTLE_MARK_SYMBOL, 20),
        (LIBSYSTEM_PUTS_SYMBOL, 28),
        (LIBSYSTEM_PRINTF_SYMBOL, 44),
    ];
    let nsyms = u32::try_from(exports.len()).unwrap_or(0);

    let symoff = align_u64(text_end, 8);
    let stroff = symoff + u64::from(NLIST64) * u64::from(nsyms);
    let mut strtab = vec![0_u8];
    let mut strx: Vec<u32> = Vec::with_capacity(exports.len());
    for (name, _) in &exports {
        strx.push(u32::try_from(strtab.len()).unwrap_or(0));
        strtab.extend_from_slice(name.as_bytes());
        strtab.push(0);
    }
    let strsize = u32::try_from(strtab.len()).unwrap_or(0);
    let file_end = stroff + u64::from(strsize);

    let text_vmaddr = LIBSYSTEM_TEXT_VA;
    let text_vmsize = 0x4000_u64;
    let text_sect_addr = text_vmaddr + text_fileoff;

    let mut buf = Vec::with_capacity(usize::try_from(file_end).unwrap_or(512));

    write_u32(&mut buf, MH_MAGIC_64);
    write_u32(&mut buf, CPU_TYPE_ARM64);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, MH_DYLIB);
    write_u32(&mut buf, ncmds);
    write_u32(&mut buf, sizeofcmds);
    write_u32(&mut buf, MH_NOUNDEFS | MH_DYLDLINK);
    write_u32(&mut buf, 0);

    write_u32(&mut buf, LC_SEGMENT_64);
    write_u32(&mut buf, text_seg_cmdsize);
    write_segname(&mut buf, b"__TEXT");
    write_u64(&mut buf, text_vmaddr);
    write_u64(&mut buf, text_vmsize);
    write_u64(&mut buf, 0);
    write_u64(&mut buf, file_end);
    write_u32(&mut buf, VM_PROT_READ | VM_PROT_EXECUTE);
    write_u32(&mut buf, VM_PROT_READ | VM_PROT_EXECUTE);
    write_u32(&mut buf, 1);
    write_u32(&mut buf, 0);

    write_sectname(&mut buf, b"__text");
    write_segname(&mut buf, b"__TEXT");
    write_u64(&mut buf, text_sect_addr);
    write_u64(&mut buf, text_filesize);
    write_u32(&mut buf, u32::try_from(text_fileoff).unwrap_or(0));
    write_u32(&mut buf, 2);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0x8000_0400);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0);

    write_u32(&mut buf, LC_ID_DYLIB);
    write_u32(&mut buf, u32::try_from(id_cmdsize).unwrap_or(0));
    write_u32(&mut buf, 24);
    write_u32(&mut buf, 1);
    write_u32(&mut buf, 0x0001_0000);
    write_u32(&mut buf, 0x0001_0000);
    buf.extend_from_slice(&id_path_nul);
    while !buf.len().is_multiple_of(8) {
        buf.push(0);
    }

    write_u32(&mut buf, LC_UUID);
    write_u32(&mut buf, uuid_cmdsize);
    buf.extend_from_slice(&[
        0xB0, 0x77, 0x1E, 0x00, 0x11, 0xB5, 0x75, 0x7E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x08,
    ]);

    write_u32(&mut buf, LC_SYMTAB);
    write_u32(&mut buf, symtab_cmdsize);
    write_u32(&mut buf, u32::try_from(symoff).unwrap_or(0));
    write_u32(&mut buf, nsyms);
    write_u32(&mut buf, u32::try_from(stroff).unwrap_or(0));
    write_u32(&mut buf, strsize);

    write_u32(&mut buf, LC_DYSYMTAB);
    write_u32(&mut buf, dysymtab_cmdsize);
    // iextdefsym=0, nextdefsym=nsyms; remaining fields zero.
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0); // iextdefsym
    write_u32(&mut buf, nsyms); // nextdefsym
    for _ in 0..14 {
        write_u32(&mut buf, 0);
    }

    let target = usize::try_from(text_fileoff).unwrap_or(buf.len());
    if buf.len() < target {
        buf.resize(target, 0);
    }
    buf.extend_from_slice(&text_code);
    let target = usize::try_from(text_end).unwrap_or(buf.len());
    if buf.len() < target {
        buf.resize(target, 0);
    }

    let target = usize::try_from(symoff).unwrap_or(buf.len());
    if buf.len() < target {
        buf.resize(target, 0);
    }
    for (i, (_, code_off)) in exports.iter().enumerate() {
        let sx = strx.get(i).copied().unwrap_or(0);
        write_u32(&mut buf, sx);
        buf.push(0x0f); // N_SECT | N_EXT
        buf.push(1); // n_sect = 1 (__text)
        write_u16(&mut buf, 0);
        write_u64(&mut buf, text_sect_addr.saturating_add(*code_off));
    }

    let target = usize::try_from(stroff).unwrap_or(buf.len());
    if buf.len() < target {
        buf.resize(target, 0);
    }
    buf.extend_from_slice(&strtab);

    let target = usize::try_from(file_end).unwrap_or(buf.len());
    if buf.len() < target {
        buf.resize(target, 0);
    }
    buf
}

/// Synthetic `MH_EXECUTE`: load absolute `/usr/lib/libSystem.B.dylib`, call
/// `_kh_bottle_mark`, `exit` with **77**.
///
/// Requires `--root` with `{root}/usr/lib/libSystem.B.dylib` (see
/// [`arm64_libsystem_stub`]). Without a bottle, resolve soft-skips libSystem and
/// bind fails with `UnresolvedSymbol`.
///
/// Includes `LC_DYLD_INFO_ONLY` classic bind of `_kh_bottle_mark` into `__got`.
#[must_use]
#[allow(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::items_after_statements,
    clippy::too_many_lines
)]
pub fn call_libsystem_exit() -> Vec<u8> {
    const MH_MAGIC_64: u32 = 0xfeed_facf;
    const CPU_TYPE_ARM64: u32 = 0x0100_000c;
    const MH_EXECUTE: u32 = 0x2;
    const MH_NOUNDEFS: u32 = 0x1;
    const MH_PIE: u32 = 0x0020_0000;
    const LC_SEGMENT_64: u32 = 0x19;
    const LC_UUID: u32 = 0x1b;
    const LC_LOAD_DYLIB: u32 = 0xc;
    const LC_SYMTAB: u32 = 0x2;
    const LC_DYLD_INFO_ONLY: u32 = 0x22 | 0x8000_0000;
    const LC_MAIN: u32 = 0x28 | 0x8000_0000;
    const VM_PROT_READ: u32 = 0x1;
    const VM_PROT_WRITE: u32 = 0x2;
    const VM_PROT_EXECUTE: u32 = 0x4;
    const SEG_CMD: u32 = 72;
    const SECT_64: u32 = 80;
    const NLIST64: u32 = 16;
    const DYLD_INFO_CMDSIZE: u32 = 48;

    let sys_path = LIBSYSTEM_INSTALL_NAME.as_bytes();
    let sys_pad = align8(sys_path.len() + 1);
    let sys_cmdsize = 24 + sys_pad;

    let pagezero_cmdsize = SEG_CMD;
    let text_seg_cmdsize = SEG_CMD + SECT_64;
    let data_seg_cmdsize = SEG_CMD + SECT_64;
    let uuid_cmdsize: u32 = 24;
    let symtab_cmdsize: u32 = 24;
    let main_cmdsize: u32 = 24;

    let bind_stream = crate::bind::encode_pointer_bind(1, KH_BOTTLE_MARK_SYMBOL, 2, 0);
    let bind_size = u32::try_from(bind_stream.len()).unwrap_or(0);

    let ncmds = 8_u32;
    let sizeofcmds = pagezero_cmdsize
        + text_seg_cmdsize
        + data_seg_cmdsize
        + uuid_cmdsize
        + u32::try_from(sys_cmdsize).unwrap_or(0)
        + DYLD_INFO_CMDSIZE
        + symtab_cmdsize
        + main_cmdsize;

    let header_size = 32_u64;
    let load_end = header_size + u64::from(sizeofcmds);
    let text_fileoff = align_u64(load_end, 16);

    // Program (5 insns = 20 bytes), pad to 32:
    //   adrp x16, __got@page
    //   ldr  x16, [x16, __got@pageoff]
    //   blr  x16
    //   movz x16, #1
    //   svc  #0x80
    let text_len = 32_u64;
    let text_end = text_fileoff + text_len;

    let data_fileoff = align_u64(text_end, 8);
    let got_filesize = 8_u64;
    let data_end = data_fileoff + got_filesize;

    let bind_off = align_u64(data_end, 8);
    let bind_end = bind_off + u64::from(bind_size);

    let symoff = align_u64(bind_end, 8);
    let nsyms = 1_u32;
    let stroff = symoff + u64::from(NLIST64) * u64::from(nsyms);
    let mut strtab = vec![0_u8];
    strtab.extend_from_slice(KH_BOTTLE_MARK_SYMBOL.as_bytes());
    strtab.push(0);
    let strsize = u32::try_from(strtab.len()).unwrap_or(0);
    let file_end = stroff + u64::from(strsize);

    let text_vmaddr = 0x0000_0001_0000_0000_u64;
    let text_vmsize = 0x4000_u64;
    let data_vmaddr = CALL_LIBSYSTEM_GOT_VA;
    let data_vmsize = 0x4000_u64;
    let entryoff = text_fileoff;
    let entry_va = text_vmaddr + entryoff;
    // ADRP is the 1st instruction → PC = entry_va.
    let adrp_pc = entry_va;
    let adrp_insn = encode_adrp(16, adrp_pc, data_vmaddr);
    let pageoff = u32::try_from(data_vmaddr & 0xfff).unwrap_or(0);
    let ldr_insn = encode_ldr_x_uoff(16, 16, pageoff);

    let mut text = Vec::with_capacity(32);
    push_u32(&mut text, adrp_insn);
    push_u32(&mut text, ldr_insn);
    push_u32(&mut text, 0xd63f_0200); // blr x16
    push_u32(&mut text, movz(0x10, 1)); // exit (x0 = 77 from mark)
    push_u32(&mut text, svc80());
    while text.len() < usize::try_from(text_len).unwrap_or(32) {
        text.push(0);
    }

    let mut buf = Vec::with_capacity(usize::try_from(file_end).unwrap_or(512));

    write_u32(&mut buf, MH_MAGIC_64);
    write_u32(&mut buf, CPU_TYPE_ARM64);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, MH_EXECUTE);
    write_u32(&mut buf, ncmds);
    write_u32(&mut buf, sizeofcmds);
    write_u32(&mut buf, MH_NOUNDEFS | MH_PIE);
    write_u32(&mut buf, 0);

    write_u32(&mut buf, LC_SEGMENT_64);
    write_u32(&mut buf, pagezero_cmdsize);
    write_segname(&mut buf, b"__PAGEZERO");
    write_u64(&mut buf, 0);
    write_u64(&mut buf, 0x0000_0001_0000_0000);
    write_u64(&mut buf, 0);
    write_u64(&mut buf, 0);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0);

    write_u32(&mut buf, LC_SEGMENT_64);
    write_u32(&mut buf, text_seg_cmdsize);
    write_segname(&mut buf, b"__TEXT");
    write_u64(&mut buf, text_vmaddr);
    write_u64(&mut buf, text_vmsize);
    write_u64(&mut buf, 0);
    write_u64(&mut buf, data_fileoff);
    write_u32(&mut buf, VM_PROT_READ | VM_PROT_EXECUTE);
    write_u32(&mut buf, VM_PROT_READ | VM_PROT_EXECUTE);
    write_u32(&mut buf, 1);
    write_u32(&mut buf, 0);

    write_sectname(&mut buf, b"__text");
    write_segname(&mut buf, b"__TEXT");
    write_u64(&mut buf, text_vmaddr + text_fileoff);
    write_u64(&mut buf, text_len);
    write_u32(&mut buf, u32::try_from(text_fileoff).unwrap_or(0));
    write_u32(&mut buf, 2);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0x8000_0400);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0);

    write_u32(&mut buf, LC_SEGMENT_64);
    write_u32(&mut buf, data_seg_cmdsize);
    write_segname(&mut buf, b"__DATA");
    write_u64(&mut buf, data_vmaddr);
    write_u64(&mut buf, data_vmsize);
    write_u64(&mut buf, data_fileoff);
    write_u64(&mut buf, got_filesize);
    write_u32(&mut buf, VM_PROT_READ | VM_PROT_WRITE);
    write_u32(&mut buf, VM_PROT_READ | VM_PROT_WRITE);
    write_u32(&mut buf, 1);
    write_u32(&mut buf, 0);

    write_sectname(&mut buf, b"__got");
    write_segname(&mut buf, b"__DATA");
    write_u64(&mut buf, data_vmaddr);
    write_u64(&mut buf, got_filesize);
    write_u32(&mut buf, u32::try_from(data_fileoff).unwrap_or(0));
    write_u32(&mut buf, 3);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0x6);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0);

    write_u32(&mut buf, LC_UUID);
    write_u32(&mut buf, uuid_cmdsize);
    buf.extend_from_slice(&[
        0xB0, 0x77, 0xCA, 0x11, 0x11, 0xB5, 0x75, 0x7E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01,
    ]);

    write_u32(&mut buf, LC_LOAD_DYLIB);
    write_u32(&mut buf, u32::try_from(sys_cmdsize).unwrap_or(0));
    write_u32(&mut buf, 24);
    write_u32(&mut buf, 2);
    write_u32(&mut buf, 0x0001_0000);
    write_u32(&mut buf, 0x0001_0000);
    buf.extend_from_slice(sys_path);
    buf.push(0);
    while !buf.len().is_multiple_of(8) {
        buf.push(0);
    }

    write_u32(&mut buf, LC_DYLD_INFO_ONLY);
    write_u32(&mut buf, DYLD_INFO_CMDSIZE);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, u32::try_from(bind_off).unwrap_or(0));
    write_u32(&mut buf, bind_size);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0);
    write_u32(&mut buf, 0);

    write_u32(&mut buf, LC_SYMTAB);
    write_u32(&mut buf, symtab_cmdsize);
    write_u32(&mut buf, u32::try_from(symoff).unwrap_or(0));
    write_u32(&mut buf, nsyms);
    write_u32(&mut buf, u32::try_from(stroff).unwrap_or(0));
    write_u32(&mut buf, strsize);

    write_u32(&mut buf, LC_MAIN);
    write_u32(&mut buf, main_cmdsize);
    write_u64(&mut buf, entryoff);
    write_u64(&mut buf, 0);

    let target = usize::try_from(text_fileoff).unwrap_or(buf.len());
    if buf.len() < target {
        buf.resize(target, 0);
    }
    buf.extend_from_slice(&text);

    let target = usize::try_from(data_fileoff).unwrap_or(buf.len());
    if buf.len() < target {
        buf.resize(target, 0);
    }
    buf.extend_from_slice(&[0_u8; 8]);

    let target = usize::try_from(bind_off).unwrap_or(buf.len());
    if buf.len() < target {
        buf.resize(target, 0);
    }
    buf.extend_from_slice(&bind_stream);

    let target = usize::try_from(symoff).unwrap_or(buf.len());
    if buf.len() < target {
        buf.resize(target, 0);
    }
    write_u32(&mut buf, 1); // n_strx
    buf.push(0x01); // N_UNDF | N_EXT
    buf.push(0);
    write_u16(&mut buf, 0);
    write_u64(&mut buf, 0);

    let target = usize::try_from(stroff).unwrap_or(buf.len());
    if buf.len() < target {
        buf.resize(target, 0);
    }
    buf.extend_from_slice(&strtab);

    let target = usize::try_from(file_end).unwrap_or(buf.len());
    if buf.len() < target {
        buf.resize(target, 0);
    }
    buf
}

/// Micro program: `write(1, "kh\\n", 3); exit(0)`.
#[must_use]
pub fn minimal_arm64_execute() -> Vec<u8> {
    let mut text = Vec::with_capacity(36);
    // movz x0, #1
    push_u32(&mut text, 0xd280_0020);
    // adr x1, #28  → message at +32
    push_u32(&mut text, 0x1000_00e1);
    // movz x2, #3
    push_u32(&mut text, 0xd280_0062);
    // movz x16, #4  write
    push_u32(&mut text, 0xd280_0090);
    // svc #0x80
    push_u32(&mut text, 0xd400_0001 | (0x80_u32 << 5));
    // movz x0, #0
    push_u32(&mut text, 0xd280_0000);
    // movz x16, #1  exit
    push_u32(&mut text, 0xd280_0030);
    // svc #0x80
    push_u32(&mut text, 0xd400_0001 | (0x80_u32 << 5));
    text.extend_from_slice(b"kh\n");
    arm64_execute_with_text(&text)
}

/// Micro program: unknown syscall (`x16=0xBEEF`) then `exit(0)`.
///
/// Used to verify ENOSYS error ABI does not abort the guest.
#[must_use]
pub fn errno_unknown_then_exit() -> Vec<u8> {
    let mut text = Vec::with_capacity(32);
    // movz x16, #0xBEEF
    push_u32(&mut text, movz(0x10, 0xBEEF));
    // svc #0x80
    push_u32(&mut text, svc80());
    // movz x0, #0
    push_u32(&mut text, movz(0x0, 0));
    // movz x16, #1
    push_u32(&mut text, movz(0x10, 1));
    // svc #0x80
    push_u32(&mut text, svc80());
    arm64_execute_with_text(&text)
}

/// Micro program: `bsdthread_register` + `bsdthread_create` worker, join via flag, `exit(0)`.
///
/// Worker (via registered start trampoline) writes `T\\n`, stores a flag, then
/// `bsdthread_terminate`. Main spins on the flag (no syscall) and exits 0.
/// Live only on Linux aarch64 (host pthread spawn).
#[must_use]
#[allow(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::as_conversions,
    clippy::too_many_lines
)]
pub fn bsdthread_create_join() -> Vec<u8> {
    // Instruction stream built linearly; ADR/CBZ patched with final offsets.
    let mut text: Vec<u8> = Vec::with_capacity(256);
    let emit = |text: &mut Vec<u8>, w: u32| push_u32(text, w);
    #[allow(clippy::integer_division)]
    let icount = |text: &[u8]| text.len() / 4;

    // --- main ---
    // sub sp, sp, #16 ; str xzr, [sp]  (flag = 0)
    emit(&mut text, sub_imm(31, 31, 16));
    emit(&mut text, str_x_uoff(31, 31, 0)); // str xzr, [sp]

    // bsdthread_register(start, 0, 0, 0, 0, 0, 0)
    let adr_start_idx = icount(&text);
    emit(&mut text, 0); // ADR x0, start
    emit(&mut text, movz(1, 0));
    emit(&mut text, movz(2, 0));
    emit(&mut text, movz(3, 0));
    emit(&mut text, movz(4, 0));
    emit(&mut text, movz(5, 0));
    emit(&mut text, movz(6, 0));
    emit(&mut text, movz(0x10, 366));
    emit(&mut text, svc80());
    let bcs_reg = icount(&text);
    emit(&mut text, 0); // b.cs fail

    // mmap(0, 0x4000, PROT_RW=3, MAP_ANON|PRIVATE=0x1002, -1, 0)
    emit(&mut text, movz(0, 0));
    emit(&mut text, movz(1, 0x4000));
    emit(&mut text, movz(2, 3));
    emit(&mut text, movz(3, 0x1002));
    emit(&mut text, 0x9280_0004); // movn x4, #0
    emit(&mut text, movz(5, 0));
    emit(&mut text, movz(0x10, 197));
    emit(&mut text, svc80());
    let bcs_map = icount(&text);
    emit(&mut text, 0); // b.cs fail
    emit(&mut text, mov_reg(19, 0)); // x19 = stack base

    // raw_top = base + 0x4000. Guest SP must sit *inside* the map so the
    // kernel can push a SIGTRAP frame (SP == exclusive end is unmapped).
    // sp = raw_top - 0x20; pthread = raw_top - 0x200 (below initial SP).
    emit(&mut text, add_imm_lsl12(20, 19, 4)); // x20 = raw_top
    emit(&mut text, sub_imm(2, 20, 0x20)); // x2 = sp
    emit(&mut text, sub_imm(3, 20, 0x200)); // x3 = pthread

    // bsdthread_create(worker, flag_ptr, sp, pthread, 0)
    let adr_worker_idx = icount(&text);
    emit(&mut text, 0); // ADR x0, worker
    emit(&mut text, add_imm(1, 31, 0)); // x1 = sp (flag)
    // x2, x3 already set
    emit(&mut text, movz(4, 0));
    emit(&mut text, movz(0x10, 360));
    emit(&mut text, svc80());
    let bcs_create = icount(&text);
    emit(&mut text, 0); // b.cs fail

    // spin: ldrb w0, [sp]; cbz w0, spin
    let spin_idx = icount(&text);
    emit(&mut text, ldrb_x(0, 31)); // ldrb w0, [sp]
    let cbz_idx = icount(&text);
    emit(&mut text, 0); // cbz w0, spin

    // exit(0)
    emit(&mut text, movz(0, 0));
    emit(&mut text, movz(0x10, 1));
    emit(&mut text, svc80());

    // fail: exit(1)
    let fail_idx = icount(&text);
    emit(&mut text, movz(0, 1));
    emit(&mut text, movz(0x10, 1));
    emit(&mut text, svc80());

    // --- worker(flag_ptr in x0) ---
    let worker_idx = icount(&text);
    emit(&mut text, mov_reg(19, 0)); // x19 = flag
    emit(&mut text, movz(0, 1)); // fd=1
    let adr_msg_idx = icount(&text);
    emit(&mut text, 0); // ADR x1, msg
    emit(&mut text, movz(2, 2)); // len
    emit(&mut text, movz(0x10, 4)); // write
    emit(&mut text, svc80());
    emit(&mut text, 0x5280_0000 | (1_u32 << 5)); // movz w0, #1
    emit(&mut text, strb_x(0, 19)); // strb w0, [x19]
    emit(&mut text, 0xD503_3BBF); // dmb ish
    emit(&mut text, 0xD65F_03C0); // ret

    // --- start trampoline (x0=pthread, x1=port, x2=func, x3=arg) ---
    let start_idx = icount(&text);
    emit(&mut text, 0xA9BF_7BFD); // stp x29, x30, [sp, #-16]!
    emit(&mut text, mov_reg(0, 3)); // x0 = arg
    emit(&mut text, 0xD63F_0000 | (2_u32 << 5)); // blr x2
    emit(&mut text, movz(0, 0));
    emit(&mut text, movz(1, 0));
    emit(&mut text, movz(2, 0));
    emit(&mut text, movz(3, 0));
    emit(&mut text, movz(0x10, 361)); // bsdthread_terminate
    emit(&mut text, svc80());
    emit(&mut text, 0x1400_0000); // b .  (hang)

    // msg: "T\n"
    let msg_off = text.len();
    text.extend_from_slice(b"T\n");
    while !text.len().is_multiple_of(4) {
        text.push(0);
    }

    // --- patches ---
    let fail_imm = i32::try_from(fail_idx).unwrap_or(0) - i32::try_from(bcs_reg).unwrap_or(0);
    patch_u32(&mut text, bcs_reg, b_cond(0x2, fail_imm)); // CS
    let fail_imm = i32::try_from(fail_idx).unwrap_or(0) - i32::try_from(bcs_map).unwrap_or(0);
    patch_u32(&mut text, bcs_map, b_cond(0x2, fail_imm));
    let fail_imm = i32::try_from(fail_idx).unwrap_or(0) - i32::try_from(bcs_create).unwrap_or(0);
    patch_u32(&mut text, bcs_create, b_cond(0x2, fail_imm));

    let spin_imm = i32::try_from(spin_idx).unwrap_or(0) - i32::try_from(cbz_idx).unwrap_or(0);
    patch_u32(&mut text, cbz_idx, cbz_w(0, spin_imm));

    let start_byte =
        (i32::try_from(start_idx).unwrap_or(0) - i32::try_from(adr_start_idx).unwrap_or(0)) * 4;
    patch_u32(&mut text, adr_start_idx, adr(0, start_byte));

    let worker_byte =
        (i32::try_from(worker_idx).unwrap_or(0) - i32::try_from(adr_worker_idx).unwrap_or(0)) * 4;
    patch_u32(&mut text, adr_worker_idx, adr(0, worker_byte));

    let msg_byte = i32::try_from(msg_off).unwrap_or(0)
        - (i32::try_from(adr_msg_idx).unwrap_or(0) * 4);
    patch_u32(&mut text, adr_msg_idx, adr(1, msg_byte));

    arm64_execute_with_text(&text)
}

/// Micro program: anonymous `mmap` + write byte + `munmap` + `exit(0)`.
///
/// Exercises memory syscalls without needing a bottle root.
#[must_use]
#[allow(clippy::arithmetic_side_effects)]
pub fn mmap_touch_exit() -> Vec<u8> {
    // mmap(0, 0x1000, PROT_READ|PROT_WRITE=3, MAP_ANON|MAP_PRIVATE=0x1002, -1, 0)
    // then store 0x42 at [x0], munmap(x0, 0x1000), exit(0)
    let mut text = Vec::with_capacity(80);
    push_u32(&mut text, movz(0x0, 0));
    push_u32(&mut text, movz(0x1, 0x1000));
    push_u32(&mut text, movz(0x2, 0x3));
    push_u32(&mut text, movz(0x3, 0x1002));
    // movn x4, #0  → -1
    push_u32(&mut text, 0x9280_0000 | 0x4);
    push_u32(&mut text, movz(0x5, 0));
    push_u32(&mut text, movz(0x10, 197));
    push_u32(&mut text, svc80());
    // mov x19, x0
    push_u32(&mut text, 0xaa00_03f3);
    // movz w20, #0x42
    push_u32(&mut text, 0x5280_0000 | (0x42_u32 << 5) | 0x14);
    // strb w20, [x19]
    push_u32(&mut text, 0x3900_0274);
    // mov x0, x19
    push_u32(&mut text, 0xaa13_03e0);
    push_u32(&mut text, movz(0x1, 0x1000));
    push_u32(&mut text, movz(0x10, 73));
    push_u32(&mut text, svc80());
    push_u32(&mut text, movz(0x0, 0));
    push_u32(&mut text, movz(0x10, 1));
    push_u32(&mut text, svc80());
    arm64_execute_with_text(&text)
}

/// Payload bytes for [`memory_file_roundtrip`] (written next to the Mach-O).
pub const ROUNDTRIP_PAYLOAD: &[u8] = b"KAKEMAP01\n";

/// Relative path embedded in [`memory_file_roundtrip`] (cwd = repo /app root).
pub const ROUNDTRIP_PAYLOAD_PATH: &str = "tests/fixtures/roundtrip_payload.bin";

/// Ultimate static fixture: open → fstat64 → file mmap → mutate → mprotect →
/// msync → clock_gettime → sysctlbyname → munmap → close → exit(0).
///
/// Requires [`ROUNDTRIP_PAYLOAD`] at [`ROUNDTRIP_PAYLOAD_PATH`] relative to CWD.
#[must_use]
#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::decimal_bitwise_operands,
    clippy::indexing_slicing,
    clippy::integer_division,
    clippy::too_many_lines
)]
pub fn memory_file_roundtrip() -> Vec<u8> {
    // Callee-saved: x19=fd, x20=map base, x21=scratch
    // Stack: [sp+0] stat64(144), [sp+0xA0] timespec(16), [sp+0xB0] oldlen(8),
    //        [sp+0xC0] ncpu(8)
    let path = ROUNDTRIP_PAYLOAD_PATH.as_bytes();
    let key = b"hw.ncpu\0";

    let mut text: Vec<u8> = Vec::with_capacity(512);
    let mut bcs: Vec<(usize, u8)> = Vec::new(); // (instr_idx, exit_code)
    let mut bne: Vec<(usize, u8)> = Vec::new();

    let emit = |text: &mut Vec<u8>, w: u32| {
        push_u32(text, w);
    };
    let icount = |text: &[u8]| text.len() / 4;

    // sub sp, sp, #0x100
    emit(&mut text, sub_imm(31, 31, 0x100));

    // --- open(path, O_RDWR=2) ---
    // adr x0, path  (patched after body length known — use placeholder then fix)
    let adr_path_idx = icount(&text);
    emit(&mut text, 0); // placeholder ADR
    emit(&mut text, movz(1, 2)); // O_RDWR
    emit(&mut text, movz(0x10, 5)); // open
    emit(&mut text, svc80());
    bcs.push((icount(&text), 2));
    emit(&mut text, 0); // b.cs fail2
    emit(&mut text, mov_reg(19, 0)); // x19 = fd

    // --- fstat64(fd, sp) ---
    // Note: SP is not usable as Rm in ORR/`mov Xd, Xm`; use ADD Xd, SP, #0.
    emit(&mut text, mov_reg(0, 19));
    emit(&mut text, add_imm(1, 31, 0)); // x1 = sp
    emit(&mut text, movz(0x10, 339));
    emit(&mut text, svc80());
    bcs.push((icount(&text), 3));
    emit(&mut text, 0);

    // ldr x21, [sp, #96]  st_size
    emit(&mut text, ldr_x_uoff(21, 31, 96));
    // cmp x21, #9  (subs xzr, x21, #9)
    emit(&mut text, cmp_x_imm(21, 9));
    bne.push((icount(&text), 3));
    emit(&mut text, 0); // b.lt fail3

    // --- mmap(0, 0x1000, PROT_RW=3, MAP_SHARED=1, fd, 0) ---
    emit(&mut text, movz(0, 0));
    emit(&mut text, movz(1, 0x1000));
    emit(&mut text, movz(2, 3));
    emit(&mut text, movz(3, 1)); // MAP_SHARED
    emit(&mut text, mov_reg(4, 19));
    emit(&mut text, movz(5, 0));
    emit(&mut text, movz(0x10, 197));
    emit(&mut text, svc80());
    bcs.push((icount(&text), 4));
    emit(&mut text, 0);
    emit(&mut text, mov_reg(20, 0)); // x20 = map

    // --- verify magic 'K' at [x20] ---
    emit(&mut text, ldrb_x(21, 20)); // ldrb w21, [x20]
    emit(&mut text, cmp_w_imm(21, u32::from(b'K')));
    bne.push((icount(&text), 5));
    emit(&mut text, 0); // b.ne fail5

    // --- mutate first byte to 'X' ---
    emit(&mut text, 0x5280_0000 | (u32::from(b'X') << 5) | 21); // movz w21, #'X'
    emit(&mut text, strb_x(21, 20)); // strb w21, [x20]

    // --- mprotect(map, 0x1000, PROT_READ=1) ---
    emit(&mut text, mov_reg(0, 20));
    emit(&mut text, movz(1, 0x1000));
    emit(&mut text, movz(2, 1));
    emit(&mut text, movz(0x10, 74));
    emit(&mut text, svc80());
    bcs.push((icount(&text), 6));
    emit(&mut text, 0);

    // --- mprotect(map, 0x1000, PROT_RW=3) ---
    emit(&mut text, mov_reg(0, 20));
    emit(&mut text, movz(1, 0x1000));
    emit(&mut text, movz(2, 3));
    emit(&mut text, movz(0x10, 74));
    emit(&mut text, svc80());
    bcs.push((icount(&text), 6));
    emit(&mut text, 0);

    // --- msync(map, 0x1000, MS_SYNC=0x10) ---
    emit(&mut text, mov_reg(0, 20));
    emit(&mut text, movz(1, 0x1000));
    emit(&mut text, movz(2, 0x10));
    emit(&mut text, movz(0x10, 65));
    emit(&mut text, svc80());
    bcs.push((icount(&text), 7));
    emit(&mut text, 0);

    // --- clock_gettime(CLOCK_REALTIME=0, sp+0xA0) ---
    emit(&mut text, movz(0, 0));
    emit(&mut text, add_imm(1, 31, 0xA0)); // x1 = sp + 0xA0
    emit(&mut text, movz(0x10, 266));
    emit(&mut text, svc80());
    bcs.push((icount(&text), 8));
    emit(&mut text, 0);
    // ldr x21, [sp, #0xA0] — tv_sec must be > 0
    emit(&mut text, ldr_x_uoff(21, 31, 0xA0));
    emit(&mut text, cmp_x_imm(21, 0));
    bne.push((icount(&text), 8));
    emit(&mut text, 0); // b.eq fail8

    // --- sysctlbyname("hw.ncpu", &ncpu, &oldlen, 0, 0) ---
    let adr_key_idx = icount(&text);
    emit(&mut text, 0); // placeholder ADR x0 = key
    // oldlen = 8 at sp+0xB0
    emit(&mut text, movz(21, 8));
    emit(&mut text, str_x_uoff(21, 31, 0xB0));
    emit(&mut text, add_imm(1, 31, 0xC0)); // oldp = sp+0xC0
    emit(&mut text, add_imm(2, 31, 0xB0)); // oldlenp
    emit(&mut text, movz(3, 0));
    emit(&mut text, movz(4, 0));
    emit(&mut text, movz(0x10, 274));
    emit(&mut text, svc80());
    bcs.push((icount(&text), 9));
    emit(&mut text, 0);
    // ldr w21, [sp, #0xC0]; cmp w21, #0; b.eq fail9
    emit(&mut text, ldr_w_uoff(21, 31, 0xC0));
    emit(&mut text, cmp_w_imm(21, 0));
    bne.push((icount(&text), 9));
    emit(&mut text, 0); // b.eq

    // --- munmap(map, 0x1000) ---
    emit(&mut text, mov_reg(0, 20));
    emit(&mut text, movz(1, 0x1000));
    emit(&mut text, movz(0x10, 73));
    emit(&mut text, svc80());
    bcs.push((icount(&text), 10));
    emit(&mut text, 0);

    // --- close(fd) ---
    emit(&mut text, mov_reg(0, 19));
    emit(&mut text, movz(0x10, 6));
    emit(&mut text, svc80());
    bcs.push((icount(&text), 11));
    emit(&mut text, 0);

    // --- exit(0) ---
    emit(&mut text, movz(0, 0));
    emit(&mut text, movz(0x10, 1));
    emit(&mut text, svc80());

    // --- fail exits: exit(code) for codes 2..=11 ---
    // Map exit_code -> instr index
    let mut fail_at = [0_usize; 16];
    for code in 2_u8..=11 {
        fail_at[usize::from(code)] = icount(&text);
        emit(&mut text, movz(0, u32::from(code)));
        emit(&mut text, movz(0x10, 1));
        emit(&mut text, svc80());
    }

    // Patch b.cs / b.eq / b.ne / b.lt
    for (idx, code) in &bcs {
        let target = fail_at[usize::from(*code)];
        let imm = i32::try_from(target).unwrap_or(0) - i32::try_from(*idx).unwrap_or(0);
        patch_u32(&mut text, *idx, b_cond(0x2, imm)); // CS
    }
    // bne list mixes b.ne (NE=1), b.lt (LT=0xB), b.eq (EQ=0)
    // We need to track which condition — restructure:
    // First bne was b.lt for size, second b.ne for magic, third b.eq for time, fourth b.eq for ncpu

    // Clear and re-do with explicit conditions stored:
    // Actually the placeholders at bne indices need correct cond:
    // idx order in bne: (lt/3), (ne/5), (eq/8), (eq/9)
    let conds = [0xB_u32, 0x1, 0x0, 0x0]; // LT, NE, EQ, EQ
    for (i, (idx, code)) in bne.iter().enumerate() {
        let target = fail_at[usize::from(*code)];
        let imm = i32::try_from(target).unwrap_or(0) - i32::try_from(*idx).unwrap_or(0);
        let cond = conds.get(i).copied().unwrap_or(0x1);
        patch_u32(&mut text, *idx, b_cond(cond, imm));
    }

    // Data: path then key
    let path_off = text.len();
    text.extend_from_slice(path);
    text.push(0);
    while !text.len().is_multiple_of(4) {
        text.push(0);
    }
    let key_off = text.len();
    text.extend_from_slice(key);
    while !text.len().is_multiple_of(4) {
        text.push(0);
    }

    // Patch ADR: offset from ADR PC to data
    // ADR PC is at adr_*_idx * 4 within text
    let path_imm = i32::try_from(path_off).unwrap_or(0)
        - i32::try_from(adr_path_idx.saturating_mul(4)).unwrap_or(0);
    patch_u32(&mut text, adr_path_idx, adr(0, path_imm));
    let key_imm = i32::try_from(key_off).unwrap_or(0)
        - i32::try_from(adr_key_idx.saturating_mul(4)).unwrap_or(0);
    patch_u32(&mut text, adr_key_idx, adr(0, key_imm));

    arm64_execute_with_text(&text)
}

/// `SUB Xd, Xn, #imm12` (64-bit, shift 0).
#[allow(
    clippy::integer_division,
    clippy::as_conversions,
    clippy::cast_sign_loss
)]
const fn sub_imm(rd: u32, rn: u32, imm12: u32) -> u32 {
    0xD100_0000 | ((imm12 & 0xFFF) << 10) | ((rn & 0x1F) << 5) | (rd & 0x1F)
}

/// `ADD Xd, Xn, #imm12` (64-bit, shift 0).
const fn add_imm(rd: u32, rn: u32, imm12: u32) -> u32 {
    0x9100_0000 | ((imm12 & 0xFFF) << 10) | ((rn & 0x1F) << 5) | (rd & 0x1F)
}

/// `ADD Xd, Xn, #imm12, LSL #12` (64-bit).
const fn add_imm_lsl12(rd: u32, rn: u32, imm12: u32) -> u32 {
    0x9100_0000 | (1 << 22) | ((imm12 & 0xFFF) << 10) | ((rn & 0x1F) << 5) | (rd & 0x1F)
}

/// `CBZ Wt, #imm` (`imm` in **instructions**, signed).
#[allow(clippy::as_conversions, clippy::cast_sign_loss)]
const fn cbz_w(rt: u32, imm_instr: i32) -> u32 {
    let imm19 = imm_instr.cast_unsigned() & 0x7_FFFF;
    0x3400_0000 | (imm19 << 5) | (rt & 0x1F)
}

/// `MOV Xd, Xm` via `ORR Xd, XZR, Xm`.
const fn mov_reg(rd: u32, rm: u32) -> u32 {
    0xAA00_03E0 | ((rm & 0x1F) << 16) | (rd & 0x1F)
}

/// `ADR Xd, #imm` (byte offset from this instruction).
#[allow(clippy::as_conversions, clippy::cast_sign_loss)]
const fn adr(rd: u32, imm: i32) -> u32 {
    let imm_u = imm.cast_unsigned();
    let immlo = imm_u & 0x3;
    let immhi = (imm_u >> 2) & 0x7_FFFF;
    0x1000_0000 | (immlo << 29) | (immhi << 5) | (rd & 0x1F)
}

/// `B.cond` with instruction-offset `imm` (signed, in instructions).
#[allow(clippy::as_conversions, clippy::cast_sign_loss)]
const fn b_cond(cond: u32, imm_instr: i32) -> u32 {
    let imm19 = imm_instr.cast_unsigned() & 0x7_FFFF;
    0x5400_0000 | (imm19 << 5) | (cond & 0xF)
}

/// `LDR Xt, [Xn, #imm]` unsigned offset (imm multiple of 8).
#[allow(clippy::integer_division)]
const fn ldr_x_uoff(rt: u32, rn: u32, imm: u32) -> u32 {
    let imm12 = (imm / 8) & 0xFFF;
    0xF940_0000 | (imm12 << 10) | ((rn & 0x1F) << 5) | (rt & 0x1F)
}

/// `STR Xt, [Xn, #imm]` unsigned offset (imm multiple of 8).
#[allow(clippy::integer_division)]
const fn str_x_uoff(rt: u32, rn: u32, imm: u32) -> u32 {
    let imm12 = (imm / 8) & 0xFFF;
    0xF900_0000 | (imm12 << 10) | ((rn & 0x1F) << 5) | (rt & 0x1F)
}

/// `LDR Wt, [Xn, #imm]` unsigned offset (imm multiple of 4).
#[allow(clippy::integer_division)]
const fn ldr_w_uoff(rt: u32, rn: u32, imm: u32) -> u32 {
    let imm12 = (imm / 4) & 0xFFF;
    0xB940_0000 | (imm12 << 10) | ((rn & 0x1F) << 5) | (rt & 0x1F)
}

/// `CMP Xn, #imm12` (`SUBS XZR, Xn, #imm`).
const fn cmp_x_imm(rn: u32, imm12: u32) -> u32 {
    0xF100_0000 | ((imm12 & 0xFFF) << 10) | ((rn & 0x1F) << 5) | 31
}

/// `CMP Wn, #imm12` (`SUBS WZR, Wn, #imm`).
const fn cmp_w_imm(rn: u32, imm12: u32) -> u32 {
    0x7100_0000 | ((imm12 & 0xFFF) << 10) | ((rn & 0x1F) << 5) | 31
}

/// `LDRB Wt, [Xn]`.
const fn ldrb_x(rt: u32, rn: u32) -> u32 {
    0x3940_0000 | ((rn & 0x1F) << 5) | (rt & 0x1F)
}

/// `STRB Wt, [Xn]`.
const fn strb_x(rt: u32, rn: u32) -> u32 {
    0x3900_0000 | ((rn & 0x1F) << 5) | (rt & 0x1F)
}

fn patch_u32(buf: &mut [u8], instr_idx: usize, word: u32) {
    let off = instr_idx.saturating_mul(4);
    if let Some(slot) = buf.get_mut(off..off.saturating_add(4)) {
        slot.copy_from_slice(&word.to_le_bytes());
    }
}

/// `movz Xd, #imm16` (shift 0).
const fn movz(rd: u32, imm16: u32) -> u32 {
    0xd280_0000 | ((imm16 & 0xFFFF) << 5) | (rd & 0x1F)
}

/// `movk Xd, #imm16, LSL #16`.
const fn movk_lsl16(rd: u32, imm16: u32) -> u32 {
    0xf2a0_0000 | ((imm16 & 0xFFFF) << 5) | (rd & 0x1F)
}

/// `svc #0x80`.
const fn svc80() -> u32 {
    0xd400_0001 | (0x80_u32 << 5)
}

fn push_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

/// `movz x16, #lo; movk x16, #hi, lsl#16; svc #0x80; ret` for a 32-bit helper id.
fn push_helper_call(buf: &mut Vec<u8>, helper: u32) {
    const RET: u32 = 0xd65f_03c0;
    let lo = helper & 0xFFFF;
    let hi = (helper >> 16) & 0xFFFF;
    push_u32(buf, movz(16, lo));
    push_u32(buf, movk_lsl16(16, hi));
    push_u32(buf, svc80());
    push_u32(buf, RET);
}

fn align8(n: usize) -> usize {
    n.div_ceil(8).saturating_mul(8)
}

#[allow(clippy::arithmetic_side_effects)]
fn align_u64(value: u64, align: u64) -> u64 {
    if align == 0 {
        return value;
    }
    let rem = value % align;
    if rem == 0 {
        value
    } else {
        value + (align - rem)
    }
}

fn write_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn write_u64(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn write_segname(buf: &mut Vec<u8>, name: &[u8]) {
    let mut field = [0_u8; 16];
    let n = name.len().min(16);
    if let Some(dst) = field.get_mut(..n)
        && let Some(src) = name.get(..n)
    {
        dst.copy_from_slice(src);
    }
    buf.extend_from_slice(&field);
}

fn write_sectname(buf: &mut Vec<u8>, name: &[u8]) {
    write_segname(buf, name);
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use goblin::mach::Mach;

    #[test]
    fn goblin_accepts_minimal_fixture() {
        let bytes = minimal_arm64_execute();
        let mach = Mach::parse(&bytes).expect("goblin parse");
        match mach {
            Mach::Binary(m) => {
                assert!(m.is_64);
                assert_eq!(m.header.cputype(), 0x0100_000c);
                assert!(!m.libs.is_empty());
            }
            Mach::Fat(_) => panic!("expected thin binary"),
        }
    }

    #[test]
    fn goblin_accepts_mmap_and_errno_fixtures() {
        for bytes in [errno_unknown_then_exit(), mmap_touch_exit()] {
            let mach = Mach::parse(&bytes).expect("goblin parse");
            assert!(matches!(mach, Mach::Binary(_)));
        }
    }

    #[test]
    fn goblin_accepts_bsdthread_fixture() {
        let bytes = bsdthread_create_join();
        let mach = Mach::parse(&bytes).expect("goblin parse");
        assert!(matches!(mach, Mach::Binary(_)));
        assert!(bytes.len() > 100);
    }

    #[test]
    fn goblin_accepts_memory_file_roundtrip() {
        let bytes = memory_file_roundtrip();
        let mach = Mach::parse(&bytes).expect("goblin parse");
        assert!(matches!(mach, Mach::Binary(_)));
        assert!(bytes.len() > 400);
    }

    #[test]
    fn goblin_accepts_dylib_and_call_dylib() {
        let dylib = arm64_dylib_add();
        let main = call_dylib_exit();
        for bytes in [&dylib[..], &main[..]] {
            let mach = Mach::parse(bytes).expect("goblin parse");
            assert!(matches!(mach, Mach::Binary(_)));
        }
        let dylib_m = match Mach::parse(&dylib).expect("parse dylib") {
            Mach::Binary(m) => m,
            Mach::Fat(_) => panic!("thin dylib"),
        };
        assert_eq!(dylib_m.header.filetype, 0x6);
        let main_m = match Mach::parse(&main).expect("parse main") {
            Mach::Binary(m) => m,
            Mach::Fat(_) => panic!("thin main"),
        };
        assert!(main_m.libs.iter().any(|l| l.contains("libkh_add")));
    }

    #[test]
    fn goblin_accepts_ctor_fixtures() {
        let dylib = arm64_dylib_ctor();
        let main = ctor_main_exit();
        for bytes in [&dylib[..], &main[..]] {
            assert!(matches!(
                Mach::parse(bytes).expect("parse"),
                Mach::Binary(_)
            ));
        }
    }

    #[test]
    fn goblin_accepts_libsystem_bottle_fixtures() {
        let dylib = arm64_libsystem_stub();
        let main = call_libsystem_exit();
        for bytes in [&dylib[..], &main[..]] {
            assert!(matches!(
                Mach::parse(bytes).expect("parse"),
                Mach::Binary(_)
            ));
        }
        let dylib_m = match Mach::parse(&dylib).expect("parse stub") {
            Mach::Binary(m) => m,
            Mach::Fat(_) => panic!("thin dylib"),
        };
        assert_eq!(dylib_m.header.filetype, 0x6);
        assert!(
            dylib_m
                .name
                .as_ref()
                .is_some_and(|n| n.contains("libSystem")),
            "LC_ID_DYLIB should be libSystem, got {:?}",
            dylib_m.name
        );
        let main_m = match Mach::parse(&main).expect("parse main") {
            Mach::Binary(m) => m,
            Mach::Fat(_) => panic!("thin main"),
        };
        assert!(
            main_m.libs.iter().any(|l| l.contains("libSystem.B.dylib")),
            "main must load absolute libSystem: {:?}",
            main_m.libs
        );
    }
}
