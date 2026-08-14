//! Darwin `fts(3)` walk (public `fts.h` layout; independent preorder walk).
//!
//! Used by bottle `ls` / `chmod` (`_fts_open` and `_fts_open$INODE64`).

#![allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::indexing_slicing,
    clippy::integer_division,
    clippy::ptr_as_ptr
)]

use core::ffi::{c_char, c_int, c_void};

use crate::kh_core::errno;
use crate::kh_core::heap::{free, malloc};

use super::posix::{closedir, lstat, opendir, readdir, stat};
use super::stdio::{bzero, strlen};

const EINVAL: i32 = 22;
const ENOMEM: i32 = 12;
const ENOENT: i32 = 2;

const FTS_COMFOLLOW: c_int = 0x001;
const FTS_LOGICAL: c_int = 0x002;
const FTS_NOCHDIR: c_int = 0x004;
const FTS_NOSTAT: c_int = 0x008;
const FTS_PHYSICAL: c_int = 0x010;
const FTS_SEEDOT: c_int = 0x020;
const FTS_XDEV: c_int = 0x040;
const FTS_NAMEONLY: c_int = 0x100;
const FTS_STOP: c_int = 0x200;
const FTS_NOSTAT_TYPE: c_int = 0x800;
const FTS_OPTIONMASK: c_int = 0xcff;

const FTS_ROOTPARENTLEVEL: i16 = -1;
const FTS_ROOTLEVEL: i16 = 0;

const FTS_D: u16 = 1;
const FTS_DC: u16 = 2;
const FTS_DEFAULT: u16 = 3;
const FTS_DNR: u16 = 4;
const FTS_DOT: u16 = 5;
const FTS_DP: u16 = 6;
const FTS_F: u16 = 8;
const FTS_NS: u16 = 10;
const FTS_NSOK: u16 = 11;
const FTS_SL: u16 = 12;
const FTS_SLNONE: u16 = 13;

const FTS_AGAIN: c_int = 1;
const FTS_FOLLOW: c_int = 2;
const FTS_NOINSTR: c_int = 3;
const FTS_SKIP: c_int = 4;

const FLAG_DESCENDED: u16 = 0x10;

const S_IFMT: u16 = 0o170_000;
const S_IFDIR: u16 = 0o040_000;
const S_IFREG: u16 = 0o100_000;
const S_IFLNK: u16 = 0o120_000;

const DT_DIR: u8 = 4;
const DT_LNK: u8 = 10;
const DT_REG: u8 = 8;
const DIRENT_TYPE_OFF: usize = 20;
const DIRENT_NAME_OFF: usize = 21;

const STAT_SIZE: usize = 144;
const FTS_MAGIC: u32 = 0x4B48_4654;

type Compar = Option<unsafe extern "C" fn(*const *mut Ftsent, *const *mut Ftsent) -> c_int>;

#[repr(C)]
pub(crate) struct Fts {
    cur: *mut Ftsent,
    child: *mut Ftsent,
    array: *mut *mut Ftsent,
    dev: i32,
    _pad_dev: i32,
    path: *mut c_char,
    rfd: c_int,
    pathlen: c_int,
    nitems: c_int,
    _pad_nitems: c_int,
    compar: Compar,
    options: c_int,
    _pad_opt: c_int,
    magic: u32,
    path_cap: u32,
}

const _: () = assert!(core::mem::offset_of!(Fts, cur) == 0);
const _: () = assert!(core::mem::offset_of!(Fts, child) == 8);
const _: () = assert!(core::mem::offset_of!(Fts, array) == 16);
const _: () = assert!(core::mem::offset_of!(Fts, dev) == 24);
const _: () = assert!(core::mem::offset_of!(Fts, path) == 32);
const _: () = assert!(core::mem::offset_of!(Fts, rfd) == 40);
const _: () = assert!(core::mem::offset_of!(Fts, pathlen) == 44);
const _: () = assert!(core::mem::offset_of!(Fts, nitems) == 48);
const _: () = assert!(core::mem::offset_of!(Fts, compar) == 56);
const _: () = assert!(core::mem::offset_of!(Fts, options) == 64);

#[repr(C)]
pub(crate) struct Ftsent {
    cycle: *mut Ftsent,
    parent: *mut Ftsent,
    link: *mut Ftsent,
    number: i64,
    pointer: *mut c_void,
    accpath: *mut c_char,
    path: *mut c_char,
    errno: c_int,
    symfd: c_int,
    pathlen: u16,
    namelen: u16,
    _pad_ino: u32,
    ino: u64,
    dev: i32,
    nlink: u16,
    level: i16,
    info: u16,
    flags: u16,
    instr: u16,
    _pad_stat: u16,
    statp: *mut c_void,
    name: [c_char; 1],
}

const _: () = assert!(core::mem::offset_of!(Ftsent, cycle) == 0);
const _: () = assert!(core::mem::offset_of!(Ftsent, parent) == 8);
const _: () = assert!(core::mem::offset_of!(Ftsent, link) == 16);
const _: () = assert!(core::mem::offset_of!(Ftsent, number) == 24);
const _: () = assert!(core::mem::offset_of!(Ftsent, pointer) == 32);
const _: () = assert!(core::mem::offset_of!(Ftsent, accpath) == 40);
const _: () = assert!(core::mem::offset_of!(Ftsent, path) == 48);
const _: () = assert!(core::mem::offset_of!(Ftsent, errno) == 56);
const _: () = assert!(core::mem::offset_of!(Ftsent, symfd) == 60);
const _: () = assert!(core::mem::offset_of!(Ftsent, pathlen) == 64);
const _: () = assert!(core::mem::offset_of!(Ftsent, namelen) == 66);
const _: () = assert!(core::mem::offset_of!(Ftsent, ino) == 72);
const _: () = assert!(core::mem::offset_of!(Ftsent, dev) == 80);
const _: () = assert!(core::mem::offset_of!(Ftsent, nlink) == 84);
const _: () = assert!(core::mem::offset_of!(Ftsent, level) == 86);
const _: () = assert!(core::mem::offset_of!(Ftsent, info) == 88);
const _: () = assert!(core::mem::offset_of!(Ftsent, flags) == 90);
const _: () = assert!(core::mem::offset_of!(Ftsent, instr) == 92);
const _: () = assert!(core::mem::offset_of!(Ftsent, statp) == 96);
const _: () = assert!(core::mem::offset_of!(Ftsent, name) == 104);
const _: () = assert!(core::mem::size_of::<Ftsent>() == 112);

fn fts_ok(sp: *mut Fts) -> bool {
    !sp.is_null() && unsafe { (*sp).magic } == FTS_MAGIC
}

fn cstr_len(p: *const c_char) -> usize {
    if p.is_null() { 0 } else { unsafe { strlen(p) } }
}

unsafe fn cstr_dup(src: *const c_char) -> *mut c_char {
    let n = cstr_len(src);
    let p = unsafe { malloc(n.saturating_add(1)) }.cast::<c_char>();
    if p.is_null() {
        return p;
    }
    if src.is_null() {
        unsafe {
            p.write(0);
        }
    } else {
        unsafe {
            core::ptr::copy_nonoverlapping(src, p, n.saturating_add(1));
        }
    }
    p
}

unsafe fn join_path(dir: *const c_char, name: *const c_char) -> *mut c_char {
    let dn = cstr_len(dir);
    let nn = cstr_len(name);
    if dn == 0 {
        return unsafe { cstr_dup(name) };
    }
    let slash = unsafe { dn == 0 || *dir.add(dn.saturating_sub(1)) != b'/'.cast_signed() };
    let extra = usize::from(slash);
    let p = unsafe {
        malloc(
            dn.saturating_add(extra)
                .saturating_add(nn)
                .saturating_add(1),
        )
    }
    .cast::<c_char>();
    if p.is_null() {
        return p;
    }
    unsafe {
        core::ptr::copy_nonoverlapping(dir, p, dn);
        let mut o = dn;
        if slash {
            p.add(o).write(b'/'.cast_signed());
            o = o.saturating_add(1);
        }
        if !name.is_null() {
            core::ptr::copy_nonoverlapping(name, p.add(o), nn);
        }
        p.add(o.saturating_add(nn)).write(0);
    }
    p
}

fn read_u16(buf: &[u8], off: usize) -> u16 {
    buf.get(off..off.saturating_add(2))
        .and_then(|s| s.try_into().ok())
        .map_or(0, u16::from_le_bytes)
}

fn read_i32(buf: &[u8], off: usize) -> i32 {
    buf.get(off..off.saturating_add(4))
        .and_then(|s| s.try_into().ok())
        .map_or(0, i32::from_le_bytes)
}

fn read_u64(buf: &[u8], off: usize) -> u64 {
    buf.get(off..off.saturating_add(8))
        .and_then(|s| s.try_into().ok())
        .map_or(0, u64::from_le_bytes)
}

unsafe fn alloc_ent(name: *const c_char, parent: *mut Ftsent, level: i16) -> *mut Ftsent {
    let namelen = cstr_len(name);
    let bytes = core::mem::size_of::<Ftsent>()
        .saturating_sub(1)
        .saturating_add(namelen)
        .saturating_add(1);
    let raw = unsafe { malloc(bytes) };
    if raw.is_null() {
        return core::ptr::null_mut();
    }
    unsafe {
        bzero(raw, bytes);
    }
    let e = raw.cast::<Ftsent>();
    unsafe {
        (*e).parent = parent;
        (*e).level = level;
        (*e).instr = FTS_NOINSTR as u16;
        (*e).namelen = u16::try_from(namelen).unwrap_or(u16::MAX);
        if !name.is_null() {
            core::ptr::copy_nonoverlapping(name, (*e).name.as_mut_ptr(), namelen.saturating_add(1));
        }
    }
    e
}

unsafe fn free_ent(e: *mut Ftsent) {
    if e.is_null() {
        return;
    }
    unsafe {
        if !(*e).accpath.is_null() {
            free((*e).accpath.cast());
        }
        if !(*e).statp.is_null() {
            free((*e).statp);
        }
        free(e.cast());
    }
}

unsafe fn free_list(mut e: *mut Ftsent) {
    while !e.is_null() {
        let n = unsafe { (*e).link };
        unsafe {
            free_ent(e);
        }
        e = n;
    }
}

unsafe fn set_paths(e: *mut Ftsent, acc: *mut c_char) {
    unsafe {
        if !(*e).accpath.is_null() {
            free((*e).accpath.cast());
        }
        (*e).accpath = acc;
        (*e).path = acc;
        let n = cstr_len(acc);
        (*e).pathlen = u16::try_from(n).unwrap_or(u16::MAX);
    }
}

unsafe fn apply_stat(e: *mut Ftsent, st: &[u8; STAT_SIZE], follow_ok: bool) {
    let mode = read_u16(st, 4);
    unsafe {
        (*e).ino = read_u64(st, 8);
        (*e).dev = read_i32(st, 0);
        (*e).nlink = read_u16(st, 6);
        if (*e).statp.is_null() {
            (*e).statp = malloc(STAT_SIZE);
        }
        if !(*e).statp.is_null() {
            core::ptr::copy_nonoverlapping(st.as_ptr(), (*e).statp.cast::<u8>(), STAT_SIZE);
        }
        let kind = mode & S_IFMT;
        (*e).info = if kind == S_IFDIR {
            if cycle(e) { FTS_DC } else { FTS_D }
        } else if kind == S_IFLNK {
            if follow_ok { FTS_D } else { FTS_SL }
        } else if kind == S_IFREG {
            FTS_F
        } else {
            FTS_DEFAULT
        };
    }
}

unsafe fn cycle(e: *mut Ftsent) -> bool {
    let (ino, dev) = unsafe { ((*e).ino, (*e).dev) };
    let mut p = unsafe { (*e).parent };
    while !p.is_null() {
        if unsafe { (*p).level } < 0 {
            break;
        }
        if unsafe { (*p).ino == ino && (*p).dev == dev && (*p).info == FTS_D } {
            unsafe {
                (*e).cycle = p;
            }
            return true;
        }
        p = unsafe { (*p).parent };
    }
    false
}

unsafe fn classify(sp: *mut Fts, e: *mut Ftsent, nameonly: bool) {
    let opts = unsafe { (*sp).options };
    let nostat = (opts & (FTS_NOSTAT | FTS_NOSTAT_TYPE)) != 0 || nameonly;
    let logical = (opts & FTS_LOGICAL) != 0;
    let follow_cmd = (opts & FTS_COMFOLLOW) != 0 && unsafe { (*e).level } == FTS_ROOTLEVEL;
    let follow = logical || follow_cmd || unsafe { (*e).instr } == FTS_FOLLOW as u16;

    let name_ptr = unsafe { (*e).name.as_ptr() };
    let namelen = unsafe { (*e).namelen } as usize;
    if namelen == 1 && unsafe { *name_ptr } as u8 == b'.'
        || namelen == 2
            && unsafe { *name_ptr } as u8 == b'.'
            && unsafe { *name_ptr.add(1) } as u8 == b'.'
    {
        unsafe {
            (*e).info = FTS_DOT;
        }
    }

    if nostat && !follow {
        if unsafe { (*e).info } != FTS_DOT {
            unsafe {
                (*e).info = FTS_NSOK;
            }
        }
        return;
    }

    let mut st = [0_u8; STAT_SIZE];
    let acc = unsafe { (*e).accpath };
    let rc = if follow {
        unsafe { stat(acc, st.as_mut_ptr().cast()) }
    } else {
        unsafe { lstat(acc, st.as_mut_ptr().cast()) }
    };
    if rc != 0 {
        if follow {
            let rc2 = unsafe { lstat(acc, st.as_mut_ptr().cast()) };
            if rc2 == 0 && (read_u16(&st, 4) & S_IFMT) == S_IFLNK {
                unsafe {
                    apply_stat(e, &st, false);
                    (*e).info = FTS_SLNONE;
                }
                return;
            }
        }
        unsafe {
            (*e).info = FTS_NS;
            (*e).errno = errno::get_errno();
        }
        return;
    }
    unsafe {
        apply_stat(e, &st, follow && (read_u16(&st, 4) & S_IFMT) == S_IFDIR);
        if (opts & FTS_XDEV) != 0 && (*e).level > 0 && (*e).dev != (*sp).dev && (*e).info == FTS_D {
            (*e).info = FTS_DEFAULT;
        }
        if (*e).level == FTS_ROOTLEVEL && (*sp).dev == 0 {
            (*sp).dev = (*e).dev;
        }
    }
}

unsafe fn sort_fn(compar: Compar) -> Compar {
    let cmp = compar?;
    let raw = crate::kh_core::sys::strip_ptrauth_ia(cmp as usize);
    if raw == 0 {
        return None;
    }
    // SAFETY: guest `fts_compar` after PAC strip; same AAPCS64 signature.
    Some(unsafe { core::mem::transmute::<usize, unsafe extern "C" fn(*const *mut Ftsent, *const *mut Ftsent) -> c_int>(raw) })
}

unsafe fn sort_list(mut head: *mut Ftsent, compar: Compar) -> *mut Ftsent {
    let Some(cmp) = (unsafe { sort_fn(compar) }) else {
        return head;
    };
    let mut arr: [*mut Ftsent; 256] = [core::ptr::null_mut(); 256];
    let mut n = 0_usize;
    while !head.is_null() && n < arr.len() {
        arr[n] = head;
        n = n.saturating_add(1);
        head = unsafe { (*head).link };
    }
    let rest = head;
    let mut i = 1_usize;
    while i < n {
        let key = arr[i];
        let mut j = i;
        while j > 0 {
            let mut left = arr[j - 1];
            let mut right = key;
            let ord = unsafe {
                cmp(
                    core::ptr::addr_of_mut!(left),
                    core::ptr::addr_of_mut!(right),
                )
            };
            if ord <= 0 {
                break;
            }
            arr[j] = arr[j - 1];
            j -= 1;
        }
        arr[j] = key;
        i = i.saturating_add(1);
    }
    let mut out = rest;
    let mut k = n;
    while k > 0 {
        k -= 1;
        unsafe {
            (*arr[k]).link = out;
        }
        out = arr[k];
    }
    out
}

unsafe fn load_children(sp: *mut Fts, parent: *mut Ftsent, nameonly: bool) -> *mut Ftsent {
    let dirp = unsafe { opendir((*parent).accpath) };
    if dirp.is_null() {
        unsafe {
            (*parent).info = FTS_DNR;
            (*parent).errno = errno::get_errno();
        }
        return core::ptr::null_mut();
    }
    let seedot = (unsafe { (*sp).options } & FTS_SEEDOT) != 0;
    let mut head: *mut Ftsent = core::ptr::null_mut();
    loop {
        let ent = unsafe { readdir(dirp) };
        if ent.is_null() {
            break;
        }
        let name = unsafe { ent.cast::<u8>().add(DIRENT_NAME_OFF).cast::<c_char>() };
        let n0 = unsafe { *name } as u8;
        let n1 = unsafe { *name.add(1) } as u8;
        if n0 == b'.' && (n1 == 0 || (n1 == b'.' && unsafe { *name.add(2) } == 0)) && !seedot {
            continue;
        }
        let child = unsafe { alloc_ent(name, parent, (*parent).level.saturating_add(1)) };
        if child.is_null() {
            unsafe {
                (*sp).options |= FTS_STOP;
            }
            break;
        }
        let acc = unsafe { join_path((*parent).accpath, name) };
        if acc.is_null() {
            unsafe {
                free_ent(child);
                (*sp).options |= FTS_STOP;
            }
            break;
        }
        unsafe {
            set_paths(child, acc);
        }
        let dtype = unsafe { ent.cast::<u8>().add(DIRENT_TYPE_OFF).read() };
        if nameonly {
            unsafe {
                (*child).info = FTS_NSOK;
            }
        } else if (unsafe { (*sp).options } & FTS_NOSTAT_TYPE) != 0 && dtype != 0 {
            unsafe {
                (*child).info = match dtype {
                    DT_DIR => FTS_D,
                    DT_LNK => FTS_SL,
                    DT_REG => FTS_F,
                    _ => FTS_DEFAULT,
                };
            }
        } else {
            unsafe {
                classify(sp, child, false);
            }
        }
        unsafe {
            (*child).link = head;
        }
        head = child;
    }
    let _ = unsafe { closedir(dirp) };
    unsafe { sort_list(head, (*sp).compar) }
}

unsafe fn publish_path(sp: *mut Fts, e: *mut Ftsent) {
    let acc = unsafe { (*e).accpath };
    let n = cstr_len(acc).saturating_add(1);
    unsafe {
        if (*sp).path.is_null() || ((*sp).path_cap as usize) < n {
            if !(*sp).path.is_null() {
                free((*sp).path.cast());
            }
            let cap = n.max(64);
            (*sp).path = malloc(cap).cast();
            (*sp).path_cap = u32::try_from(cap).unwrap_or(0);
            (*sp).pathlen = c_int::try_from(cap).unwrap_or(0);
        }
        if !(*sp).path.is_null() && !acc.is_null() {
            core::ptr::copy_nonoverlapping(acc, (*sp).path, n);
            (*e).path = (*sp).path;
        }
        (*sp).cur = e;
        (*sp).child = core::ptr::null_mut();
    }
}

unsafe fn next_after(sp: *mut Fts, cur: *mut Ftsent) -> *mut Ftsent {
    let sib = unsafe { (*cur).link };
    if !sib.is_null() {
        return sib;
    }
    let parent = unsafe { (*cur).parent };
    if parent.is_null() || unsafe { (*parent).level } < 0 {
        return core::ptr::null_mut();
    }
    unsafe {
        (*parent).info = FTS_DP;
        (*parent).flags |= FLAG_DESCENDED;
    }
    let _ = sp;
    parent
}

/// C `fts_open` → nlist `_fts_open`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn fts_open(
    argv: *const *const c_char,
    options: c_int,
    compar: Compar,
) -> *mut Fts {
    if argv.is_null() || (options & !FTS_OPTIONMASK) != 0 {
        errno::set_errno(EINVAL);
        return core::ptr::null_mut();
    }
    if (options & (FTS_LOGICAL | FTS_PHYSICAL)) == 0 {
        errno::set_errno(EINVAL);
        return core::ptr::null_mut();
    }
    let raw = unsafe { malloc(core::mem::size_of::<Fts>()) };
    if raw.is_null() {
        errno::set_errno(ENOMEM);
        return core::ptr::null_mut();
    }
    unsafe {
        bzero(raw, core::mem::size_of::<Fts>());
    }
    let sp = raw.cast::<Fts>();
    unsafe {
        (*sp).magic = FTS_MAGIC;
        (*sp).options = options | FTS_NOCHDIR;
        (*sp).compar = compar;
        (*sp).rfd = -1;
    }
    let dummy = unsafe {
        alloc_ent(
            core::ptr::null(),
            core::ptr::null_mut(),
            FTS_ROOTPARENTLEVEL,
        )
    };
    if dummy.is_null() {
        unsafe {
            free(raw);
        }
        errno::set_errno(ENOMEM);
        return core::ptr::null_mut();
    }
    let slash = c"/".as_ptr();
    let acc = unsafe { cstr_dup(slash) };
    if acc.is_null() {
        unsafe {
            free_ent(dummy);
            free(raw);
        }
        errno::set_errno(ENOMEM);
        return core::ptr::null_mut();
    }
    unsafe {
        set_paths(dummy, acc);
        (*dummy).info = FTS_D;
    }
    let mut head: *mut Ftsent = core::ptr::null_mut();
    let mut tail: *mut Ftsent = core::ptr::null_mut();
    let mut i = 0_usize;
    loop {
        let p = unsafe { argv.add(i).read() };
        if p.is_null() {
            break;
        }
        if unsafe { *p } == 0 {
            errno::set_errno(ENOENT);
            unsafe {
                free_list(head);
                free_ent(dummy);
                free(raw);
            }
            return core::ptr::null_mut();
        }
        let e = unsafe { alloc_ent(p, dummy, FTS_ROOTLEVEL) };
        if e.is_null() {
            unsafe {
                free_list(head);
                free_ent(dummy);
                free(raw);
            }
            errno::set_errno(ENOMEM);
            return core::ptr::null_mut();
        }
        let path = unsafe { cstr_dup(p) };
        if path.is_null() {
            unsafe {
                free_ent(e);
                free_list(head);
                free_ent(dummy);
                free(raw);
            }
            errno::set_errno(ENOMEM);
            return core::ptr::null_mut();
        }
        unsafe {
            set_paths(e, path);
            classify(sp, e, false);
        }
        if tail.is_null() {
            head = e;
        } else {
            unsafe {
                (*tail).link = e;
            }
        }
        tail = e;
        i = i.saturating_add(1);
    }
    if head.is_null() {
        errno::set_errno(EINVAL);
        unsafe {
            free_ent(dummy);
            free(raw);
        }
        return core::ptr::null_mut();
    }
    head = unsafe { sort_list(head, compar) };
    unsafe {
        (*dummy).link = head;
        (*sp).cur = dummy;
    }
    sp
}

/// C `fts_open$INODE64` → nlist `_fts_open$INODE64`.
#[unsafe(export_name = "fts_open$INODE64")]
pub(crate) unsafe extern "C" fn fts_open_inode64(
    argv: *const *const c_char,
    options: c_int,
    compar: Compar,
) -> *mut Fts {
    unsafe { fts_open(argv, options, compar) }
}

/// C `fts_read` → nlist `_fts_read`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn fts_read(sp: *mut Fts) -> *mut Ftsent {
    if !fts_ok(sp) {
        errno::set_errno(EINVAL);
        return core::ptr::null_mut();
    }
    if (unsafe { (*sp).options } & FTS_STOP) != 0 {
        return core::ptr::null_mut();
    }
    let cur = unsafe { (*sp).cur };
    if cur.is_null() {
        return core::ptr::null_mut();
    }
    if unsafe { (*cur).instr } == FTS_AGAIN as u16 {
        unsafe {
            (*cur).instr = FTS_NOINSTR as u16;
            classify(sp, cur, false);
            publish_path(sp, cur);
        }
        return cur;
    }
    let next = if unsafe { (*cur).level } < 0 {
        unsafe { (*cur).link }
    } else if unsafe { (*cur).info } == FTS_D
        && (unsafe { (*cur).flags } & FLAG_DESCENDED) == 0
        && unsafe { (*cur).instr } != FTS_SKIP as u16
    {
        let kids = unsafe { load_children(sp, cur, false) };
        unsafe {
            (*cur).flags |= FLAG_DESCENDED;
        }
        if kids.is_null() {
            if unsafe { (*cur).info } == FTS_DNR {
                unsafe {
                    publish_path(sp, cur);
                }
                return cur;
            }
            unsafe {
                (*cur).info = FTS_DP;
            }
            cur
        } else {
            kids
        }
    } else {
        unsafe { next_after(sp, cur) }
    };
    if next.is_null() {
        unsafe {
            (*sp).cur = core::ptr::null_mut();
        }
        return core::ptr::null_mut();
    }
    if unsafe { (*next).instr } == FTS_FOLLOW as u16 {
        unsafe {
            classify(sp, next, false);
            (*next).instr = FTS_NOINSTR as u16;
        }
    }
    unsafe {
        publish_path(sp, next);
    }
    next
}

/// C `fts_read$INODE64` → nlist `_fts_read$INODE64`.
#[unsafe(export_name = "fts_read$INODE64")]
pub(crate) unsafe extern "C" fn fts_read_inode64(sp: *mut Fts) -> *mut Ftsent {
    unsafe { fts_read(sp) }
}

/// C `fts_children` → nlist `_fts_children`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn fts_children(sp: *mut Fts, instr: c_int) -> *mut Ftsent {
    if !fts_ok(sp) {
        errno::set_errno(EINVAL);
        return core::ptr::null_mut();
    }
    let cur = unsafe { (*sp).cur };
    if cur.is_null() {
        return core::ptr::null_mut();
    }
    let nameonly = instr == FTS_NAMEONLY;
    if unsafe { (*cur).level } < 0 {
        unsafe {
            (*sp).child = (*cur).link;
        }
        return unsafe { (*sp).child };
    }
    if unsafe { (*cur).info } != FTS_D {
        return core::ptr::null_mut();
    }
    let kids = unsafe { load_children(sp, cur, nameonly) };
    unsafe {
        (*sp).child = kids;
    }
    kids
}

/// C `fts_children$INODE64` → nlist `_fts_children$INODE64`.
#[unsafe(export_name = "fts_children$INODE64")]
pub(crate) unsafe extern "C" fn fts_children_inode64(sp: *mut Fts, instr: c_int) -> *mut Ftsent {
    unsafe { fts_children(sp, instr) }
}

/// C `fts_set` → nlist `_fts_set`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn fts_set(sp: *mut Fts, ent: *mut Ftsent, instr: c_int) -> c_int {
    if !fts_ok(sp) || ent.is_null() {
        errno::set_errno(EINVAL);
        return -1;
    }
    if instr != FTS_AGAIN && instr != FTS_FOLLOW && instr != FTS_NOINSTR && instr != FTS_SKIP {
        errno::set_errno(EINVAL);
        return -1;
    }
    unsafe {
        (*ent).instr = instr as u16;
    }
    0
}

/// C `fts_set$INODE64` → nlist `_fts_set$INODE64`.
#[unsafe(export_name = "fts_set$INODE64")]
pub(crate) unsafe extern "C" fn fts_set_inode64(
    sp: *mut Fts,
    ent: *mut Ftsent,
    instr: c_int,
) -> c_int {
    unsafe { fts_set(sp, ent, instr) }
}

unsafe fn free_tree(e: *mut Ftsent) {
    if e.is_null() {
        return;
    }
    let mut n = e;
    while !n.is_null() {
        let next = unsafe { (*n).link };
        unsafe {
            free_ent(n);
        }
        n = next;
    }
}

/// C `fts_close` → nlist `_fts_close`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn fts_close(sp: *mut Fts) -> c_int {
    if !fts_ok(sp) {
        errno::set_errno(EINVAL);
        return -1;
    }
    unsafe {
        (*sp).magic = 0;
        let mut cur = (*sp).cur;
        if !cur.is_null() {
            while !(*cur).parent.is_null() && (*(*cur).parent).level >= 0 {
                cur = (*cur).parent;
            }
            if (*cur).level < 0 {
                free_tree((*cur).link);
                free_ent(cur);
            } else {
                free_tree(cur);
            }
        }
        if !(*sp).path.is_null() {
            free((*sp).path.cast());
        }
        free(sp.cast());
    }
    0
}

/// C `fts_close$INODE64` → nlist `_fts_close$INODE64`.
#[unsafe(export_name = "fts_close$INODE64")]
pub(crate) unsafe extern "C" fn fts_close_inode64(sp: *mut Fts) -> c_int {
    unsafe { fts_close(sp) }
}
