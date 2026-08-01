//! Darwin BSD syscall numbers used by the micro translator (arm64).

/// Known BSD syscalls we dispatch (subset of XNU `syscalls.master`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BsdSyscall {
    /// `exit`.
    Exit,
    /// `fork`.
    Fork,
    /// `vfork` (translator: same as `fork`).
    Vfork,
    /// `wait4` / `waitpid`.
    Wait4,
    /// `execve`.
    Execve,
    /// `dup2`.
    Dup2,
    /// `setsid`.
    Setsid,
    /// `setpgid`.
    Setpgid,
    /// `getpgrp`.
    Getpgrp,
    /// `kill`.
    Kill,
    /// `read`.
    Read,
    /// `write`.
    Write,
    /// `open`.
    Open,
    /// `close`.
    Close,
    /// `getpid`.
    Getpid,
    /// `getppid`.
    Getppid,
    /// `getuid`.
    Getuid,
    /// `geteuid`.
    Geteuid,
    /// `getgid`.
    Getgid,
    /// `getegid`.
    Getegid,
    /// `access`.
    Access,
    /// `issetugid`.
    Issetugid,
    /// `munmap`.
    Munmap,
    /// `mprotect`.
    Mprotect,
    /// `mmap`.
    Mmap,
    /// `msync`.
    Msync,
    /// `dup`.
    Dup,
    /// `fcntl`.
    Fcntl,
    /// `lseek`.
    Lseek,
    /// `pread`.
    Pread,
    /// `pwrite`.
    Pwrite,
    /// `stat` / `stat64`.
    Stat,
    /// `fstat` / `fstat64`.
    Fstat,
    /// `lstat` / `lstat64`.
    Lstat,
    /// `unlink`.
    Unlink,
    /// `link` (hard link).
    Link,
    /// `symlink`.
    Symlink,
    /// `readlink`.
    Readlink,
    /// `mkdir`.
    Mkdir,
    /// `rmdir`.
    Rmdir,
    /// `chdir`.
    Chdir,
    /// `__getcwd` (fills absolute path buffer).
    Getcwd,
    /// `rename`.
    Rename,
    /// `ftruncate`.
    Ftruncate,
    /// `fsync`.
    Fsync,
    /// `openat`.
    Openat,
    /// `fstatat` / `fstatat64`.
    Fstatat,
    /// `gettimeofday`.
    Gettimeofday,
    /// `clock_gettime`.
    ClockGettime,
    /// `sysctl`.
    Sysctl,
    /// `sysctlbyname`.
    Sysctlbyname,
    /// `sigprocmask`.
    Sigprocmask,
    /// `sigaction`.
    Sigaction,
    /// `bsdthread_create`.
    BsdthreadCreate,
    /// `bsdthread_terminate`.
    BsdthreadTerminate,
    /// `bsdthread_register`.
    BsdthreadRegister,
    /// `thread_selfid`.
    ThreadSelfid,
    /// `pipe`.
    Pipe,
    /// `socket`.
    Socket,
    /// `socketpair`.
    Socketpair,
    /// `connect`.
    Connect,
    /// `bind`.
    Bind,
    /// `listen`.
    Listen,
    /// `accept`.
    Accept,
    /// `setsockopt`.
    Setsockopt,
    /// `getsockopt`.
    Getsockopt,
    /// `shutdown`.
    Shutdown,
    /// `sendto`.
    Sendto,
    /// `recvfrom`.
    Recvfrom,
    /// `sendmsg`.
    Sendmsg,
    /// `recvmsg`.
    Recvmsg,
    /// `send` (often libc → sendto).
    Send,
    /// `recv`.
    Recv,
    /// `poll`.
    Poll,
    /// `select`.
    Select,
    /// `getsockname`.
    Getsockname,
    /// `getpeername`.
    Getpeername,
}

impl BsdSyscall {
    /// Trace / CLI label.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Exit => "exit",
            Self::Fork => "fork",
            Self::Vfork => "vfork",
            Self::Wait4 => "wait4",
            Self::Execve => "execve",
            Self::Dup2 => "dup2",
            Self::Setsid => "setsid",
            Self::Setpgid => "setpgid",
            Self::Getpgrp => "getpgrp",
            Self::Kill => "kill",
            Self::Read => "read",
            Self::Write => "write",
            Self::Open => "open",
            Self::Close => "close",
            Self::Getpid => "getpid",
            Self::Getppid => "getppid",
            Self::Getuid => "getuid",
            Self::Geteuid => "geteuid",
            Self::Getgid => "getgid",
            Self::Getegid => "getegid",
            Self::Access => "access",
            Self::Issetugid => "issetugid",
            Self::Munmap => "munmap",
            Self::Mprotect => "mprotect",
            Self::Mmap => "mmap",
            Self::Msync => "msync",
            Self::Dup => "dup",
            Self::Fcntl => "fcntl",
            Self::Lseek => "lseek",
            Self::Pread => "pread",
            Self::Pwrite => "pwrite",
            Self::Stat => "stat",
            Self::Fstat => "fstat",
            Self::Lstat => "lstat",
            Self::Unlink => "unlink",
            Self::Link => "link",
            Self::Symlink => "symlink",
            Self::Readlink => "readlink",
            Self::Mkdir => "mkdir",
            Self::Rmdir => "rmdir",
            Self::Chdir => "chdir",
            Self::Getcwd => "__getcwd",
            Self::Rename => "rename",
            Self::Ftruncate => "ftruncate",
            Self::Fsync => "fsync",
            Self::Openat => "openat",
            Self::Fstatat => "fstatat",
            Self::Gettimeofday => "gettimeofday",
            Self::ClockGettime => "clock_gettime",
            Self::Sysctl => "sysctl",
            Self::Sysctlbyname => "sysctlbyname",
            Self::Sigprocmask => "sigprocmask",
            Self::Sigaction => "sigaction",
            Self::BsdthreadCreate => "bsdthread_create",
            Self::BsdthreadTerminate => "bsdthread_terminate",
            Self::BsdthreadRegister => "bsdthread_register",
            Self::ThreadSelfid => "thread_selfid",
            Self::Pipe => "pipe",
            Self::Socket => "socket",
            Self::Socketpair => "socketpair",
            Self::Connect => "connect",
            Self::Bind => "bind",
            Self::Listen => "listen",
            Self::Accept => "accept",
            Self::Setsockopt => "setsockopt",
            Self::Getsockopt => "getsockopt",
            Self::Shutdown => "shutdown",
            Self::Sendto => "sendto",
            Self::Recvfrom => "recvfrom",
            Self::Sendmsg => "sendmsg",
            Self::Recvmsg => "recvmsg",
            Self::Send => "send",
            Self::Recv => "recv",
            Self::Poll => "poll",
            Self::Select => "select",
            Self::Getsockname => "getsockname",
            Self::Getpeername => "getpeername",
        }
    }

    /// Primary Darwin syscall number.
    #[must_use]
    pub const fn number(self) -> u32 {
        match self {
            Self::Exit => 1,
            Self::Fork => 2,
            Self::Read => 3,
            Self::Write => 4,
            Self::Open => 5,
            Self::Close => 6,
            Self::Wait4 => 7,
            Self::Unlink => 10,
            Self::Execve => 59,
            Self::Vfork => 66,
            Self::Dup2 => 90,
            Self::Setsid => 147,
            Self::Setpgid => 82,
            Self::Getpgrp => 81,
            Self::Kill => 37,
            Self::Link => 9,
            Self::Getpid => 20,
            Self::Getuid => 24,
            Self::Geteuid => 25,
            Self::Getgid => 47,
            Self::Getegid => 43,
            Self::Getppid => 39,
            Self::Access => 33,
            Self::Dup => 41,
            Self::Symlink => 57,
            Self::Readlink => 58,
            Self::Sigaction => 46,
            Self::Sigprocmask => 48,
            Self::Msync => 65,
            Self::Munmap => 73,
            Self::Mprotect => 74,
            Self::Fcntl => 92,
            Self::Fsync => 95,
            Self::Gettimeofday => 116,
            Self::Rename => 128,
            Self::Mkdir => 136,
            Self::Rmdir => 137,
            Self::Chdir => 12,
            Self::Getcwd => 344,
            Self::Mmap => 197,
            Self::Lseek => 199,
            Self::Pread => 153,
            Self::Pwrite => 154,
            Self::Ftruncate => 201,
            Self::Sysctl => 202,
            Self::ClockGettime => 266,
            Self::Sysctlbyname => 274,
            Self::Issetugid => 327,
            // Prefer 64-bit variants as primary; aliases in lookup.
            Self::Stat => 338,
            Self::Fstat => 339,
            Self::Lstat => 340,
            Self::BsdthreadCreate => 360,
            Self::BsdthreadTerminate => 361,
            Self::BsdthreadRegister => 366,
            Self::ThreadSelfid => 372,
            Self::Openat => 463,
            Self::Fstatat => 470,
            Self::Pipe => 42,
            Self::Accept => 30,
            Self::Recvmsg => 27,
            Self::Sendmsg => 28,
            Self::Recvfrom | Self::Recv => 29,
            Self::Socket => 97,
            Self::Socketpair => 135,
            Self::Connect => 98,
            Self::Bind => 104,
            Self::Setsockopt => 105,
            Self::Listen => 106,
            Self::Getsockopt => 118,
            Self::Sendto | Self::Send => 133,
            Self::Shutdown => 134,
            Self::Select => 93,
            Self::Poll => 230,
            Self::Getpeername => 31,
            Self::Getsockname => 32,
        }
    }
}

/// Looks up a syscall by Darwin number (includes NOCANCEL / 64-bit aliases).
#[must_use]
pub const fn lookup(number: u32) -> Option<BsdSyscall> {
    match number {
        1 => Some(BsdSyscall::Exit),
        2 => Some(BsdSyscall::Fork),
        3 | 396 => Some(BsdSyscall::Read),
        4 | 397 => Some(BsdSyscall::Write),
        5 | 398 => Some(BsdSyscall::Open),
        6 | 399 => Some(BsdSyscall::Close),
        7 | 400 => Some(BsdSyscall::Wait4), // wait4 / wait4_nocancel-ish
        9 => Some(BsdSyscall::Link),
        10 | 401 => Some(BsdSyscall::Unlink),
        12 => Some(BsdSyscall::Chdir),
        20 => Some(BsdSyscall::Getpid),
        24 => Some(BsdSyscall::Getuid),
        25 => Some(BsdSyscall::Geteuid),
        33 => Some(BsdSyscall::Access),
        37 => Some(BsdSyscall::Kill),
        39 => Some(BsdSyscall::Getppid),
        43 => Some(BsdSyscall::Getegid),
        47 => Some(BsdSyscall::Getgid),
        81 => Some(BsdSyscall::Getpgrp),
        82 => Some(BsdSyscall::Setpgid),
        147 => Some(BsdSyscall::Setsid),
        27 | 402 => Some(BsdSyscall::Recvmsg),  // recvmsg / nocancel
        28 | 408 => Some(BsdSyscall::Sendmsg),  // sendmsg / nocancel-ish
        29 | 403 => Some(BsdSyscall::Recvfrom), // recvfrom / nocancel
        30 | 404 => Some(BsdSyscall::Accept),   // accept / nocancel
        31 => Some(BsdSyscall::Getpeername),
        32 => Some(BsdSyscall::Getsockname),
        41 => Some(BsdSyscall::Dup),
        42 | 405 => Some(BsdSyscall::Pipe), // pipe / nocancel-ish
        46 => Some(BsdSyscall::Sigaction),
        48 => Some(BsdSyscall::Sigprocmask),
        57 => Some(BsdSyscall::Symlink),
        58 => Some(BsdSyscall::Readlink),
        59 => Some(BsdSyscall::Execve),
        65 => Some(BsdSyscall::Msync),
        66 => Some(BsdSyscall::Vfork),
        73 => Some(BsdSyscall::Munmap),
        74 => Some(BsdSyscall::Mprotect),
        90 => Some(BsdSyscall::Dup2),
        92 => Some(BsdSyscall::Fcntl),
        93 | 394 => Some(BsdSyscall::Select), // select / select_nocancel
        95 | 406 => Some(BsdSyscall::Fsync),
        97 => Some(BsdSyscall::Socket),
        135 => Some(BsdSyscall::Socketpair),
        98 => Some(BsdSyscall::Connect),
        104 => Some(BsdSyscall::Bind),
        105 => Some(BsdSyscall::Setsockopt),
        106 => Some(BsdSyscall::Listen),
        116 => Some(BsdSyscall::Gettimeofday),
        118 => Some(BsdSyscall::Getsockopt),
        128 => Some(BsdSyscall::Rename),
        153 | 474 => Some(BsdSyscall::Pread),  // pread / pread_nocancel-ish
        154 | 475 => Some(BsdSyscall::Pwrite), // pwrite
        133 | 407 => Some(BsdSyscall::Sendto), // sendto / nocancel
        134 => Some(BsdSyscall::Shutdown),
        136 => Some(BsdSyscall::Mkdir),
        137 => Some(BsdSyscall::Rmdir),
        188 | 338 => Some(BsdSyscall::Stat),  // stat / stat64
        189 | 339 => Some(BsdSyscall::Fstat), // fstat / fstat64
        190 | 340 => Some(BsdSyscall::Lstat), // lstat / lstat64
        197 => Some(BsdSyscall::Mmap),
        199 => Some(BsdSyscall::Lseek),
        201 => Some(BsdSyscall::Ftruncate),
        202 => Some(BsdSyscall::Sysctl),
        230 => Some(BsdSyscall::Poll),
        266 => Some(BsdSyscall::ClockGettime),
        274 => Some(BsdSyscall::Sysctlbyname),
        327 => Some(BsdSyscall::Issetugid),
        344 => Some(BsdSyscall::Getcwd),
        360 => Some(BsdSyscall::BsdthreadCreate),
        361 => Some(BsdSyscall::BsdthreadTerminate),
        366 => Some(BsdSyscall::BsdthreadRegister),
        372 => Some(BsdSyscall::ThreadSelfid),
        463 => Some(BsdSyscall::Openat),
        470 | 471 => Some(BsdSyscall::Fstatat), // fstatat / nocancel
        _ => None,
    }
}

/// Name for a raw number, if known.
#[must_use]
pub const fn name_of(number: u32) -> Option<&'static str> {
    match lookup(number) {
        Some(s) => Some(s.name()),
        None => None,
    }
}

/// Snapshot of the table used by unit tests / docs.
#[must_use]
pub fn known_syscalls() -> &'static [(u32, &'static str)] {
    &[
        (1, "exit"),
        (2, "fork"),
        (3, "read"),
        (4, "write"),
        (5, "open"),
        (6, "close"),
        (7, "wait4"),
        (20, "getpid"),
        (59, "execve"),
        (66, "vfork"),
        (90, "dup2"),
        (24, "getuid"),
        (25, "geteuid"),
        (33, "access"),
        (39, "getppid"),
        (43, "getegid"),
        (47, "getgid"),
        (41, "dup"),
        (46, "sigaction"),
        (48, "sigprocmask"),
        (57, "symlink"),
        (58, "readlink"),
        (65, "msync"),
        (73, "munmap"),
        (74, "mprotect"),
        (92, "fcntl"),
        (116, "gettimeofday"),
        (197, "mmap"),
        (153, "pread"),
        (154, "pwrite"),
        (199, "lseek"),
        (202, "sysctl"),
        (266, "clock_gettime"),
        (274, "sysctlbyname"),
        (327, "issetugid"),
        (9, "link"),
        (10, "unlink"),
        (95, "fsync"),
        (128, "rename"),
        (12, "chdir"),
        (136, "mkdir"),
        (137, "rmdir"),
        (344, "__getcwd"),
        (201, "ftruncate"),
        (338, "stat"),
        (339, "fstat"),
        (340, "lstat"),
        (463, "openat"),
        (470, "fstatat"),
        (360, "bsdthread_create"),
        (361, "bsdthread_terminate"),
        (366, "bsdthread_register"),
        (372, "thread_selfid"),
        (463, "openat"),
        (42, "pipe"),
        (97, "socket"),
        (98, "connect"),
        (104, "bind"),
        (105, "setsockopt"),
        (106, "listen"),
        (118, "getsockopt"),
        (133, "sendto"),
        (134, "shutdown"),
        (29, "recvfrom"),
        (30, "accept"),
        (93, "select"),
        (230, "poll"),
        (31, "getpeername"),
        (32, "getsockname"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_table_consistent() {
        for &(num, name) in known_syscalls() {
            assert_eq!(name_of(num), Some(name));
            assert_eq!(lookup(num).map(BsdSyscall::name), Some(name));
        }
    }

    #[test]
    fn nocancel_and_stat_aliases() {
        assert_eq!(lookup(396), Some(BsdSyscall::Read));
        assert_eq!(lookup(397), Some(BsdSyscall::Write));
        assert_eq!(lookup(398), Some(BsdSyscall::Open));
        assert_eq!(lookup(399), Some(BsdSyscall::Close));
        assert_eq!(lookup(188), Some(BsdSyscall::Stat));
        assert_eq!(lookup(189), Some(BsdSyscall::Fstat));
    }
}
