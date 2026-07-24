//! Darwin BSD syscall numbers used by the micro translator (arm64).

/// Known BSD syscalls we dispatch (subset of XNU `syscalls.master`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BsdSyscall {
    /// `exit`.
    Exit,
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
    /// `stat` / `stat64`.
    Stat,
    /// `fstat` / `fstat64`.
    Fstat,
    /// `openat`.
    Openat,
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
}

impl BsdSyscall {
    /// Trace / CLI label.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Exit => "exit",
            Self::Read => "read",
            Self::Write => "write",
            Self::Open => "open",
            Self::Close => "close",
            Self::Getpid => "getpid",
            Self::Access => "access",
            Self::Issetugid => "issetugid",
            Self::Munmap => "munmap",
            Self::Mprotect => "mprotect",
            Self::Mmap => "mmap",
            Self::Msync => "msync",
            Self::Dup => "dup",
            Self::Fcntl => "fcntl",
            Self::Lseek => "lseek",
            Self::Stat => "stat",
            Self::Fstat => "fstat",
            Self::Openat => "openat",
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
        }
    }

    /// Primary Darwin syscall number.
    #[must_use]
    pub const fn number(self) -> u32 {
        match self {
            Self::Exit => 1,
            Self::Read => 3,
            Self::Write => 4,
            Self::Open => 5,
            Self::Close => 6,
            Self::Getpid => 20,
            Self::Access => 33,
            Self::Dup => 41,
            Self::Sigaction => 46,
            Self::Sigprocmask => 48,
            Self::Msync => 65,
            Self::Munmap => 73,
            Self::Mprotect => 74,
            Self::Fcntl => 92,
            Self::Gettimeofday => 116,
            Self::Mmap => 197,
            Self::Lseek => 199,
            Self::Sysctl => 202,
            Self::ClockGettime => 266,
            Self::Sysctlbyname => 274,
            Self::Issetugid => 327,
            // Prefer 64-bit variants as primary; aliases in lookup.
            Self::Stat => 338,
            Self::Fstat => 339,
            Self::BsdthreadCreate => 360,
            Self::BsdthreadTerminate => 361,
            Self::BsdthreadRegister => 366,
            Self::ThreadSelfid => 372,
            Self::Openat => 463,
        }
    }
}

/// Looks up a syscall by Darwin number (includes NOCANCEL / 64-bit aliases).
#[must_use]
pub const fn lookup(number: u32) -> Option<BsdSyscall> {
    match number {
        1 => Some(BsdSyscall::Exit),
        3 | 396 => Some(BsdSyscall::Read),
        4 | 397 => Some(BsdSyscall::Write),
        5 | 398 => Some(BsdSyscall::Open),
        6 | 399 => Some(BsdSyscall::Close),
        20 => Some(BsdSyscall::Getpid),
        33 => Some(BsdSyscall::Access),
        41 => Some(BsdSyscall::Dup),
        46 => Some(BsdSyscall::Sigaction),
        48 => Some(BsdSyscall::Sigprocmask),
        65 => Some(BsdSyscall::Msync),
        73 => Some(BsdSyscall::Munmap),
        74 => Some(BsdSyscall::Mprotect),
        92 => Some(BsdSyscall::Fcntl),
        116 => Some(BsdSyscall::Gettimeofday),
        188 | 338 => Some(BsdSyscall::Stat),  // stat / stat64
        189 | 339 => Some(BsdSyscall::Fstat), // fstat / fstat64
        197 => Some(BsdSyscall::Mmap),
        199 => Some(BsdSyscall::Lseek),
        202 => Some(BsdSyscall::Sysctl),
        266 => Some(BsdSyscall::ClockGettime),
        274 => Some(BsdSyscall::Sysctlbyname),
        327 => Some(BsdSyscall::Issetugid),
        360 => Some(BsdSyscall::BsdthreadCreate),
        361 => Some(BsdSyscall::BsdthreadTerminate),
        366 => Some(BsdSyscall::BsdthreadRegister),
        372 => Some(BsdSyscall::ThreadSelfid),
        463 => Some(BsdSyscall::Openat),
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
        (3, "read"),
        (4, "write"),
        (5, "open"),
        (6, "close"),
        (20, "getpid"),
        (33, "access"),
        (41, "dup"),
        (46, "sigaction"),
        (48, "sigprocmask"),
        (65, "msync"),
        (73, "munmap"),
        (74, "mprotect"),
        (92, "fcntl"),
        (116, "gettimeofday"),
        (197, "mmap"),
        (199, "lseek"),
        (202, "sysctl"),
        (266, "clock_gettime"),
        (274, "sysctlbyname"),
        (327, "issetugid"),
        (338, "stat"),
        (339, "fstat"),
        (360, "bsdthread_create"),
        (361, "bsdthread_terminate"),
        (366, "bsdthread_register"),
        (372, "thread_selfid"),
        (463, "openat"),
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
