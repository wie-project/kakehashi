# Syscall / helper coverage
Snapshot of what freestanding `kh-libsystem` and `kh-runtime` know.
Not a full XNU `syscalls.master` — only numbers we touch.
States: **done** (dispatched / wrapped), **stub** (soft), **missing** (neither).

## BSD syscalls (runtime table)
| # | name | freestanding `SYS_*` | notes |
| ---: | --- | --- | --- |
| 1 | `exit` | yes | done |
| 2 | `fork` | yes | done |
| 3 | `read` | yes | done |
| 4 | `write` | yes | done |
| 5 | `open` | yes | done |
| 6 | `close` | yes | done |
| 7 | `wait4` | yes | done |
| 9 | `link` | yes | done |
| 10 | `unlink` | yes | done |
| 12 | `chdir` | yes | done |
| 20 | `getpid` | yes | done |
| 24 | `getuid` | yes | done |
| 25 | `geteuid` | yes | done |
| 29 | `recvfrom` | yes | done |
| 30 | `accept` | yes | done |
| 31 | `getpeername` | yes | done |
| 32 | `getsockname` | yes | done |
| 33 | `access` | yes | done |
| 39 | `getppid` | yes | done |
| 41 | `dup` | yes | done |
| 42 | `pipe` | yes | done |
| 43 | `getegid` | yes | done |
| 46 | `sigaction` | yes | done |
| 47 | `getgid` | yes | done |
| 48 | `sigprocmask` | yes | done |
| 54 | `ioctl` | yes | done (tty / termios / FION*) |
| 57 | `symlink` | yes | done |
| 58 | `readlink` | yes | done |
| 59 | `execve` | yes | done |
| 65 | `msync` | — | done |
| 66 | `vfork` | yes | done |
| 73 | `munmap` | yes | done |
| 74 | `mprotect` | yes | done |
| 90 | `dup2` | yes | done |
| 92 | `fcntl` | yes | done |
| 93 | `select` | yes | done |
| 95 | `fsync` | yes | done |
| 97 | `socket` | yes | done |
| 98 | `connect` | yes | done |
| 104 | `bind` | yes | done |
| 105 | `setsockopt` | yes | done |
| 106 | `listen` | yes | done |
| 116 | `gettimeofday` | yes | done |
| 118 | `getsockopt` | yes | done |
| 124 | `fchmod` | yes | done |
| 128 | `rename` | yes | done |
| 133 | `sendto` | yes | done |
| 134 | `shutdown` | yes | done |
| 136 | `mkdir` | yes | done |
| 137 | `rmdir` | yes | done |
| 153 | `pread` | yes | done |
| 154 | `pwrite` | yes | done |
| 197 | `mmap` | yes | done |
| 199 | `lseek` | yes | done |
| 201 | `ftruncate` | yes | done |
| 202 | `sysctl` | yes | done |
| 230 | `poll` | yes | done |
| 266 | `clock_gettime` | — | done |
| 274 | `sysctlbyname` | yes | done |
| 327 | `issetugid` | — | done |
| 338 | `stat` | yes | done |
| 339 | `fstat` | yes | done |
| 340 | `lstat` | yes | done |
| 344 | `__getcwd` | yes | done |
| 360 | `bsdthread_create` | yes | done |
| 361 | `bsdthread_terminate` | yes | done |
| 366 | `bsdthread_register` | yes | done |
| 372 | `thread_selfid` | — | done |
| 463 | `openat` | yes | done |
| 470 | `fstatat` | yes | done |

### Freestanding-only numbers

| # | freestanding | notes |
| ---: | --- | --- |
| 27 | `SYS_RECVMSG` | thin wrap; check runtime |
| 28 | `SYS_SENDMSG` | thin wrap; check runtime |
| 37 | `SYS_KILL` | thin wrap; check runtime |
| 54 | `SYS_IOCTL` | tty / termios / FION* via runtime |
| 81 | `SYS_GETPGRP` | thin wrap; check runtime |
| 82 | `SYS_SETPGID` | thin wrap; check runtime |
| 135 | `SYS_SOCKETPAIR` | thin wrap; check runtime |
| 147 | `SYS_SETSID` | thin wrap; check runtime |

### Runtime-only (no freestanding `SYS_*` constant yet)

| # | name | notes |
| ---: | --- | --- |
| 65 | `msync` | runtime dispatch only |
| 266 | `clock_gettime` | runtime dispatch only |
| 327 | `issetugid` | runtime dispatch only |
| 372 | `thread_selfid` | runtime dispatch only |

## Host helpers (`0x4B48_xxxx`)

| id | name |
| --- | --- |
| `0x4B48_0001` | `KH_HELPER_PUTS` |
| `0x4B48_0002` | `KH_HELPER_PRINTF` |
| `0x4B48_0003` | `KH_HELPER_READDIR` |
| `0x4B48_0004` | `KH_HELPER_YIELD` |
| `0x4B48_0005` | `KH_HELPER_NCPU` |
| `0x4B48_0006` | `KH_HELPER_PARK` |
| `0x4B48_0007` | `KH_HELPER_WAKE` |
| `0x4B48_0008` | `KH_HELPER_GETADDRINFO` |
| `0x4B48_0009` | `KH_HELPER_VERIFY_CERT` |
| `0x4B48_000A` | `KH_HELPER_GUEST_HOME` |
| `0x4B48_000B` | `KH_HELPER_HEAP_STATS_ON` |
| `0x4B48_000C` | `KH_HELPER_HTTP` |
| `0x4B48_000D` | `KH_HELPER_GETENV` |
| `0x4B48_000E` | `KH_HELPER_REGCOMP` |
| `0x4B48_000F` | `KH_HELPER_REGEXEC` |
| `0x4B48_0010` | `KH_HELPER_REGFREE` |
| `0x4B48_0011` | `KH_HELPER_TLS_CONNECT` |
| `0x4B48_0012` | `KH_HELPER_EXECUTABLE_PATH` |
| `0x4B48_0013` | `KH_HELPER_DLOPEN` |
| `0x4B48_0014` | `KH_HELPER_DLSYM` |
| `0x4B48_0015` | `KH_HELPER_SPAWN` |

## Gaps (full Darwin surface)

Apple XNU exposes hundreds of BSD numbers. Unlisted numbers return `ENOSYS` from the runtime table. Expand by:

1. Adding a row to `kh-runtime` `syscall/table.rs` + handler.
2. Adding `SYS_*` + thin wrapper in `kh-libsystem` if guests call it via libc.
