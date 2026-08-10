/* Apple arm64 ABI: `fcntl` is
 *   int fcntl(int fildes, int cmd, ...);
 * so the optional third argument is on the **stack**, not in x2.
 * Curl multi sets O_NONBLOCK via fcntl(F_SETFL, …); a fixed 3-arg Rust
 * export never saw the real flags → host pipes stayed “guest blocking”
 * and empty wakeup-pipe reads hung forever (docker-curl-options tier1).
 *
 * Same pattern as curl_varargs.c / printf_fmt.c (stable Rust has no
 * c_variadic). Impl body is Rust `kh_fcntl_impl`.
 */

#pragma clang diagnostic ignored "-Wbuiltin-requires-header"

typedef __builtin_va_list va_list;
#define va_start __builtin_va_start
#define va_arg __builtin_va_arg
#define va_end __builtin_va_end

/* Darwin fcntl cmds that take a third argument (subset). */
#define F_DUPFD 0
#define F_SETFD 2
#define F_SETFL 4
#define F_SETOWN 6
#define F_SETLK 8
#define F_SETLKW 9
#define F_SETLKWTIMEOUT 10
#define F_FLUSH_DATA 40
#define F_CHKCLEAN 41
#define F_PREALLOCATE 42
#define F_SETSIZE 43
#define F_RDADVISE 44
#define F_RDAHEAD 45
#define F_NOCACHE 48
#define F_LOG2PHYS 49
#define F_GETPATH 50
#define F_FULLFSYNC 51
#define F_PATHPKG_CHECK 52
#define F_FREEZE_FS 53
#define F_THAW_FS 54
#define F_GLOBAL_NOCACHE 55
#define F_ADDSIGS 59
#define F_ADDFILESIGS 61
#define F_NODIRECT 62
#define F_GETPROTECTIONCLASS 63
#define F_SETPROTECTIONCLASS 64
#define F_LOG2PHYS_EXT 65
#define F_GETPATH_MTMINFO 71
#define F_GETCODEDIR 72
#define F_SETNOSIGPIPE 73
#define F_GETNOSIGPIPE 74
#define F_TRANSCODEKEY 75
#define F_SINGLE_WRITER 76
#define F_GETPROTECTIONLEVEL 77
#define F_FINDSIGS 78
#define F_ADDFILESIGS_FOR_DYLD_SIM 83
#define F_BARRIERFSYNC 85
#define F_ADDFILESIGS_RETURN 97
#define F_CHECK_LV 98
#define F_PUNCHHOLE 99
#define F_TRIM_ACTIVE_FILE 100
#define F_SPECULATIVE_READ 101
#define F_GETPATH_NOFIRMLINK 102
#define F_ADDFILESIGS_INFO 103
#define F_ADDFILESUPPL 104
#define F_GETSIGSINFO 105
#define F_SETLEASE 111
#define F_GETLEASE 112
#define F_SETLEASE_ARG 113
#define F_TRANSFEREXTENTS 114
#define F_ATTRIBUTION_TAG 115
#define F_DUPFD_CLOEXEC 67

extern int kh_fcntl_impl(int fd, int cmd, unsigned long long arg);

static int fcntl_cmd_takes_arg(int cmd) {
  switch (cmd) {
  case F_DUPFD:
  case F_SETFD:
  case F_SETFL:
  case F_SETOWN:
  case F_SETLK:
  case F_SETLKW:
  case F_SETLKWTIMEOUT:
  case F_PREALLOCATE:
  case F_SETSIZE:
  case F_RDADVISE:
  case F_RDAHEAD:
  case F_NOCACHE:
  case F_LOG2PHYS:
  case F_GETPATH:
  case F_PATHPKG_CHECK:
  case F_GLOBAL_NOCACHE:
  case F_ADDSIGS:
  case F_ADDFILESIGS:
  case F_NODIRECT:
  case F_SETPROTECTIONCLASS:
  case F_LOG2PHYS_EXT:
  case F_GETPATH_MTMINFO:
  case F_GETCODEDIR:
  case F_SETNOSIGPIPE:
  case F_TRANSCODEKEY:
  case F_SINGLE_WRITER:
  case F_FINDSIGS:
  case F_ADDFILESIGS_FOR_DYLD_SIM:
  case F_ADDFILESIGS_RETURN:
  case F_CHECK_LV:
  case F_PUNCHHOLE:
  case F_TRIM_ACTIVE_FILE:
  case F_SPECULATIVE_READ:
  case F_GETPATH_NOFIRMLINK:
  case F_ADDFILESIGS_INFO:
  case F_ADDFILESUPPL:
  case F_GETSIGSINFO:
  case F_SETLEASE:
  case F_SETLEASE_ARG:
  case F_TRANSFEREXTENTS:
  case F_ATTRIBUTION_TAG:
  case F_DUPFD_CLOEXEC:
    return 1;
  default:
    return 0;
  }
}

int fcntl(int fd, int cmd, ...) {
  unsigned long long arg = 0;
  if (fcntl_cmd_takes_arg(cmd)) {
    va_list ap;
    va_start(ap, cmd);
    /* Apple arm64: each variadic slot is 8 bytes. */
    arg = va_arg(ap, unsigned long long);
    va_end(ap);
  }
  return kh_fcntl_impl(fd, cmd, arg);
}
