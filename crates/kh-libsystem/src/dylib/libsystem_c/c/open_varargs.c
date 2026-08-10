/* Apple arm64 ABI: `open` / `openat` are
 *   int open(const char *path, int oflag, ...);
 *   int openat(int fd, const char *path, int oflag, ...);
 * so the optional mode argument is on the **stack**, not in x2/x3.
 *
 * A fixed 3-arg Rust `open` left mode as register garbage → host files
 * created as mode 0001 (`---------x`) after we started honoring mode for
 * executable products. Same pattern as fcntl_varargs.c.
 *
 * Impl body is Rust `kh_open_impl` / `kh_openat_impl`.
 */

#pragma clang diagnostic ignored "-Wbuiltin-requires-header"

typedef __builtin_va_list va_list;
#define va_start __builtin_va_start
#define va_arg __builtin_va_arg
#define va_end __builtin_va_end

/* Darwin open flags that require a mode argument. */
#define O_CREAT 0x00000200
#define O_TMPFILE 0x20000000 /* Linux; harmless if unset on Darwin */

extern int kh_open_impl(const char *path, int oflag, int mode);
extern int kh_openat_impl(int fd, const char *path, int oflag, int mode);

int open(const char *path, int oflag, ...) {
  int mode = 0;
  if (oflag & (O_CREAT | O_TMPFILE)) {
    va_list ap;
    va_start(ap, oflag);
    mode = va_arg(ap, int);
    va_end(ap);
  }
  return kh_open_impl(path, oflag, mode);
}

int openat(int fd, const char *path, int oflag, ...) {
  int mode = 0;
  if (oflag & (O_CREAT | O_TMPFILE)) {
    va_list ap;
    va_start(ap, oflag);
    mode = va_arg(ap, int);
    va_end(ap);
  }
  return kh_openat_impl(fd, path, oflag, mode);
}
