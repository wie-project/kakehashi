/* Apple arm64 ABI: `ioctl` is
 *   int ioctl(int fd, unsigned long request, ...);
 * so the optional third argument is on the **stack**, not in x2.
 * A fixed 3-arg Rust export would see a garbage pointer and termios /
 * TIOCGWINSZ would never reach the translator.
 *
 * Same pattern as fcntl_varargs.c (stable Rust has no c_variadic).
 * Impl body is Rust `kh_ioctl_impl`.
 */

#pragma clang diagnostic ignored "-Wbuiltin-requires-header"

typedef __builtin_va_list va_list;
#define va_start __builtin_va_start
#define va_arg __builtin_va_arg
#define va_end __builtin_va_end

extern int kh_ioctl_impl(int fd, unsigned long request, unsigned long arg);

int ioctl(int fd, unsigned long request, ...) {
  unsigned long arg = 0;
  va_list ap;
  va_start(ap, request);
  /* Apple arm64: each variadic slot is 8 bytes. VOID requests ignore arg. */
  arg = va_arg(ap, unsigned long);
  va_end(ap);
  return kh_ioctl_impl(fd, request, arg);
}
