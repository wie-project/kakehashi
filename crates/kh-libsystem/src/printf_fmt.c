/* Minimal freestanding *printf for Darwin curl G1 (kh-libsystem).
 * Linked into libkh_libsystem.dylib via build.rs (cc).
 * Supports %s %d %i %u %x %X %c %p %% and simple width/0-pad.
 *
 * Why C (not Rust): stable Rust has no c_variadic; curl imports snprintf /
 * fprintf with `...`. This file is freestanding (-ffreestanding) and only
 * calls Rust exports write / fileno / _exit — not host libc bodies.
 */

/* clangd/Zed: we intentionally redeclare printf-family without <stdio.h>. */
#pragma clang diagnostic ignored "-Wbuiltin-requires-header"

typedef unsigned long size_t;
typedef long ssize_t;
typedef int int32_t;
typedef long long int64_t;
typedef unsigned long long uint64_t;
typedef __builtin_va_list va_list;
#define va_start __builtin_va_start
#define va_arg __builtin_va_arg
#define va_end __builtin_va_end
#define va_copy __builtin_va_copy

extern ssize_t write(int fd, const void *buf, size_t nbyte);
extern int fileno(void *stream);

static void push_byte(char *dst, size_t cap, size_t *out_len, unsigned char b) {
  if (dst && cap > 0) {
    size_t idx = *out_len;
    if (idx + 1 < cap)
      dst[idx] = (char)b;
  }
  *out_len = *out_len + 1;
}

static void push_u64(char *dst, size_t cap, size_t *out_len, uint64_t v,
                     size_t width, int zero_pad, unsigned base, int upper) {
  char buf[32];
  size_t n = 0;
  if (v == 0) {
    buf[0] = '0';
    n = 1;
  } else {
    while (v > 0 && n < sizeof(buf)) {
      unsigned d = (unsigned)(v % base);
      if (d < 10)
        buf[n++] = (char)('0' + d);
      else
        buf[n++] = (char)((upper ? 'A' : 'a') + (d - 10));
      v /= base;
    }
  }
  size_t pad = width > n ? width - n : 0;
  unsigned char pad_byte = zero_pad ? '0' : ' ';
  for (size_t i = 0; i < pad; i++)
    push_byte(dst, cap, out_len, pad_byte);
  while (n > 0) {
    n--;
    push_byte(dst, cap, out_len, (unsigned char)buf[n]);
  }
}

static void push_i64(char *dst, size_t cap, size_t *out_len, int64_t v,
                     size_t width, int zero_pad) {
  if (v < 0) {
    push_byte(dst, cap, out_len, '-');
    push_u64(dst, cap, out_len, (uint64_t)(-v), width > 0 ? width - 1 : 0,
             zero_pad, 10, 0);
  } else {
    push_u64(dst, cap, out_len, (uint64_t)v, width, zero_pad, 10, 0);
  }
}

static size_t c_strlen(const char *s) {
  size_t n = 0;
  if (!s)
    return 0;
  while (s[n])
    n++;
  return n;
}

static int vsnprintf_impl(char *dst, size_t cap, const char *fmt, va_list ap) {
  size_t out_len = 0;
  size_t i = 0;
  if (!fmt)
    return -1;
  while (fmt[i]) {
    char ch = fmt[i++];
    if (ch != '%') {
      push_byte(dst, cap, &out_len, (unsigned char)ch);
      continue;
    }
    int zero_pad = 0;
    size_t width = 0;
    for (;;) {
      char f = fmt[i];
      if (f == '0') {
        zero_pad = 1;
        i++;
        continue;
      }
      if (f == '-' || f == '+' || f == ' ' || f == '#') {
        i++;
        continue;
      }
      break;
    }
    while (fmt[i] >= '0' && fmt[i] <= '9') {
      width = width * 10 + (size_t)(fmt[i] - '0');
      i++;
    }
    if (fmt[i] == '.') {
      i++;
      while (fmt[i] >= '0' && fmt[i] <= '9')
        i++;
    }
    int long_mod = 0;
    for (;;) {
      char m = fmt[i];
      if (m == 'l') {
        long_mod = long_mod < 2 ? long_mod + 1 : 2;
        i++;
        continue;
      }
      if (m == 'z' || m == 't' || m == 'h' || m == 'j') {
        if (m == 'z')
          long_mod = 3;
        i++;
        continue;
      }
      break;
    }
    char spec = fmt[i];
    if (!spec)
      break;
    i++;
    if (spec == '%') {
      push_byte(dst, cap, &out_len, '%');
    } else if (spec == 'c') {
      int c = va_arg(ap, int);
      push_byte(dst, cap, &out_len, (unsigned char)(c & 0xff));
    } else if (spec == 's') {
      const char *s = va_arg(ap, const char *);
      if (!s)
        s = "(null)";
      size_t n = c_strlen(s);
      for (size_t k = 0; k < n; k++)
        push_byte(dst, cap, &out_len, (unsigned char)s[k]);
    } else if (spec == 'd' || spec == 'i') {
      int64_t v;
      if (long_mod >= 2)
        v = va_arg(ap, long long);
      else if (long_mod == 1)
        v = va_arg(ap, long);
      else
        v = va_arg(ap, int);
      push_i64(dst, cap, &out_len, v, width, zero_pad);
    } else if (spec == 'u') {
      uint64_t v;
      if (long_mod >= 2)
        v = va_arg(ap, unsigned long long);
      else if (long_mod == 1 || long_mod == 3)
        v = va_arg(ap, unsigned long);
      else
        v = va_arg(ap, unsigned);
      push_u64(dst, cap, &out_len, v, width, zero_pad, 10, 0);
    } else if (spec == 'x' || spec == 'X') {
      uint64_t v;
      if (long_mod >= 2)
        v = va_arg(ap, unsigned long long);
      else if (long_mod == 1 || long_mod == 3)
        v = va_arg(ap, unsigned long);
      else
        v = va_arg(ap, unsigned);
      push_u64(dst, cap, &out_len, v, width, zero_pad, 16, spec == 'X');
    } else if (spec == 'p') {
      void *p = va_arg(ap, void *);
      push_byte(dst, cap, &out_len, '0');
      push_byte(dst, cap, &out_len, 'x');
      push_u64(dst, cap, &out_len, (uint64_t)(size_t)p, 0, 0, 16, 0);
    } else {
      push_byte(dst, cap, &out_len, '%');
      push_byte(dst, cap, &out_len, (unsigned char)spec);
    }
  }
  if (dst && cap > 0) {
    size_t term = out_len < cap - 1 ? out_len : cap - 1;
    dst[term] = 0;
  }
  return (int)out_len;
}

int vsnprintf(char *dst, size_t cap, const char *fmt, va_list ap) {
  return vsnprintf_impl(dst, cap, fmt, ap);
}

int snprintf(char *dst, size_t cap, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  int n = vsnprintf_impl(dst, cap, fmt, ap);
  va_end(ap);
  return n;
}

int __snprintf_chk(char *dst, size_t cap, int flag, size_t slen,
                   const char *fmt, ...) {
  (void)flag;
  (void)slen;
  va_list ap;
  va_start(ap, fmt);
  int n = vsnprintf_impl(dst, cap, fmt, ap);
  va_end(ap);
  return n;
}

int __vsnprintf_chk(char *dst, size_t cap, int flag, size_t slen,
                    const char *fmt, va_list ap) {
  (void)flag;
  (void)slen;
  return vsnprintf_impl(dst, cap, fmt, ap);
}

int vfprintf(void *stream, const char *fmt, va_list ap) {
  char buf[4096];
  int n = vsnprintf_impl(buf, sizeof(buf), fmt, ap);
  if (n < 0)
    return -1;
  size_t len = (size_t)n;
  if (len >= sizeof(buf))
    len = sizeof(buf) - 1;
  int fd = fileno(stream);
  if (fd < 0)
    return -1;
  ssize_t w = write(fd, buf, len);
  if (w < 0)
    return -1;
  return (int)w;
}

int fprintf(void *stream, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  int n = vfprintf(stream, fmt, ap);
  va_end(ap);
  return n;
}

/* Apple git --version: printf("git version %s\n", git_version_string); */
int printf(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  char buf[4096];
  int n = vsnprintf_impl(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  if (n < 0)
    return -1;
  size_t len = (size_t)n;
  if (len >= sizeof(buf))
    len = sizeof(buf) - 1;
  ssize_t w = write(1, buf, len);
  if (w < 0)
    return -1;
  return (int)w;
}

int vprintf(const char *fmt, va_list ap) {
  char buf[4096];
  int n = vsnprintf_impl(buf, sizeof(buf), fmt, ap);
  if (n < 0)
    return -1;
  size_t len = (size_t)n;
  if (len >= sizeof(buf))
    len = sizeof(buf) - 1;
  ssize_t w = write(1, buf, len);
  if (w < 0)
    return -1;
  return (int)w;
}

int putchar(int c) {
  unsigned char b = (unsigned char)(c & 0xff);
  if (write(1, &b, 1) < 0)
    return -1;
  return c & 0xff;
}

void __assert_rtn(const char *func, const char *file, int line,
                  const char *expr) {
  (void)func;
  (void)file;
  (void)line;
  (void)expr;
  const char msg[] = "[kh-libsystem] __assert_rtn\n";
  (void)write(2, msg, sizeof(msg) - 1);
  /* exit via guest _exit if linked; else spin */
  extern void _exit(int) __attribute__((noreturn));
  _exit(134);
}
