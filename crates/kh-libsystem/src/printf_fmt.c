/* Minimal freestanding *printf for Darwin curl/git G1–G3 (kh-libsystem).
 * Linked into libkh_libsystem.dylib via build.rs (cc).
 * Supports %s %d %i %u %o %x %X %c %p %% , width/0-pad, and precision
 * including %.*s / %*s (git pathspec / prefix_path / tree "%o %s").
 *
 * Why C (not Rust): stable Rust has no c_variadic; curl/git import snprintf /
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
    int prec = -1; /* -1 = unspecified */
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
    if (fmt[i] == '*') {
      /* %*s / %*d — width from next int arg */
      int w = va_arg(ap, int);
      if (w < 0)
        w = 0;
      width = (size_t)w;
      i++;
    } else {
      while (fmt[i] >= '0' && fmt[i] <= '9') {
        width = width * 10 + (size_t)(fmt[i] - '0');
        i++;
      }
    }
    if (fmt[i] == '.') {
      i++;
      if (fmt[i] == '*') {
        /* %.*s — precision from next int arg (critical for git prefix_path) */
        prec = va_arg(ap, int);
        if (prec < 0)
          prec = -1;
        i++;
      } else {
        prec = 0;
        while (fmt[i] >= '0' && fmt[i] <= '9') {
          prec = prec * 10 + (fmt[i] - '0');
          i++;
        }
      }
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
      if (prec >= 0 && (size_t)prec < n)
        n = (size_t)prec;
      /* optional left-pad to width (git rarely needs it for %s) */
      if (width > n) {
        size_t pad = width - n;
        for (size_t p = 0; p < pad; p++)
          push_byte(dst, cap, &out_len, ' ');
      }
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
    } else if (spec == 'o') {
      /* Octal — git tree entries: strbuf_addf("%o %s%c", mode, path, 0) */
      uint64_t v;
      if (long_mod >= 2)
        v = va_arg(ap, unsigned long long);
      else if (long_mod == 1 || long_mod == 3)
        v = va_arg(ap, unsigned long);
      else
        v = va_arg(ap, unsigned);
      push_u64(dst, cap, &out_len, v, width, zero_pad, 8, 0);
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

/* sprintf / asprintf — ld-classic and clang diagnostics (G4). */
extern void *malloc(size_t);
extern void free(void *);

int vsprintf(char *dst, const char *fmt, va_list ap) {
  /* Unbounded write; caller must size correctly (classic sprintf contract). */
  return vsnprintf_impl(dst, (size_t)-1 / 2, fmt, ap);
}

int sprintf(char *dst, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  int n = vsprintf(dst, fmt, ap);
  va_end(ap);
  return n;
}

int vasprintf(char **ret, const char *fmt, va_list ap) {
  if (!ret)
    return -1;
  *ret = 0;
  char stack[4096];
  va_list ap2;
  va_copy(ap2, ap);
  int n = vsnprintf_impl(stack, sizeof(stack), fmt, ap2);
  va_end(ap2);
  if (n < 0)
    return -1;
  size_t need = (size_t)n + 1;
  char *p = (char *)malloc(need);
  if (!p)
    return -1;
  if ((size_t)n < sizeof(stack)) {
    size_t i;
    for (i = 0; i < need; i++)
      p[i] = stack[i];
  } else {
    int n2 = vsnprintf_impl(p, need, fmt, ap);
    if (n2 < 0) {
      free(p);
      return -1;
    }
  }
  *ret = p;
  return n;
}

int asprintf(char **ret, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  int n = vasprintf(ret, fmt, ap);
  va_end(ap);
  return n;
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

/* ── Apple `_simple_vsprintf` (modern ld mach_o::Error) ─────────────────────
 *
 * Soft handle layout (must match extra_stubs.rs):
 *   struct { char *buf; size_t cap; size_t len; }  — 3× pointer-sized words.
 *
 * `_simple_salloc` / `_simple_string` / `_simple_sfree` live in Rust; this C
 * body formats with the same `vsnprintf_impl` used by fprintf so `va_list`
 * ABI matches Apple arm64 (Error C1 passes a stack va_list into here).
 */
int _simple_vsprintf(void *h, const char *fmt, va_list ap) {
  if (!h || !fmt)
    return -1;
  char stack[4096];
  int n = vsnprintf_impl(stack, sizeof(stack), fmt, ap);
  if (n < 0)
    return -1;
  size_t add = (size_t)n;
  if (add >= sizeof(stack))
    add = sizeof(stack) - 1;

  size_t *words = (size_t *)h;
  char *buf = (char *)words[0];
  size_t cap = words[1];
  size_t len = words[2];
  size_t need = len + add + 1;
  if (need > cap) {
    size_t ncap = cap < 64 ? 64 : cap;
    while (ncap < need) {
      size_t next = ncap * 2;
      if (next < ncap) {
        ncap = need;
        break;
      }
      ncap = next;
    }
    char *nbuf = (char *)malloc(ncap);
    if (!nbuf)
      return -1;
    if (buf && len > 0) {
      size_t i;
      for (i = 0; i < len; i++)
        nbuf[i] = buf[i];
    }
    if (buf)
      free(buf);
    buf = nbuf;
    cap = ncap;
    words[0] = (size_t)buf;
    words[1] = cap;
  }
  if (!buf)
    return -1;
  {
    size_t i;
    for (i = 0; i < add; i++)
      buf[len + i] = stack[i];
  }
  len += add;
  buf[len] = 0;
  words[2] = len;
  return n;
}

/* ── sscanf / vsscanf (Apple arm64 va_list — Rust fixed-arg ABI was wrong) ──
 *
 * Observed: modern `ld` `-flto` parses platform versions via sscanf
 * ("%u.%u.%u"). The Rust soft sscanf took a0..a3 as fixed args; the C
 * caller uses true variadic ABI → wrong outs / n=0 → version string
 * '15.0.\x18\x03' / "malformed version number".
 */
static int is_space_c(unsigned char c) {
  return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v';
}

static int parse_uint(const char *s, unsigned *out, unsigned base) {
  int i = 0;
  unsigned acc = 0;
  int n = 0;
  if (!s || !out)
    return 0;
  if (s[0] == '+' || s[0] == '-')
    return 0; /* unsigned path: no sign for version fields */
  for (;;) {
    unsigned char c = (unsigned char)s[i];
    unsigned d;
    if (c >= '0' && c <= '9')
      d = (unsigned)(c - '0');
    else if (base == 16 && c >= 'a' && c <= 'f')
      d = (unsigned)(c - 'a' + 10);
    else if (base == 16 && c >= 'A' && c <= 'F')
      d = (unsigned)(c - 'A' + 10);
    else
      break;
    if (d >= base)
      break;
    acc = acc * base + d;
    i++;
    n++;
    if (n > 10)
      break;
  }
  if (n == 0)
    return 0;
  *out = acc;
  return i;
}

static int parse_int_signed(const char *s, int *out) {
  int i = 0;
  int sign = 1;
  unsigned u = 0;
  int n;
  if (!s || !out)
    return 0;
  if (s[0] == '+' || s[0] == '-') {
    if (s[0] == '-')
      sign = -1;
    i = 1;
  }
  n = parse_uint(s + i, &u, 10);
  if (n == 0)
    return 0;
  *out = sign < 0 ? -(int)u : (int)u;
  return i + n;
}

static int vsscanf_impl(const char *s, const char *fmt, va_list ap) {
  size_t si = 0;
  size_t fi = 0;
  int assigned = 0;
  if (!s || !fmt)
    return -1;
  for (;;) {
    unsigned char f = (unsigned char)fmt[fi];
    if (f == 0)
      break;
    if (f == '%') {
      unsigned char spec;
      int suppress = 0;
      fi++;
      if (fmt[fi] == '*') {
        suppress = 1;
        fi++;
      }
      /* skip width */
      while (fmt[fi] >= '0' && fmt[fi] <= '9')
        fi++;
      /* length modifiers */
      if (fmt[fi] == 'h') {
        fi++;
        if (fmt[fi] == 'h')
          fi++;
      } else if (fmt[fi] == 'l') {
        fi++;
        if (fmt[fi] == 'l')
          fi++;
      } else if (fmt[fi] == 'z' || fmt[fi] == 't' || fmt[fi] == 'j') {
        fi++;
      }
      spec = (unsigned char)fmt[fi];
      if (spec == 0)
        break;
      fi++;
      while (is_space_c((unsigned char)s[si]))
        si++;
      if (spec == '%') {
        if ((unsigned char)s[si] != '%')
          break;
        si++;
        continue;
      }
      if (spec == 'd' || spec == 'i') {
        int v = 0;
        int n = parse_int_signed(s + si, &v);
        if (n == 0)
          break;
        si += (size_t)n;
        if (!suppress) {
          int *p = va_arg(ap, int *);
          if (p)
            *p = v;
          assigned++;
        }
        continue;
      }
      if (spec == 'u' || spec == 'x' || spec == 'X' || spec == 'o') {
        unsigned base = spec == 'u' ? 10 : (spec == 'o' ? 8 : 16);
        unsigned v = 0;
        int n = parse_uint(s + si, &v, base);
        if (n == 0)
          break;
        si += (size_t)n;
        if (!suppress) {
          unsigned *p = va_arg(ap, unsigned *);
          if (p)
            *p = v;
          assigned++;
        }
        continue;
      }
      if (spec == 's') {
        char *dst = suppress ? 0 : va_arg(ap, char *);
        size_t n = 0;
        if ((unsigned char)s[si] == 0)
          break;
        while (s[si] && !is_space_c((unsigned char)s[si])) {
          if (dst && n < 255)
            dst[n] = s[si];
          n++;
          si++;
        }
        if (n == 0)
          break;
        if (dst)
          dst[n < 255 ? n : 255] = 0;
        if (!suppress)
          assigned++;
        continue;
      }
      if (spec == 'c') {
        if ((unsigned char)s[si] == 0)
          break;
        if (!suppress) {
          char *p = va_arg(ap, char *);
          if (p)
            *p = s[si];
          assigned++;
        }
        si++;
        continue;
      }
      /* unsupported conversion */
      break;
    }
    if (is_space_c(f)) {
      while (is_space_c((unsigned char)fmt[fi]))
        fi++;
      while (is_space_c((unsigned char)s[si]))
        si++;
      continue;
    }
    if ((unsigned char)s[si] != f)
      break;
    si++;
    fi++;
  }
  return assigned;
}

int vsscanf(const char *s, const char *fmt, va_list ap) {
  return vsscanf_impl(s, fmt, ap);
}

int sscanf(const char *s, const char *fmt, ...) {
  va_list ap;
  int n;
  va_start(ap, fmt);
  n = vsscanf_impl(s, fmt, ap);
  va_end(ap);
  return n;
}
