/* Apple arm64 ABI: variadic args for curl_easy_setopt / curl_easy_getinfo
 * always live on the stack (not x2+). Git was compiled against
 *   CURLcode curl_easy_setopt(CURL *, CURLoption, ...);
 * so freestanding must match that, not a fixed 3-arg C prototype.
 *
 * Stable Rust has no c_variadic; same pattern as printf_fmt.c.
 * Impl bodies are Rust (`kh_curl_easy_*_impl`).
 */

#pragma clang diagnostic ignored "-Wbuiltin-requires-header"

typedef __builtin_va_list va_list;
#define va_start __builtin_va_start
#define va_arg __builtin_va_arg
#define va_end __builtin_va_end

typedef int CURLcode;
typedef int CURLoption;
typedef int CURLINFO;

extern CURLcode kh_curl_easy_setopt_impl(void *curl, CURLoption option,
                                         unsigned long long param);
extern CURLcode kh_curl_easy_getinfo_impl(void *curl, CURLINFO info,
                                          unsigned long long param);

CURLcode curl_easy_setopt(void *curl, CURLoption option, ...) {
  va_list ap;
  unsigned long long param;
  va_start(ap, option);
  /* Apple arm64: each variadic slot is 8 bytes (pointer or long long). */
  param = va_arg(ap, unsigned long long);
  va_end(ap);
  return kh_curl_easy_setopt_impl(curl, option, param);
}

CURLcode curl_easy_getinfo(void *curl, CURLINFO info, ...) {
  va_list ap;
  unsigned long long param;
  va_start(ap, info);
  param = va_arg(ap, unsigned long long);
  va_end(ap);
  return kh_curl_easy_getinfo_impl(curl, info, param);
}
