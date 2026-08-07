#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

typedef void *lto_module_t;
typedef void *lto_code_gen_t;
typedef void (*lto_diagnostic_handler_t)(int severity, const char *diag, void *ctxt);

extern lto_module_t lto_module_create_in_local_context(const void *, size_t, const char *);
extern lto_module_t lto_module_create_in_codegen_context(const void *, size_t, const char *, lto_code_gen_t);
extern lto_code_gen_t lto_codegen_create_in_local_context(void);
extern void lto_codegen_set_diagnostic_handler(lto_code_gen_t, lto_diagnostic_handler_t, void *);
extern bool lto_codegen_set_pic_model(lto_code_gen_t, int);
extern void lto_codegen_set_cpu(lto_code_gen_t, const char *);
extern bool lto_codegen_add_module(lto_code_gen_t, lto_module_t);
extern bool lto_codegen_optimize(lto_code_gen_t);
extern const void *lto_codegen_compile_optimized(lto_code_gen_t, size_t *len);
extern const char *lto_get_error_message(void);
extern const char *lto_get_version(void);
extern void lto_module_dispose(lto_module_t);
extern const char *lto_module_get_target_triple(lto_module_t);
extern unsigned lto_module_get_num_symbols(lto_module_t);

static void diag(int sev, const char *msg, void *ctx) {
  (void)ctx;
  fprintf(stderr, "[lto-diag sev=%d] %s\n", sev, msg ? msg : "(null)");
}

int main(int argc, char **argv) {
  const char *path = argc > 1 ? argv[1] : "/Volumes/linux/out/t-flto.o";
  int fd = open(path, O_RDONLY);
  if (fd < 0) { perror("open"); return 1; }
  struct stat st; fstat(fd, &st);
  void *buf = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  if (buf == MAP_FAILED) { perror("mmap"); return 1; }
  close(fd);
  fprintf(stderr, "mmap size=%lld ver=%s\n", (long long)st.st_size, lto_get_version());

  lto_module_t m = lto_module_create_in_local_context(buf, (size_t)st.st_size, path);
  if (!m) { fprintf(stderr, "create_local FAIL: '%s'\n", lto_get_error_message()); return 2; }
  fprintf(stderr, "create_local OK triple=%s nsym=%u\n", lto_module_get_target_triple(m), lto_module_get_num_symbols(m));
  lto_module_dispose(m);

  lto_code_gen_t cg = lto_codegen_create_in_local_context();
  if (!cg) { fprintf(stderr, "cg FAIL: '%s'\n", lto_get_error_message()); return 3; }
  lto_codegen_set_diagnostic_handler(cg, diag, NULL);
  if (lto_codegen_set_pic_model(cg, 1)) {
    fprintf(stderr, "set_pic_model FAIL: '%s'\n", lto_get_error_message());
    return 5;
  }
  fprintf(stderr, "set_pic_model OK\n");
  lto_codegen_set_cpu(cg, "apple-m1");

  lto_module_t m2 = lto_module_create_in_codegen_context(buf, (size_t)st.st_size, path, cg);
  if (!m2) {
    const char *e = lto_get_error_message();
    fprintf(stderr, "create_in_codegen FAIL: '%s' len=%zu\n", e?e:"(null)", e?strlen(e):0);
    return 4;
  }
  fprintf(stderr, "create_in_codegen OK nsym=%u\n", lto_module_get_num_symbols(m2));
  if (lto_codegen_add_module(cg, m2)) {
    fprintf(stderr, "add_module FAIL: '%s'\n", lto_get_error_message());
    return 6;
  }
  fprintf(stderr, "add_module OK\n");
  if (lto_codegen_optimize(cg)) {
    fprintf(stderr, "optimize FAIL: '%s'\n", lto_get_error_message());
    return 7;
  }
  fprintf(stderr, "optimize OK\n");
  size_t out_len = 0;
  const void *out = lto_codegen_compile_optimized(cg, &out_len);
  if (!out) {
    fprintf(stderr, "compile FAIL: '%s'\n", lto_get_error_message());
    return 8;
  }
  fprintf(stderr, "compile OK out_len=%zu\n", out_len);
  lto_module_dispose(m2);
  fprintf(stderr, "ALL OK\n");
  return 0;
}
