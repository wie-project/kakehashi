/* LTO probe linked against libLTO — symbols resolved at load under kh. */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Declare LTO C API */
typedef void *lto_module_t;
typedef void *lto_code_gen_t;
extern lto_module_t lto_module_create_in_local_context(const void *, size_t, const char *);
extern lto_module_t lto_module_create_in_codegen_context(const void *, size_t, const char *, lto_code_gen_t);
extern lto_code_gen_t lto_codegen_create_in_local_context(void);
extern const char *lto_get_error_message(void);
extern const char *lto_get_version(void);
extern void lto_module_dispose(lto_module_t);
extern const char *lto_module_get_target_triple(lto_module_t);
extern unsigned lto_module_get_num_symbols(lto_module_t);

int main(int argc, char **argv) {
  const char *path = argc > 1 ? argv[1] : "/Volumes/linux/out/t-flto.o";
  int fd = open(path, O_RDONLY);
  if (fd < 0) { perror("open"); return 1; }
  struct stat st; fstat(fd, &st);
  void *buf = malloc((size_t)st.st_size);
  if (!buf || read(fd, buf, (size_t)st.st_size) != st.st_size) { perror("read"); return 1; }
  close(fd);
  fprintf(stderr, "bitcode size=%lld magic=%02x%02x%02x%02x\n", (long long)st.st_size,
          ((unsigned char*)buf)[0], ((unsigned char*)buf)[1],
          ((unsigned char*)buf)[2], ((unsigned char*)buf)[3]);
  fprintf(stderr, "ver='%s'\n", lto_get_version());

  lto_module_t m = lto_module_create_in_local_context(buf, (size_t)st.st_size, path);
  if (!m) { fprintf(stderr, "create_local FAIL: '%s'\n", lto_get_error_message()); return 2; }
  fprintf(stderr, "create_local OK triple='%s' nsym=%u\n",
          lto_module_get_target_triple(m), lto_module_get_num_symbols(m));
  lto_module_dispose(m);

  lto_code_gen_t cg = lto_codegen_create_in_local_context();
  if (!cg) { fprintf(stderr, "cg_create FAIL: '%s'\n", lto_get_error_message()); return 3; }
  fprintf(stderr, "cg_create OK\n");

  lto_module_t m2 = lto_module_create_in_codegen_context(buf, (size_t)st.st_size, path, cg);
  if (!m2) {
    const char *e = lto_get_error_message();
    fprintf(stderr, "create_in_codegen_context FAIL: '%s' (len=%zu)\n", e?e:"(null)", e?strlen(e):0);
    return 4;
  }
  fprintf(stderr, "create_in_codegen_context OK triple='%s' nsym=%u\n",
          lto_module_get_target_triple(m2), lto_module_get_num_symbols(m2));
  lto_module_dispose(m2);
  fprintf(stderr, "ALL OK\n");
  return 0;
}
