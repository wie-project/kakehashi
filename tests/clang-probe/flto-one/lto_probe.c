/* Minimal libLTO create_local vs create_in_codegen_context probe under kh. */
#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

typedef void *lto_module_t;
typedef void *lto_code_gen_t;
typedef lto_module_t (*create_local_fn)(const void *, size_t, const char *);
typedef lto_module_t (*create_cg_fn)(const void *, size_t, const char *,
                                     lto_code_gen_t);
typedef lto_code_gen_t (*cg_create_fn)(void);
typedef const char *(*err_fn)(void);
typedef const char *(*ver_fn)(void);
typedef void (*dispose_fn)(lto_module_t);
typedef const char *(*triple_fn)(lto_module_t);
typedef unsigned (*nsym_fn)(lto_module_t);

static void *must_dlsym(void *h, const char *n) {
  void *p = dlsym(h, n);
  if (!p)
    fprintf(stderr, "dlsym %s: %s\n", n, dlerror());
  return p;
}

int main(int argc, char **argv) {
  const char *path = argc > 1 ? argv[1] : "/Volumes/linux/out/t-flto.o";
  const char *lto_path =
      argc > 2 ? argv[2]
               : "/Library/Developer/CommandLineTools/usr/lib/libLTO.dylib";

  int fd = open(path, O_RDONLY);
  if (fd < 0) {
    perror("open bitcode");
    return 1;
  }
  struct stat st;
  if (fstat(fd, &st) != 0) {
    perror("fstat");
    return 1;
  }
  void *buf = malloc((size_t)st.st_size);
  if (!buf) {
    fprintf(stderr, "malloc fail\n");
    return 1;
  }
  if (read(fd, buf, (size_t)st.st_size) != st.st_size) {
    perror("read");
    return 1;
  }
  close(fd);

  fprintf(stderr, "bitcode path=%s size=%lld magic=%02x%02x%02x%02x\n", path,
          (long long)st.st_size, ((unsigned char *)buf)[0],
          ((unsigned char *)buf)[1], ((unsigned char *)buf)[2],
          ((unsigned char *)buf)[3]);

  void *h = dlopen(lto_path, RTLD_NOW);
  if (!h) {
    fprintf(stderr, "dlopen(%s): %s\n", lto_path, dlerror());
    return 1;
  }
  create_local_fn create_local =
      (create_local_fn)must_dlsym(h, "lto_module_create_in_local_context");
  create_cg_fn create_cg =
      (create_cg_fn)must_dlsym(h, "lto_module_create_in_codegen_context");
  cg_create_fn cg_create =
      (cg_create_fn)must_dlsym(h, "lto_codegen_create_in_local_context");
  err_fn get_err = (err_fn)must_dlsym(h, "lto_get_error_message");
  ver_fn get_ver = (ver_fn)must_dlsym(h, "lto_get_version");
  dispose_fn dispose = (dispose_fn)must_dlsym(h, "lto_module_dispose");
  triple_fn triple = (triple_fn)must_dlsym(h, "lto_module_get_target_triple");
  nsym_fn nsym = (nsym_fn)must_dlsym(h, "lto_module_get_num_symbols");
  if (!create_local || !create_cg || !cg_create || !get_err)
    return 1;

  fprintf(stderr, "libLTO ver='%s'\n", get_ver ? get_ver() : "?");

  lto_module_t m = create_local(buf, (size_t)st.st_size, path);
  if (!m) {
    fprintf(stderr, "create_local FAIL: '%s'\n", get_err());
    return 2;
  }
  fprintf(stderr, "create_local OK triple='%s' nsym=%u\n",
          triple ? triple(m) : "?", nsym ? nsym(m) : 0u);
  dispose(m);

  lto_code_gen_t cg = cg_create();
  if (!cg) {
    fprintf(stderr, "cg_create FAIL: '%s'\n", get_err());
    return 3;
  }
  fprintf(stderr, "cg_create OK\n");

  lto_module_t m2 = create_cg(buf, (size_t)st.st_size, path, cg);
  if (!m2) {
    const char *e = get_err();
    fprintf(stderr, "create_in_codegen_context FAIL: '%s' (len=%zu)\n",
            e ? e : "(null)", e ? strlen(e) : 0);
    /* dump first/last bytes of buffer for corruption check */
    unsigned char *b = (unsigned char *)buf;
    fprintf(stderr, "buf head:");
    for (int i = 0; i < 16 && i < st.st_size; i++)
      fprintf(stderr, " %02x", b[i]);
    fprintf(stderr, "\n");
    return 4;
  }
  fprintf(stderr, "create_in_codegen_context OK triple='%s' nsym=%u\n",
          triple ? triple(m2) : "?", nsym ? nsym(m2) : 0u);
  dispose(m2);
  fprintf(stderr, "ALL OK\n");
  return 0;
}
