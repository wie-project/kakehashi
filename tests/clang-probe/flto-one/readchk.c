#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
int main(void) {
  const char *path = "/Volumes/linux/out/t-flto.o";
  int fd = open(path, O_RDONLY);
  if (fd < 0) { perror("open"); return 1; }
  struct stat st;
  if (fstat(fd, &st) != 0) { perror("fstat"); return 2; }
  size_t n = (size_t)st.st_size;
  printf("size=%zu\n", n);
  /* read path */
  unsigned char buf[4096];
  ssize_t nr = read(fd, buf, n < sizeof(buf) ? n : sizeof(buf));
  printf("read=%zd head=", nr);
  for (int i = 0; i < 20 && i < nr; i++) printf("%02x", buf[i]);
  printf("\n");
  /* find BC magic */
  for (int i = 0; i + 4 < nr; i++) {
    if (buf[i]==0x42 && buf[i+1]==0x43 && buf[i+2]==0xc0 && buf[i+3]==0xde) {
      printf("BC at %d\n", i);
    }
  }
  /* mmap path */
  lseek(fd, 0, SEEK_SET);
  void *p = mmap(NULL, n, PROT_READ, MAP_PRIVATE, fd, 0);
  printf("mmap=%p\n", p);
  if (p && p != (void*)-1) {
    unsigned char *m = p;
    printf("mmap head=");
    for (int i = 0; i < 20; i++) printf("%02x", m[i]);
    printf("\n");
    int diff = memcmp(buf, m, nr < 100 ? nr : 100);
    printf("memcmp head100=%d\n", diff);
    munmap(p, n);
  }
  close(fd);
  return 0;
}
