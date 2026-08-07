#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
int main(void) {
  int fd = open("/Volumes/linux/out/t-flto.o", 0);
  if (fd < 0) { perror("open"); return 1; }
  unsigned char buf[4096];
  ssize_t n;
  unsigned long long h = 14695981039346656037ULL; /* FNV */
  size_t total = 0;
  while ((n = read(fd, buf, sizeof buf)) > 0) {
    total += (size_t)n;
    for (ssize_t i = 0; i < n; i++) {
      h ^= buf[i];
      h *= 1099511628211ULL;
    }
  }
  printf("total=%zu fnv=%016llx\n", total, h);
  /* also print bytes around potential datalayout in bitcode - scan for Fn32 ascii if any */
  lseek(fd, 0, SEEK_SET);
  n = read(fd, buf, sizeof buf);
  for (int i = 0; i + 4 < n; i++) {
    if (buf[i]=='F' && buf[i+1]=='n' && buf[i+2]=='3' && buf[i+3]=='2') {
      printf("Fn32 at %d\n", i);
    }
  }
  close(fd);
  return 0;
}
