/* Minimal clang guest for Kakehashi bottle libSystem (_write / __exit).
 *
 * Build on macOS arm64:
 *   clang -O0 -arch arm64 -o write_exit write_exit.c
 *   codesign --remove-signature write_exit   # optional
 */
#include <unistd.h>

int main(void) {
    write(1, "hello\n", 6);
    _exit(0);
}
