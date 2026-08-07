# Multi-file G4 probe. Built by guest Apple clang under kh (or host CLT).
#
# Host-style (macOS with CLT):
#   make -C tests/clang-probe/g4-mini
#
# Under kh (Docker / UTM / Colima), prefer a **single** driver invocation so
# freestanding + clang image map only once (~6–7s for 5× `kh run` is mostly
# process start + wait4 of nested -cc1/ld):
#   make -C tests/clang-probe/g4-mini one CC="kh run clang --"
#
# Per-object make (default `all`) is fine for native, but under kh each
# `$(CC) -c` is a full translator start — use `one` for wall-time checks.
#
# Guest paths inside Docker/kh bottle:
#   make -C /Volumes/linux/src/tests/clang-probe/g4-mini \
#     one CC="kh run clang --" OUT=/Volumes/linux/out/g4-mini \
#     SYSROOT=/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk

CC       ?= clang
CFLAGS   ?= -O0 -Wall -Wextra -std=c11 -arch arm64
CPPFLAGS ?= -Iinclude
# Optional SDK root (recommended under kh when xcrun is soft).
SYSROOT  ?=
ifneq ($(SYSROOT),)
  SYSROOT_FLAGS := -isysroot $(SYSROOT)
else
  SYSROOT_FLAGS :=
endif
# Modern ld is green under freestanding (G5 + live -lto_library). Override to
# ld-classic only if debugging a classic-only path:
#   make LDFLAGS='--ld-path=…/ld-classic'
LDFLAGS  ?=
OUT      ?= build/g4-mini

SRCS := src/calc.c src/report.c src/words.c src/main.c
OBJS := $(SRCS:src/%.c=build/%.o)

.PHONY: all one clean run flto-one

# Default: separate -c + link (native-friendly; N+1 kh processes under CC=kh).
all: $(OUT)

# One clang driver invocation (best wall time under kh).
one: | build
	$(CC) $(SYSROOT_FLAGS) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $(OUT) $(SRCS)

# Same as `one` with full LTO (bitcode path; needs freestanding facet surface).
flto-one: | build
	$(CC) $(SYSROOT_FLAGS) $(CPPFLAGS) $(CFLAGS) -flto $(LDFLAGS) -o $(OUT) $(SRCS)

build:
	mkdir -p build

build/%.o: src/%.c | build
	$(CC) $(SYSROOT_FLAGS) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(OUT): $(OBJS)
	$(CC) $(SYSROOT_FLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJS)

clean:
	rm -rf build

# Product is a Darwin Mach-O: run under kh on Linux, or natively on macOS.
run: $(OUT)
	./$(OUT)
