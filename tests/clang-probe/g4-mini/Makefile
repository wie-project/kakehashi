# Multi-file G4 probe. Intended to be built by guest Apple clang under kh.
#
# Host-style (on macOS with CLT):
#   make -C tests/clang-probe/g4-mini
#
# Guest (paths as seen inside Docker/kh bottle):
#   make -C /Volumes/linux/src/tests/clang-probe/g4-mini \
#     CC=clang OUT=/Volumes/linux/out/g4-mini

CC      ?= clang
CFLAGS  ?= -O0 -Wall -Wextra -std=c11 -arch arm64
CPPFLAGS?= -Iinclude
# Under kh, prefer ld-classic (modern ld pulls Foundation/ObjC).
LDFLAGS ?= --ld-path=/Library/Developer/CommandLineTools/usr/bin/ld-classic
OUT     ?= build/g4-mini

SRCS := src/calc.c src/report.c src/words.c src/main.c
OBJS := $(SRCS:src/%.c=build/%.o)

.PHONY: all clean run

all: $(OUT)

build:
	mkdir -p build

build/%.o: src/%.c | build
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(OUT): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJS)

clean:
	rm -rf build

# Only useful when the product is a host-runnable binary (macOS native).
run: $(OUT)
	./$(OUT)
