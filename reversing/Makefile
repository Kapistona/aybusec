# aybusec reversing lab — derleme
# Native ELF/Mach-O:   make
# Linux ELF (docker):  make elf
# Windows PE (docker): make pe

CC ?= cc
CFLAGS = -O0 -fno-stack-protector -no-pie -g

all: stage1 stage2

stage1: stage1.c
	$(CC) $(CFLAGS) -o stage1 stage1.c

stage2: stage2.c
	$(CC) $(CFLAGS) -o stage2 stage2.c

# Linux x86_64 ELF (host ne olursa olsun) — docker gerektirir
elf:
	docker run --rm -v "$(CURDIR)":/src -w /src gcc:13 \
	  sh -c 'gcc -O0 -fno-stack-protector -no-pie -g -o stage1.elf stage1.c && \
	         gcc -O0 -fno-stack-protector -no-pie -g -o stage2.elf stage2.c'

# Windows x86_64 PE — mingw docker gerektirir
pe:
	docker run --rm -v "$(CURDIR)":/src -w /src dockcross/windows-static-x64 \
	  sh -c '$$CC -O0 -o stage1.exe stage1.c && $$CC -O0 -o stage2.exe stage2.c'

clean:
	rm -f stage1 stage2 stage1.elf stage2.elf stage1.exe stage2.exe

.PHONY: all elf pe clean
