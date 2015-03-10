ARM_CC ?= arm gcc
HOST_CC ?= gcc
CFLAGS += -std=c99 -D_XOPEN_SOURCE=600 -D_BSD_SOURCE -Wall -pedantic -Wno-switch

.PHONY: all clean distclean test

all: bin/corehandler

bin/corehandler: CC = $(ARM_CC)
bin/corehandler: bin/ src/main.o src/proc.o src/unwind.o src/util.o src/xmalloc.o src/elf_lib.o
	$(CC) -o $@ src/main.o src/proc.o src/unwind.o src/util.o src/xmalloc.o src/elf_lib.o

bin/:
	mkdir -p $@

test/test_elf_lib: CFLAGS+=-DTARGET_ELF_CLASS=$(shell getconf LONG_BIT)
test/test_elf_lib: CFLAGS+=-Isrc
test/test_elf_lib: test/test_elf_lib.o src/elf_lib.o src/util.o src/xmalloc.o
	$(CC) -o $@ test/test_elf_lib.o src/elf_lib.o src/util.o src/xmalloc.o

test: CC = $(HOST_CC)
test: test/test_elf_lib
	test/test_elf_lib

clean:
	rm -rf bin/ src/*.o test/*.o test/test_elf_lib

distclean: clean
