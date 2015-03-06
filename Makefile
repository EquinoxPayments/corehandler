CC = arm gcc
CFLAGS += -std=c99 -D_XOPEN_SOURCE=600 -D_BSD_SOURCE -Wall -pedantic -Wno-switch # FIXME add -Wextra and fix warnings

.PHONY: all clean distclean

all: bin/corehandler

bin/corehandler: bin/ src/main.o src/proc.o src/unwind.o src/util.o src/xmalloc.o src/elf2.o
	$(CC) -o $@ src/main.o src/proc.o src/unwind.o src/util.o src/xmalloc.o src/elf2.o

bin/:
	mkdir -p $@

clean:
	rm -rf bin/ src/*.o

distclean: clean
