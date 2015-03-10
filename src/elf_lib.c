/*
 * Copyright (c) 2015 Equinox Payments, LLC
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "elf_lib.h"
#include "util.h"
#include "xmalloc.h"

#if TARGET_ELF_CLASS == 64
typedef Elf64_Ehdr	Elf_Ehdr;
typedef Elf64_Shdr	Elf_Shdr;
typedef Elf64_Sym	Elf_Sym;
#else
typedef Elf32_Ehdr	Elf_Ehdr;
typedef Elf32_Shdr	Elf_Shdr;
typedef Elf32_Sym	Elf_Sym;
#endif

/*
 * An ELF file.
 */
struct elf {
	char		*path;	/* Filesystem path to ELF file. */
	int		 fd;	/* File descriptor of an open ELF file. */
	Elf_Ehdr	 hdr;	/* Pointer to ELF header. */
	unsigned long	 shnum;	/* Number of section headers. */
};

/*
 * Read a block from ELF file, return true if successful.
 */
static bool
read_block(const struct elf *elf, off_t off, void *ptr, size_t size)
{
	ssize_t	 n;

	n = pread(elf->fd, ptr, size, off);
	return n == (ssize_t)size;
}

/*
 * Read the ELF section header at the given index, return true if successful.
 */
static bool
get_shdr_index(const struct elf *elf, Elf_Shdr *shp, unsigned long ndx)
{
	off_t		 off;
	Elf_Shdr	 sh;

	off = elf->hdr.e_shoff + elf->hdr.e_shentsize * ndx;
	if (!read_block(elf, off, &sh, sizeof sh)) {
		warningx("%s: failed to read section header %lu, at offset %lx", elf->path, ndx, (unsigned long)off);
		return false;
	}
	*shp = sh;
	return true;
}

/*
 * Read the first ELF section header which has the given type, return true
 * if successful.
 */
static bool
get_shdr_type(const struct elf *elf, Elf_Shdr *shp, unsigned long type)
{
	Elf_Shdr	 sh;
	unsigned long	 i;

	for (i = 0; i < elf->hdr.e_shnum; i++) {
		if (!get_shdr_index(elf, &sh, i))
			return false;
		if (sh.sh_type == type) {
			*shp = sh;
			return true;
		}
	}
	return false;
}

/*
 * Open an ELF file, return a handle if successful.
 */
struct elf *
elf_open(const char *path)
{
	struct elf	*elf;
	Elf_Shdr	 sh;

	elf = xcalloc(1, sizeof *elf);
	elf->fd = open(path, O_RDONLY);
	if (elf->fd == -1) {
		warning("%s: open", path);
		goto error;
	}
	elf->path = xstrdup(path);
	if (!read_block(elf, 0, &elf->hdr, sizeof(elf->hdr))) {
		warningx("%s: failed to read ELF header", path);
		goto error;
	}

	if (elf->hdr.e_shentsize < sizeof(Elf_Shdr)) {
		warningx("%s: invalid size of section headers", path);
		goto error;
	}

	if (elf->hdr.e_shnum > 0) {
		elf->shnum = elf->hdr.e_shnum;
	} else if (!read_block(elf, elf->hdr.e_shoff, &sh, sizeof sh)) {
		warningx("%s: failed to read first section header", path);
		goto error;
	}

	elf->shnum = sh.sh_size;

	return elf;

error:
	warningx("%s: failed to open", path);
	elf_close(elf);
	return NULL;
}

/*
 * Close an ELF file.
 */
void
elf_close(struct elf *elf)
{
	free(elf->path);
	(void)close(elf->fd);
	free(elf);
}

/*
 * Return true if the ELF file is a shared object.
 */
bool
elf_is_shared_object(const struct elf *elf)
{
	return elf->hdr.e_type == ET_DYN;
}

/*
 * Search for a symbol which matches addr, put it's name into buf and offset
 * from beginning into offp. Return true if successful.
 */
bool
elf_resolve_sym(const struct elf *elf, unsigned long addr, char *buf, size_t bufsize, unsigned long *offp)
{
	const unsigned long	*type = (const unsigned long[]){
		SHT_SYMTAB,
		SHT_DYNSYM,
		SHT_NULL
	};
	Elf_Shdr	 symtabhdr;
	Elf_Shdr	 strtabhdr;
	off_t		 off;
	Elf_Sym		 sym;
	ssize_t		 n;

nextsymtab:
	while (*type != SHT_NULL) {
		if (!get_shdr_type(elf, &symtabhdr, *type++))
			continue;
		if (!get_shdr_index(elf, &strtabhdr, symtabhdr.sh_link))
			continue;
		if (symtabhdr.sh_entsize < sizeof(Elf_Sym))
			warningx("%s: symbol/dynamic table has invalid entity size", elf->path);
		for (off = symtabhdr.sh_offset;
		    off < symtabhdr.sh_offset + symtabhdr.sh_size;
		    off += symtabhdr.sh_entsize) {
			if (!read_block(elf, off, &sym, sizeof(sym))) {
				warningx("%s: failed to read symbol at offset %lu", elf->path, (unsigned long)off);
				goto nextsymtab;
			}
			if (addr >= sym.st_value && addr < sym.st_value + sym.st_size) {
				n = pread(elf->fd, buf, bufsize - 1, strtabhdr.sh_offset + sym.st_name);
				if (n < 0) {
					warning("%s: failed to read symbol name", elf->path);
					return false;
				}
				buf[n] = '\0';
				*offp = addr - sym.st_value;
				return true;
			}
		}
	}

	return false;
}

