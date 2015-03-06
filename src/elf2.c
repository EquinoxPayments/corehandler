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
#include "util.h"
#include "xmalloc.h"

#define TARGET_ELF_CLASS	32

#if TARGET_ELF_CLASS == 32
typedef Elf32_Ehdr	Elf_Ehdr;
typedef Elf32_Shdr	Elf_Shdr;
typedef Elf32_Sym	Elf_Sym;
#else
typedef Elf64_Ehdr	Elf_Ehdr;
typedef Elf64_Shdr	Elf_Shdr;
typedef Elf64_Sym	Elf_Sym;
#endif

/*
 * An ELF file.
 */
struct elf {
	char		*path;	// Filesystem path to ELF file.
	int		 fd;	// File descriptor of an open ELF file.
	Elf_Ehdr	 hdr;	// Pointer to ELF header.
	unsigned long	 shnum;	// Number of section headers.
};

static ssize_t
seek_read(int fd, off_t off, void *ptr, size_t size)
{
	ssize_t	 n;

	if (lseek(fd, off, SEEK_SET) == (off_t)-1)
		return -1;
	n = read(fd, ptr, size);
	return n;
}

static bool
read_struct(const struct elf *elf, off_t off, void *ptr, size_t size)
{
	ssize_t	 n;

	n = seek_read(elf->fd, off, ptr, size);
	return n == (ssize_t)size;
}

static bool
get_shdr_index(const struct elf *elf, Elf_Shdr *shp, unsigned long ndx)
{
	off_t		 off;
	Elf_Shdr	 sh;

	off = elf->hdr.e_shoff + elf->hdr.e_shentsize * ndx;
	if (!read_struct(elf, off, &sh, sizeof sh)) {
		warningx("%s: failed to read section header %lu, at offset %lx", elf->path, ndx, (unsigned long)off);
		return false;
	}
	*shp = sh;
	return true;
}

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

void
elf_close(struct elf *elf)
{
	free(elf->path);
	(void)close(elf->fd);
	free(elf);
}

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
	if (!read_struct(elf, 0, &elf->hdr, sizeof(elf->hdr))) {
		warningx("%s: failed to read ELF header", path);
		goto error;
	}

	if (elf->hdr.e_shentsize < sizeof(Elf_Shdr)) {
		warningx("%s: invalid size of section headers", path);
		goto error;
	}

	if (elf->hdr.e_shnum > 0) {
		elf->shnum = elf->hdr.e_shnum;
	} else if (!read_struct(elf, elf->hdr.e_shoff, &sh, sizeof sh)) {
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

bool
elf_is_shared_object(const struct elf *elf)
{
	return elf->hdr.e_type == ET_DYN;
}

bool
elf_resolve_sym(const struct elf *elf, unsigned long addr, char *buf, size_t bufsize)
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
		debug("looking at tab of type %lu\n", *type);
		if (!get_shdr_type(elf, &symtabhdr, *type++))
			continue;
		if (!get_shdr_index(elf, &strtabhdr, symtabhdr.sh_link))
			continue;
		if (symtabhdr.sh_entsize < sizeof(Elf_Sym))
			warningx("%s: symbol/dynamic table has invalid entity size", elf->path);
		for (off = symtabhdr.sh_offset;
		    off < symtabhdr.sh_offset + symtabhdr.sh_size;
		    off += symtabhdr.sh_entsize) {
			if (!read_struct(elf, off, &sym, sizeof(sym))) {
				warningx("%s: failed to read symbol at offset %lu", elf->path, (unsigned long)off);
				goto nextsymtab;
			}
			if (addr >= sym.st_value
			    && addr < sym.st_value + sym.st_size) {
				debug("%s: found matching symbol @%lx, name @%lx",
				    elf->path,
				    (unsigned long)off,
				    (unsigned long)strtabhdr.sh_offset + sym.st_value);
				n = seek_read(elf->fd,
				    strtabhdr.sh_offset + sym.st_name,
				    buf,
				    bufsize - 1);
				if (n < 0) {
					warning("%s: failed to read symbol name", elf->path);
					return false;
				}
				buf[n] = '\0';
				return true;
			}
		}
	}

	return false;
}

