#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <err.h>
#include <elf.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "util.h"

#define warn	warning
#define warnx	warning

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
	const Elf_Ehdr	 hdr;	// Pointer to ELF header.
	unsigned long	 shnum;	// Number of section headers.
};

static bool
read_elf(struct elf *elf, off_t off, void *ptr, size_t size)
{
	if (lseek(elf->fd, off, SEEK_SET) < 0)
		return false;
	if (read(elf->fd, ptr, size) != (ssize_t)size)
		return false;
	return true;
}

static bool
get_shdr_index(const struct elf *elf, Elf_Shdr *shp, unsigned long ndx)
{
	off_t		 off;
	Elf_Shdr	 sh;

	off = elf->hdr.e_shoff + elf->hdr.e_shentsize * ndx;
	if (!read_elf(elf, off, &sh, sizeof sh)) {
		warning("%s: failed to read section header %lu", elf->path, ndx);
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

static bool
get_shstrndx(const struct elf *elf, unsigned long *ndxp)
{
	Elf_Shdr	 sh;

	if (elf->hdr.e_shstrndx != SHN_XINDEX) {
		*ndxp = elf->hdr.e_shstrndx;
	} else {
		if (!get_shdr_index(elf, &sh, 0))
			return false;
		*ndxp = sh.sh_link;
	}
	return true;
}

static bool
get_shdr_name(const struct elf *elf, Elf_Shdr *shp, const char *name)
{
	unsigned long	 shstrndx;			// Index of section header string table header.
	Elf_Shdr	 shstrhdr;			// Section header of section header string table.
	size_t		 namelen = strlen(name);
	char		 buf[namelen + 1];
	unsigned long	 i;
	Elf_Shdr	 sh;
	ssize_t		 n;

	if (!get_shstrndx(elf, &shstrndx)) {
		warningx("%s: failed to get section header string table index", elf->path);
		return false;
	}

	if (!get_shdr_index(elf, &shstrhdr, shstrndx)) {
		warningx("%s: failed to read section header string table header", elf->path);
		return false;
	}

	for (i = 0; i < elf->shnum; i++) {
		if (!get_shdr_index(elf, &sh, i))
			return false;

		if (lseek(elf->fd, shstrhdr->sh_offset + sh.sh_name, SEEK_SET) < 0) {
			warning("%s: failed to seek to section header string table", elf->path);
			return false;
		}
		n = read(elf->fd, buf, sizeof(buf) - 1);
		if (n < 0) {
			warning("%s: failed to read name of section header %lu", elf->path, i);
			return false;
		}
		buf[n] = '\0';

		if (strcmp(buf, name) == 0) {
			*shp = sh;
			return true;
		}
	}
	return false;
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
	if (!read_elf(elf, 0, &elf->hdr, sizeof(elf->hdr))) {
		warning("%s: failed to read ELF header", path);
		goto error;
	}

	if (elf->hdr.e_shentsize < sizeof(Elf_Shdr)) {
		warningx("%s: invalid size of section headers", path);
		goto error;
	}

	if (elf->hdr.e_shnum > 0) {
		elf->shnum = elf->hdr.e_shnum;
	} else if (!read_elf(elf, elf->hdr.e_shoff, &sh, sizeof sh)) {
		warning("%s: failed to read first section header", path);
		goto error;
	}

	elf->shnum = sh.sh_size;

	return elf;

error:
	elf_close(elf);
	return NULL;
}


void
elf_close(const struct elf *elf)
{
	free(elf->path);
	(void)close(elf->fd);
	free(elf);
}

bool
elf_is_shared_object(const struct elf *elf)
{
	return elf->hdr.e_type == ET_DYN;
}

const char *
elf_resolve_sym(const struct elf *elf, unsigned long addr)
{
	//TODO
}

