#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <err.h>
#include <elf.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TARGET_BITS 64

#if TARGET_BITS == 64
typedef Elf64_Ehdr Elf_Ehdr;
typedef Elf64_Shdr Elf_Shdr;
#else
typedef Elf32_Ehdr Elf_Ehdr;
typedef Elf32_Shdr Elf_Shdr;
#endif

/*
 * An ELF file.
 */
struct ef {
	char		*path;	// Filesystem path to ELF file.
	const char	*ptr;	// Pointer to memory map of the whole file.
	size_t		 size;	// Size of memory map.
	const Elf_Ehdr	*hdr;	// Pointer to ELF header.
	unsigned long	 shnum;	// Number of section headers.
};

#if 0
// possible api
struct elf_file *ef;
ef = elf_open("/path/to/elf");
const char *elf_resolve_addr(ef, 0x123123);
addr = elf_resolve_name(ef, "ajshdasd");
addr = elf_xlate_virt_addr(ef, 0x123123, base);
elf_close(ef);
#endif

#define Y(x)	{ x, #x }
static const struct strtab {
	unsigned long	 key;
	const char	*val;
} classes[] = {
	Y(ELFCLASSNONE),
	Y(ELFCLASS32),
	Y(ELFCLASS64),
	{ 0, NULL },
}, dataencodings[] = {
	Y(ELFDATANONE),
	Y(ELFDATA2LSB),
	Y(ELFDATA2MSB),
	{ 0, NULL },
}, abis[] = {
	Y(ELFOSABI_NONE),
	Y(ELFOSABI_SYSV),
	Y(ELFOSABI_HPUX),
	Y(ELFOSABI_NETBSD),
	Y(ELFOSABI_GNU),
	Y(ELFOSABI_SOLARIS),
	Y(ELFOSABI_AIX),
	Y(ELFOSABI_IRIX),
	Y(ELFOSABI_FREEBSD),
	Y(ELFOSABI_TRU64),
	Y(ELFOSABI_MODESTO),
	Y(ELFOSABI_OPENBSD),
	Y(ELFOSABI_ARM_AEABI),
	Y(ELFOSABI_ARM),
	Y(ELFOSABI_STANDALONE),
	{ 0, NULL },
}, objtypes[] = {
	Y(ET_NONE),
	Y(ET_REL),
	Y(ET_EXEC),
	Y(ET_DYN),
	Y(ET_CORE),
	{ 0, NULL },
}, sectiontypes[] = {
	Y(SHT_NULL),
	Y(SHT_PROGBITS),
	Y(SHT_SYMTAB),
	Y(SHT_STRTAB),
	Y(SHT_RELA),
	Y(SHT_HASH),
	Y(SHT_DYNAMIC),
	Y(SHT_NOTE),
	Y(SHT_NOBITS),
	Y(SHT_REL),
	Y(SHT_SHLIB),
	Y(SHT_DYNSYM),
	Y(SHT_INIT_ARRAY),
	Y(SHT_FINI_ARRAY),
	Y(SHT_PREINIT_ARRAY),
	Y(SHT_GROUP),
	Y(SHT_SYMTAB_SHNDX),
	{ 0, NULL },
};
#undef Y

const char *
key2str(const struct strtab *tab, int key, const char *dflt)
{
	while (tab->val != NULL) {
		if (tab->key == key)
			return tab->val;
		++tab;
	}
	return dflt;
}

static void
elf_print_ehdr(const char *name, const Elf_Ehdr *h)
{
	const char	*tmp;

	printf("%s\n", name);
	printf(" ident: %3s\n", h->e_ident + 1);
	printf(" class: %s\n", key2str(classes, h->e_ident[EI_CLASS], "unknown"));
	printf(" data encoding: %s\n", key2str(dataencodings, h->e_ident[EI_DATA], "unknown"));
	printf(" os abi: %s\n", key2str(abis, h->e_ident[EI_OSABI], "unknown"));
	printf(" abi version: %d\n", h->e_ident[EI_ABIVERSION]);
	printf(" version: %d\n", h->e_ident[EI_VERSION]);
	tmp = key2str(objtypes, h->e_type, NULL);
	if (tmp == NULL) {
		if (h->e_type >= ET_LOOS && h->e_type <= ET_HIOS)
			tmp = "OS specific";
		else if (h->e_type >= ET_LOPROC && h->e_type <= ET_HIPROC)
			tmp = "Processor specific";
		else
			tmp = "unknown";
	}
	printf(" type: %s\n", tmp);
	printf(" machine: %d\n", h->e_machine);
	printf(" version: %d\n", h->e_version);
	printf(" entry: 0x%lx\n", (unsigned long)h->e_entry);
	if (h->e_phoff > 0)
		printf(" program header: 0x%lx\n", (unsigned long)h->e_phoff);
	if (h->e_shoff > 0)
		printf(" section header: 0x%lx\n", (unsigned long)h->e_shoff);
	if (h->e_shstrndx != SHN_UNDEF)
		printf(" section name table index: %d\n", (int)h->e_shstrndx);
}

static void
elf_print_shdr_raw(Elf_Shdr *h)
{
	printf("Elf_Shdr:\n");
#define P(x)	printf(" " #x ": 0x%lx\n", (unsigned long)h->x)
	P(sh_name);
	P(sh_type);
	P(sh_flags);
	P(sh_flags);
	P(sh_addr);
	P(sh_offset);
	P(sh_size);
	P(sh_link);
	P(sh_info);
	P(sh_addralign);
	P(sh_entsize);
#undef P
}

/*
 * Return header of section i.
 */
static const Elf_Shdr *
elf_get_shdr(const struct ef *ef, unsigned long i)
{
	if (i >= ef->shnum) {
		warnx("attempt to access section header %lu while there are only %lu section headers", i, ef->shnum);
		return NULL;
	}

	return (Elf_Shdr *)(ef->ptr + ef->hdr->e_shoff + ef->hdr->e_shentsize * i);
}

/*
 * Return pointer to first byte of section i.
 */
static const char *
elf_get_sdata(const struct ef *ef, unsigned long i)
{
	const Elf_Shdr	*sh;

	sh = elf_get_shdr(ef, i);
	if (sh == NULL)
		return NULL;
	if (sh->sh_type == SHT_NULL || sh->sh_type == SHT_NOBITS) {
		warnx("attempt to access data of section %lu which has no data (section type is %lu)", i, (unsigned long)sh->sh_type);
		return NULL;
	}
	return ef->ptr + sh->sh_offset;
}

static void
elf_print_shdr(struct ef *ef, unsigned long ndx, const Elf_Shdr *sh)
{
	const char	*tmp;
	char		 buf[64];
	const char	*strtab;

	printf("Section header %lu:\n", ndx);

	strtab = elf_get_sdata(ef, ef->hdr->e_shstrndx);

	printf(" name: %s\n", strtab + sh->sh_name);
	if (sh->sh_type >= SHT_LOOS) {
		if (sh->sh_type <= SHT_HIOS)
			tmp = "SHT_LOOS, SHT_HIOS";
		else if (sh->sh_type <= SHT_HIPROC)
			tmp = "SHT_LOPROC, SHT_HIPROC";
		else if (sh->sh_type <= SHT_HIUSER)
			tmp = "SHT_LOUSER, SHT_HIUSER";
		(void)snprintf(buf, sizeof buf, "%lu (%s)", (unsigned long)sh->sh_type, tmp);
		tmp = buf;
	} else {
		tmp = key2str(sectiontypes, sh->sh_type, NULL);
		if (tmp == NULL) {
			(void)snprintf(buf, sizeof buf, "%lu (?)", (unsigned long)sh->sh_type);
			tmp = buf;
		}
	}
	printf(" type: %s\n", tmp);
}

static bool
elf_is_valid(const char *ptr, size_t size, const char **errstr)
{
	Elf_Ehdr	*e;
	size_t		 n;

	if (size < sizeof *e) {
		*errstr = "ELF header goes beyond end of file";
		return false;
	}

	e = (Elf_Ehdr *)ptr;

	if (e->e_shoff > 0) {
		if (e->e_shoff >= size) {
			*errstr = "first section header is beyond end of file";
			return false;
		}
		if (e->e_shentsize < sizeof(Elf_Shdr)) {
			*errstr = "size of section headers is less than expected";
			return false;
		}
		if (e->e_shnum > 0) {
			n = e->e_shnum;
		} else {
			n = ((Elf_Shdr *)(ptr + e->e_shoff))->sh_size;
		}
		if (e->e_shoff + e->e_shentsize * n > size) {
			*errstr = "section header table goes beyond end of file";
			return false;
		}
	}

	return true;
}

/*
 * Open an ELF file, perform basic sanity checks, return a pointer to filled
 * struct elf_file.
 */
struct ef *
elf_open(const char *path)
{
	struct stat	 st;
	int		 fd;
	const void	*ptr;
	const char	*errstr;
	struct ef	*ef;
	Elf_Shdr	*sh;

	if (stat(path, &st) == -1) {
		warn("%s: stat", path);
		return NULL;
	}
	fd = open(path, O_RDONLY);
	if (fd == -1) {
		warn("%s: open", path);
		return NULL;
	}
	ptr = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	(void)close(fd);
	if (ptr == MAP_FAILED) {
		warn("%s: mmap", path);
		return NULL;
	}

	if (!elf_is_valid(ptr, st.st_size, &errstr)) {
		warnx("%s: %s", path, errstr);
		munmap((void *)ptr, st.st_size);
		return NULL;
	}

	ef = malloc(sizeof *ef); // FIXME replace with xmalloc
	ef->ptr = ptr;
	ef->size = st.st_size;
	ef->hdr = ptr;
	if (ef->hdr->e_shoff > 0) {
		if (ef->hdr->e_shnum > 0) {
			ef->shnum = ef->hdr->e_shnum;
		} else {
			sh = (Elf_Shdr *)(ef->ptr + ef->hdr->e_shoff);
			ef->shnum = sh->sh_size;
		}
	}

	return ef;
}

static void
elf_print_info(const char *path)
{
	struct ef	*ef;
	unsigned long	 i;

	ef = elf_open(path);
	if (ef == NULL) {
		warnx("%s: failed to open elf file", path);
		return;
	}

	elf_print_ehdr(path, ef->hdr);

	for (i = 0; i < ef->shnum; ++i)
		elf_print_shdr(ef, i, elf_get_shdr(ef, i));
}

int
main(int argc, char **argv)
{
	while (--argc)
		elf_print_info(*++argv);
	return 0;
}

