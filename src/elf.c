#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <err.h>
#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if 0
// possible api
struct elf_file {
	const char	*path;
	const void	*ptr;	// Memory map of the whole file.
	size_t		 size;	// Size of memory map.
	const Elf_Ehdr	*eh;
	size_t		 shnum;
	const Elf_Shdr	*sh;
};
struct elf_file *ef;
ef = elf_open("aksdhas");
const char *elf_resolve_addr(ef, 0x123123);
addr = elf_resolve_name(ef, "ajshdasd");
addr = elf_xlate_virt_addr(ef, 0x123123, base);
elf_close(ef);
#endif

#define MACHINE_BITS	64
#define CAT(x, y)	x##y
#define EVAL_CAT(x, y)	CAT(x, y)

typedef EVAL_CAT(EVAL_CAT(Elf, MACHINE_BITS), _Ehdr) Elf_Ehdr;
typedef EVAL_CAT(EVAL_CAT(Elf, MACHINE_BITS), _Shdr) Elf_Shdr;

static const struct strtab {
	unsigned long	 key;
	const char	*val;
}  classes[] = {
	{ ELFCLASSNONE, "invalid" },
	{ ELFCLASS32, "32" },
	{ ELFCLASS64, "64" },
	{ 0, NULL }
}, dataencodings[] = {
	{ ELFDATANONE, "invalid" },
	{ ELFDATA2LSB, "2's comp. little endian" },
	{ ELFDATA2MSB, "2's comp. big endian" },
	{ 0, NULL },
}, abis[] = {
	{ ELFOSABI_NONE, "none" },
	{ ELFOSABI_SYSV, "UNIX System V" },
	{ ELFOSABI_HPUX, "HP-UX" },
	{ ELFOSABI_NETBSD, "NetBSD" },
	{ ELFOSABI_GNU, "GNU" },
	{ ELFOSABI_SOLARIS, "Solaris" },
	{ ELFOSABI_AIX, "IBM AIX" },
	{ ELFOSABI_IRIX, "SGI Irix" },
	{ ELFOSABI_FREEBSD, "FreeBSD" },
	{ ELFOSABI_TRU64, "Compaq TRU64 UNIX" },
	{ ELFOSABI_MODESTO, "Novell Modesto" },
	{ ELFOSABI_OPENBSD, "OpenBSD" },
	{ ELFOSABI_ARM_AEABI, "ARM EABI" },
	{ ELFOSABI_ARM, "ARM" },
	{ ELFOSABI_STANDALONE, "Standalone (embedded) application" },
	{ 0, NULL },
}, objtypes[] = {
	{ ET_NONE, "none" },
	{ ET_REL, "relocatable file" },
	{ ET_EXEC, "executable file" },
	{ ET_DYN, "shared object file" },
	{ ET_CORE, "core file" },
	{ 0, NULL },
};

const char *
key2str(const struct strtab *tab, int key, const char *dflt)
{
	while (tab->val != NULL) {
		if (tab->key == key)
			return tab->val;
		++tab;
	}
	return NULL;
}

static void
elf_print_ehdr(const char *name, Elf_Ehdr *h)
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

static void
elf(const char *path)
{
	int		 fd;
	struct stat	 st;
	void		*ptr;
	Elf_Ehdr	*hdr;
	int		 n;

	if (stat(path, &st) == -1)
		err(EXIT_FAILURE, "%s: stat", path);

	if (st.st_size < sizeof(Elf_Ehdr))
		err(EXIT_FAILURE, "%s: file too small for an ELF file", path);

	fd = open(path, O_RDONLY);
	if (fd == -1)
		err(EXIT_FAILURE, "%s: open", path);

	ptr = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (ptr == MAP_FAILED)
		err(EXIT_FAILURE, "%s: mmap", path);
	close(fd);

	hdr = (Elf_Ehdr *)ptr;

	if (hdr->e_ehsize != sizeof(Elf_Ehdr)) {
		err(EXIT_FAILURE, "%s: ELF header size is %lu, should be %lu",
		    path,
		    (unsigned long)hdr->e_ehsize,
		    (unsigned long)sizeof(Elf_Ehdr));
	}

	elf_print_ehdr(path, hdr);

	n = hdr->e_shnum;
	for (Elf_Shdr *sh = (Elf_Shdr *)(ptr + hdr->e_shoff); n > 0; --n, ++sh)
		elf_print_shdr_raw(sh);

	munmap(ptr, st.st_size);
}

int
main(int argc, char **argv)
{
	while (--argc)
		elf(*++argv);
	return 0;
}

