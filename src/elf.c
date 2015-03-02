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
typedef Elf64_Sym Elf_Sym;
#else
typedef Elf32_Ehdr Elf_Ehdr;
typedef Elf32_Shdr Elf_Shdr;
typedef Elf32_Sym Elf_Sym;
#endif

/*
 * An ELF file.
 */
struct ef {
	char		*path;
	const char	*ptr;		// Pointer to memory map of the whole file.
	size_t		 size;		// Size of memory map.
	const Elf_Ehdr	*hdr;		// Pointer to ELF header.
	unsigned long	 shnum;		// Number of section headers.
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
elf_print_shdr_raw(const Elf_Shdr *h)
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

// FIXME implement checks of EVERYTHING

static const Elf_Shdr *
elf_get_shdr_type(const struct ef *ef, unsigned long type)
{
	unsigned long	 i;
	const Elf_Shdr	*sh;

	for (i = 0; i < ef->shnum; ++i) {
		sh = (const Elf_Shdr *)(ef->ptr + ef->hdr->e_shoff + ef->hdr->e_shentsize * i);
		if (sh->sh_type == type)
			return sh;
	}

	return NULL;
}

/*
 * Return header of section i.
 */
static const Elf_Shdr *
elf_get_shdr_index(const struct ef *ef, unsigned long ndx)
{
	const char	*data;

	if (ndx >= ef->shnum) {
		warnx("%s: attempt to access section header %lu while there are only %lu section headers", ef->path, ndx, ef->shnum);
		return NULL;
	}

	data = ef->ptr + ef->hdr->e_shoff + ef->hdr->e_shentsize * ndx;

	if (data >= (ef->ptr + ef->size) - sizeof(Elf_Shdr)) {
		warnx("%s: invalid offset/size for section header %lu", ef->path, ndx);
		return NULL;
	}

	return (const Elf_Shdr *)data;
}

unsigned long
min_ulong(unsigned long a, unsigned long b)
{
	if (a <= b)
		return a;
	else
		return b;
}

static const Elf_Shdr *
elf_get_shdr_name(const struct ef *ef, const char *name)
{
	unsigned long	 ndx;
	const char	*data;
	const Elf_Shdr	*sh;
	const char	*strtab;
	size_t		 strtabsize;
	size_t		 cmpsize;
	size_t		 namelen;

	if (ef->hdr->e_shstrndx == SHN_UNDEF) {
		warnx("%s: file has no section name string table", ef->path);
		return NULL;
	}

	/* Fetch index of section name string table. */

	ndx = ef->hdr->e_shstrndx;
	if (ndx == SHN_XINDEX) {
		sh = elf_get_shdr_index(ef, 0);
		if (sh == NULL)
			return NULL;
		ndx = sh->sh_link;
	}
	if (ndx >= ef->hdr->e_shnum) {
		warnx("%s: invalid index for section name string table", ef->path);
		return NULL;
	}

	/* Using the index, fetch a pointer to section name string table. */

	sh = elf_get_shdr_index(ef, ndx);
	if (sh == NULL)
		return NULL;
	strtab = ef->ptr + sh->sh_offset;
	strtabsize = sh->sh_size;
	if (strtab + strtabsize  >= ef->ptr + ef->size) {
		warnx("%s: invalid offset/size for section name string table", ef->path);
		return NULL;
	}

	/* Walk section headers, return header if it's name matches. */

	namelen = strlen(name);
	for (ndx = 0; ndx < ef->hdr->e_shnum; ++ndx) {
		sh = elf_get_shdr_index(ef, ndx);
		if (sh == NULL)
			return NULL;

		if (sh->sh_name >= strtabsize) {
			warnx("%s: invalid string table index in section header %lu", ef->path, ndx);
			return NULL;
		}

		cmpsize = min_ulong(namelen, strtabsize - sh->sh_name);
		if (strncmp(strtab[sh->sh_name], name, cmpsize) == 0)
			return sh;
	}

	return NULL;
}

static const char *
elf_get_sdata(const struct ef *ef, const Elf_Shdr *sh)
{
	const char	*data;

	if (sh == NULL)
		return NULL;

	if (sh->sh_type == SHT_NULL || sh->sh_type == SHT_NOBITS) {
		warnx("%s: attempt to access data of section which has no on-disk data (section type is %lu)", ef->path, (unsigned long)sh->sh_type);
		return NULL;
	}

	data = ef->ptr + sh->sh_offset;

	if (data >= ef->ptr + ef->size) {
		warnx("%s: invalid data offset in section header", ef->path);
		return NULL;
	}

	return data;
}

static void
elf_print_shdr(const struct ef *ef, unsigned long ndx, const Elf_Shdr *sh)
{
	const char	*tmp;
	char		 buf[64];
	const char	*strtab;

	printf("Section header %lu:\n", ndx);

	strtab = elf_get_sdata(ef, elf_get_shdr(ef, ef->hdr->e_shstrndx));

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
		warnx("%s: %s", path, errstr); // FIXME replace with debug()/warning()/fatal() ...
		munmap((void *)ptr, st.st_size);
		return NULL;
	}

	ef = malloc(sizeof *ef); // FIXME replace with xmalloc
	ef->path = strdup(path); // FIXME replace with xstrdup
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

void
elf_close(struct ef *ef)
{
	free(ef->path);
	munmap(ef->ptr, ef->size);
	free(ef);
}

bool
elf_resolve_func(const struct ef *ef, unsigned long off, const char **name, unsigned long *addr)
{
	const unsigned long	*type = (const unsigned long[]){
		SHT_SYMTAB,
		SHT_DYNSYM,
		0
	};
	Elf_Shdr		*sh;
	const char		*data;
	Elf_Sym			*sym;

	sh = elf_get_shdr_name(ef, ".text");
	if (sh == NULL)
		return false;
	*addr = sh->sh_addr + off;

	while (*type != 0) {
		sh = elf_get_shdr_type(ef, *type++);
		if (sh == NULL)
			continue;
		
		// TODO Walk sym tab
	}
}

static void
elf_print_sym_raw(const Elf_Sym *s)
{
#define Y(x)	printf("%s: 0x%lx\n", #x, (unsigned long)s->x)
	Y(st_name);
	Y(st_value);
	Y(st_size);
	Y(st_info);
	Y(st_other);
	Y(st_shndx);
#undef Y
}

static void
elf_print_symtabs(const struct ef *ef)
{
	const unsigned long	*type;
	const Elf_Shdr		*sh;
	const char		*data;
	const char		*end;
	const char		*strtab;
	const Elf_Sym		*sym;

	printf("\nSymbols:\n");

	for (type = (const unsigned long[]){ SHT_SYMTAB, SHT_DYNSYM, 0 }; *type != 0; type++) {
		sh = elf_get_shdr_type(ef, *type);
		if (sh == NULL)
			continue;
		elf_print_shdr_raw(sh);

		strtab = elf_get_sdata(ef, elf_get_shdr(ef, sh->sh_link));
		printf("strtab=%p\n", strtab);
		printf("strtab: %s\n", strtab);

		data = elf_get_sdata(ef, sh) + sh->sh_entsize;
		end = ef->ptr + sh->sh_offset + sh->sh_size;
		while (data < end) {
			sym = (const Elf_Sym *)data;
			if (sym->st_name > 0) {
				printf("[%s]\n", strtab + sym->st_name);
			}
			elf_print_sym_raw(sym);
			printf("\n");
			data += sh->sh_entsize;
		}
	}
}

static void
elf_print_info(const char *path)
{
	const struct ef	*ef;
	unsigned long	 i;

	ef = elf_open(path);
	if (ef == NULL) {
		warnx("%s: failed to open elf file", path);
		return;
	}

	elf_print_ehdr(path, ef->hdr);

	for (i = 0; i < ef->shnum; ++i)
		elf_print_shdr(ef, i, elf_get_shdr(ef, i));

	elf_print_symtabs(ef);
}

/*
 * Memory map.
 */
struct map {
	unsigned long	 start;
	unsigned long	 end;
	char		*path;
	struct {
		unsigned	r:1;
		unsigned	w:1;
		unsigned	x:1;
	} perm;
	struct map	*next;
};

static void
print_map(const struct map *map)
{
	printf("map: %lx-%lx %c%c%c %s\n",
	    map->start,
	    map->end,
	    map->perm.r ? 'r' : '-',
	    map->perm.w ? 'w' : '-',
	    map->perm.x ? 'x' : '-',
	    map->path);
}

struct map *
load_maps(pid_t pid)
{
	char		 path[1024];
	FILE		*fp;
	char		 line[2048];
	struct map	*map;
	struct map	*head = NULL;
	unsigned long	 start;
	unsigned long	 end;
	int		 r;
	int		 w;
	int		 x;
	char		*pathp;

	snprintf(path, sizeof path, "/proc/%d/maps", (int)pid);

	fp = fopen(path, "r");
	while (fgets(line, sizeof line, fp) != NULL) {
		line[strlen(line) - 1] = '\0';
		printf("Parsing mem map line: %s\n", line);
		pathp = strrchr(line, ' ') + 1;
		if (sscanf(line, "%lx-%lx %c%c%c", &start, &end, &r, &w, &x) == 5) {
			map = calloc(1, sizeof *map);
			map->start = start;
			map->end = end;
			map->path = strdup(pathp);
			if (r == 'r')
				map->perm.r = 1;
			if (w == 'w')
				map->perm.w = 1;
			if (x == 'x')
				map->perm.x = 1;
			map->next = head;
			head = map;

			print_map(map);
		}
	}

	return head;
}

int
main(int argc, char **argv)
{
	struct map	*maps;

	maps = load_maps(getpid());

	printf("main@%p\n", &main);

	while (--argc)
		elf_print_info(*++argv);

	return 0;
}

