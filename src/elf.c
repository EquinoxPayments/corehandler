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

static void
elf_hdr_read(void *ptr, Elf32_Ehdr *hdr)
{
	unsigned char	*data = ptr;
	struct {
		void	*ptr;
		size_t	 size;
	} fields[] = {
#define Y(x)	{ &hdr->x, sizeof hdr->x }
		Y(e_ident),
		Y(e_type),
		Y(e_machine),
		Y(e_version),
		Y(e_entry),
		Y(e_phoff),
		Y(e_shoff),
		Y(e_flags),
		Y(e_ehsize),
		Y(e_phentsize),
		Y(e_phnum),
		Y(e_shentsize),
		Y(e_shnum),
		Y(e_shstrndx),
#undef Y
		{ NULL }
	}, *fld;

	for (fld = fields; fld->ptr != NULL; ++fld) {
		memcpy(fld->ptr, data, fld->size);
		data += fld->size;
	}
}

static void
elf(const char *path)
{
	int		 fd;
	struct stat	 st;
	void		*ptr;
	Elf32_Ehdr	 hdr;
	unsigned char	*ch;

	fd = open(path, O_RDONLY);
	if (fd == -1)
		err(EXIT_FAILURE, "%s: open", path);

	if (stat(path, &st) == -1)
		err(EXIT_FAILURE, "%s: stat", path);

	ptr = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (ptr == MAP_FAILED)
		err(EXIT_FAILURE, "%s: mmap", path);

	elf_hdr_read(ptr, &hdr);

	printf("%s\n", path);
	printf(" ident: ");
	for (ch = hdr.e_ident; ch < (hdr.e_ident + EI_NIDENT) && *ch != '\0'; ++ch)
		putchar(*ch);
	putchar('\n');
	printf(" type: %d\n machine: %d\n version: %d\n",
	    hdr.e_type,
	    hdr.e_machine,
	    hdr.e_version);

	munmap(ptr, st.st_size);

	close(fd);
}

int
main(int argc, char **argv)
{
	while (--argc)
		elf(*++argv);
	return 0;
}
