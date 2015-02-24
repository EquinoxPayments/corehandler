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

typedef Elf64_Ehdr Elf_Ehdr;

static void
elf_print_hdr(const char *name, Elf_Ehdr *hdr)
{
	const unsigned char	*ch;

	printf("%s\n", name);
	printf(" ident: ");
	for (ch = hdr->e_ident; ch < (hdr->e_ident + EI_NIDENT) && *ch != '\0'; ++ch)
		putchar(*ch);
	putchar('\n');
	printf(" type: %d\n", hdr->e_type);
	printf(" machine: %d\n", hdr->e_machine);
	printf(" version: %d\n", hdr->e_version);
	printf(" entry: 0x%lx\n", (unsigned long)hdr->e_entry);
}

static void
elf(const char *path)
{
	int		 fd;
	struct stat	 st;
	void		*ptr;
	Elf_Ehdr	*hdr;

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

	elf_print_hdr(path, hdr);

	munmap(ptr, st.st_size);
}

int
main(int argc, char **argv)
{
	while (--argc)
		elf(*++argv);
	return 0;
}
