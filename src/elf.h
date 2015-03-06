#ifndef ELF_H
#define ELF_H

#include <stdbool.h>

struct elf;

struct elf	*elf_open(const char *);
void		 elf_close(const struct elf *);
bool		 elf_is_shared_object(const struct elf *);
bool		 elf_resolve_sym(const struct elf *, unsigned long, char *, size_t);

#endif
