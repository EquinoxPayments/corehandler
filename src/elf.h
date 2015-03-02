#ifndef ELF_H
#define ELF_H

#include <stdbool.h>

struct ef;

struct ef	*elf_open(const char *);
void		 elf_close(const struct ef *);
bool		 elf_resolve_func(const struct ef *, unsigned long, const char **, unsigned long *);

#endif
