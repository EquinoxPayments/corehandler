#ifndef ELF_H
#define ELF_H

#include <stdbool.h>

struct ef;

struct ef	*elf_open(const char *);
void		 elf_close(const struct ef *);
bool		 elf_is_shared_object(const struct ef *);
const char	*elf_resolve_sym(const struct ef *, unsigned long);

#endif
