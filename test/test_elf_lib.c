/*
 * Copyright (c) 2015 Equinox Payments, LLC
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <unistd.h>
#include <err.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "xmalloc.h"
#include "elf.h"

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
	struct elf	*ef;
	struct map	*next;
};

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
	char		 r;
	char		 w;
	char		 x;
	char		*pathp;

	snprintf(path, sizeof path, "/proc/%d/maps", (int)pid);

	fp = fopen(path, "r");
	while (fgets(line, sizeof line, fp) != NULL) {
		line[strlen(line) - 1] = '\0';
		pathp = strrchr(line, ' ') + 1;
		if (sscanf(line, "%lx-%lx %c%c%c", &start, &end, &r, &w, &x) == 5) {
			map = calloc(1, sizeof *map);
			map->start = start;
			map->end = end;
			map->path = xstrdup(pathp);
			if (r == 'r')
				map->perm.r = 1;
			if (w == 'w')
				map->perm.w = 1;
			if (x == 'x') {
				map->perm.x = 1;
				map->ef = elf_open(map->path);
			}

			map->next = head;
			head = map;
		}
	}

	return head;
}

static void
test(struct map *maps)
{
	struct func {
		const void	*ptr;
		const char	*name;
		unsigned long	 off;
	} *func = (struct func[]) {
		{ test, "test", 0 },
		{ load_maps, "load_maps", 0 },
		{ NULL }
	};
	int			 i;
	struct map		*map;
	unsigned long		 vaddr;
	char			 name[64];
	unsigned long		 off;

	i = 0;
	while (func->ptr != NULL) {
		vaddr = (unsigned long)(func->ptr);
		for (map = maps; map != NULL; map = map->next) {
			if (vaddr < map->start || vaddr >= map->end || map->ef == NULL)
				continue;

			if (!elf_resolve_sym(map->ef, vaddr, name, sizeof name, &off))
				err(1, "failed to resolve function %d", i);
			if (strcmp(name, func->name) != 0)
				err(1, "failed to resolve function %d: name is \"%s\", should be \"%s\"", i, name, func->name);
			if (off != func->off)
				err(1, "failed to resolve function %d: offset is %lu, should be %lu", i, off, func->off);
		}
		func++;
		i++;
	}
}

int
main(int argc, char **argv)
{
	struct map	*maps;

	maps = load_maps(getpid());
	if (maps == NULL)
		errx(1, "%d: failed to load memory maps", (int)getpid());

	test(maps);

	return 0;
}
