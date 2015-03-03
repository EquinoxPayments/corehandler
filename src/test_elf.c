#include <unistd.h>
#include <err.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
	char		 r;
	char		 w;
	char		 x;
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

const char *
fmt(const char *fmtspec, ...)
{
	static char	 buf[1024];
	va_list		 ap;

	va_start(ap, fmtspec);
	(void)snprintf(buf, sizeof buf, fmtspec, ap);
	va_end(ap);

	return buf;
}

static void
test(struct ef *ef, struct map *maps)
{
	static const void	*funcs[] = { fmt, test, load_maps, NULL };
	const void	**fp;
	struct map	*mp;
	unsigned long	 vaddr;
	unsigned long	 voff;
	unsigned long	 elfaddr;
	const char	*name;

	for (fp = funcs; *fp != NULL; fp++) {
		vaddr = (unsigned long)(*fp);
		for (mp = maps; mp != NULL; mp = mp->next) {
			if (vaddr < mp->start || vaddr >= mp->end)
				continue;
			name = elf_resolve_sym(ef, vaddr);
			if (name == NULL)
				name = "unknown";
			printf("ptr=%lx, name=%s\n", vaddr, name);
		}
	}
}

int
main(int argc, char **argv)
{
	struct ef	*ef;
	struct map	*maps;

	ef = elf_open(*argv);
	if (ef == NULL)
		errx(1, "%s: failed to open elf file", *argv);

	maps = load_maps(getpid());
	if (maps == NULL)
		errx(1, "%d: failed to load memory maps", (int)getpid());

	test(ef, maps);

	elf_close(ef);

	return 0;
}
