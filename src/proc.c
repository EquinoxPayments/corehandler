/*
 * Copyright (c) 2014 Equinox Payments, LLC
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

#include <sys/ptrace.h>
#include <asm/ptrace.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/limits.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "proc.h"
#include "xmalloc.h"
#include "util.h"
#include "config.h"

#define MAPS_PATH_FMT		PROC_DIR_PATH "/%d/maps"
#define CMDLINE_PATH_FMT	PROC_DIR_PATH "/%d/cmdline"
#define EXE_PATH_FMT		PROC_DIR_PATH "/%d/exe"
#define STATUS_PATH_FMT		PROC_DIR_PATH "/%d/status"

#define MAPS_END_OFFSET		9
#define MAPS_PERM_OFFSET	18

static char	*get_exe(pid_t);
static void	 parse_cmdline(struct proc *);
static void	 parse_maps(struct proc *);
static void	 determine_stack(struct proc *);

/*
 * Attach to a process with ptrace(2), gather and return information about it.
 */
struct proc *
proc_attach(pid_t tid, pid_t pid, int sig, uid_t uid, gid_t gid)
{
	struct proc	*p;

	p = xcalloc(1, sizeof(*p));

	LIST_INIT(&p->maps);
	TAILQ_INIT(&p->backtrace);

	p->tid = tid;
	p->pid = pid;
	p->sig = sig;
	p->uid = uid;
	p->gid = gid;
	p->exe = get_exe(pid);
	get_key_value(format(STATUS_PATH_FMT, p->pid), "Threads", INT, &p->nthreads);

	if (ptrace(PTRACE_ATTACH, p->tid, NULL, NULL) == -1)
		fatal("%d: failed to attach to pess", p->pid);
	if (ptrace(PTRACE_GETREGS, p->tid, NULL, &p->regs) == -1)
		fatal("%d: failed to retrieve process' registers", p->tid);

	parse_cmdline(p);
	parse_maps(p);
	determine_stack(p);

	return p;
}

/*
 * Return a dynamically allocated buffer wich contains the target of the
 * /proc/<pid>/exe symlink.
 */
static char *
get_exe(pid_t pid)
{
	char	 buf[PATH_MAX];
	ssize_t	 n;

	n = readlink(format(EXE_PATH_FMT, pid), buf, sizeof(buf) - 1);
	if (n == -1)
		fatal(EXE_PATH_FMT ": failed to read symlink", pid);
	buf[n] = '\0';

	return xstrdup(buf);
}

/*
 * Parse a /proc/<pid>/cmdline file, which contains the argument vector.
 * Each argument ends with a '\0'.
 */
static void
parse_cmdline(struct proc *p)
{
	char		 buf[8192];
	ssize_t		 n;
	int		 fd;
	const char	*path;
	char		**argp;
	char		*tok;

	path = format(CMDLINE_PATH_FMT, p->pid);
	fd = open(path, O_RDONLY);
	if (fd == -1)
		fatal("%s: failed to open", path);
	n = read(fd, buf, sizeof(buf) - 1);
	if (n < 0) {
		warning("%s: failed to read", path);
		close(fd);
		return;
	}
	close(fd);
	buf[n] = '\0';

	tok = buf;
	argp = p->argv;
	while (tok < buf + n && argp < p->argv + PROC_MAX_ARGV - 1) {
		*argp = xstrdup(tok);
		tok = tok + strlen(tok) + 1;
		++argp;
	}
	*argp = NULL;
}

/*
 * Parse a /proc/<pid>/maps file, which contains the virtual memory mappings
 * of the process.
 *
 * Entries in this file have the following format:
 *
 * 6f000000-6f01e000 rwxp 00000000 00:0c 16389419   /system/lib/libcomposer.so
 * l        h        p
 *
 * l: low address
 * h: high address
 * p: access permissions
 */
static void
parse_maps(struct proc *proc)
{
	const char	*path;
	FILE		*fp;
	char		 line[4096];
	char		*p;
	struct map	*map;

	path = format(MAPS_PATH_FMT, proc->pid);
	fp = fopen(path, "r");
	if (fp == NULL)
		fatal("%s: failed to open", path);

	LIST_INIT(&proc->maps);
	while (fgets(line, sizeof line, fp)) {
		chop_newline(line);
		map        = xcalloc(1, sizeof *map);
		map->str   = xstrdup(line);
		// FIXME better use sscanf?
		map->start = strtoul(line, NULL, 16);
		map->end   = strtoul(line + MAPS_END_OFFSET, NULL, 16);
		for (p = line + MAPS_PERM_OFFSET; *p != ' ' && *p != '\0'; ++p) {
			switch (*p) {
			case 'r':
				map->perm.r = true;
				break;
			case 'w':
				map->perm.w = true;
				break;
			case 'x':
				map->perm.x = true;
				break;
			}
		}
		if (map->perm.x) {
			p = strrchr(line, ' ');
			if (p != NULL)
				map->elf = elf_open(p + 1);
		}
		LIST_INSERT_HEAD(&proc->maps, map, entry);
	}

	fclose(fp);

	if (LIST_EMPTY(&proc->maps))
		fatalx("failed to retrieve process' memory maps");
}

/*
 * Determine which of process' memory maps is the stack.
 */
static void
determine_stack(struct proc *p)
{
	struct map	*map;

	LIST_FOREACH(map, &p->maps, entry) {
		if (p->regs.ARM_sp > map->start
		    && p->regs.ARM_sp <= map->end) {
			p->stack = map;
			return;
		}
	}

	/*
	 * SP doesn't point into any memory map -- this might be a stack
	 * overflow.
	 * Assume the stack to be the map to which SP is the closest to.
	 */
	unsigned long	 diff;
	unsigned long	 min_diff = ~0;

	LIST_FOREACH(map, &p->maps, entry) {
		if (p->regs.ARM_sp < map->start) {
			diff = map->start - p->regs.ARM_sp;
			if (diff < min_diff) {
				min_diff = diff;
				p->stack = map;
			}
		}
	}
}

static void
free_maps(struct maps *maps)
{
	struct map	*m, *next;

	m = LIST_FIRST(maps);
	while (m != NULL) {
		next = LIST_NEXT(m, entry);
		LIST_REMOVE(m, entry);
		free(m->str);
		if (m->elf != NULL)
			elf_close(m->elf);
		free(m);
		m = next;
	}
}

static void
free_backtrace(struct backtrace *bt)
{
	struct frame	*f, *next;

	f = TAILQ_FIRST(bt);
	while (f != NULL) {
		next = TAILQ_NEXT(f, entry);
		TAILQ_REMOVE(bt, f, entry);
		free(f);
		f = next;
	}
}

/*
 * Detach from process described by p and free the resources the data structure
 * uses.
 */
void
proc_detach(struct proc *p)
{
	char		**argp;

	(void) ptrace(PTRACE_DETACH, p->tid, NULL, NULL);

	free_maps(&p->maps);
	free_backtrace(&p->backtrace);
	for (argp = p->argv; *argp != NULL; ++argp)
		free(*argp);
	free(p->exe);
	free(p);
}

/*
 * Short-hand for ptrace(PTRACE_PEEKTEXT, ...).
 */
word_t
peek(struct proc *p, word_t addr)
{
	return ptrace(PTRACE_PEEKTEXT, p->tid, (void *)addr, NULL);
}
