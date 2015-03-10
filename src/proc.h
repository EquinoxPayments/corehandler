/*
 * Copyright (c) 2014, 2015 Equinox Payments, LLC
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

#ifndef PROC_H
#define PROC_H

#include <asm/ptrace.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include "elf_lib.h"

/* Max number of arguments to parse from /proc/<pid>/cmdline. */
#define PROC_MAX_ARGV	24

/*
 * ARM machine word.
 */
typedef uint32_t	 word_t;

/*
 * Memory map.
 */
struct map {
	LIST_ENTRY(map)	 entry;
	char		*str;	/* copy of original string from /proc/<pid>/maps */
	unsigned long	 start;	/* low address */
	unsigned long	 end;	/* high address */
	struct {		/* access permissions */
		bool	 r;	/* read */
		bool	 w;	/* write */
		bool	 x;	/* execute */
	} perm;
	struct elf	*elf;
};

/*
 * Call frame.
 */
struct frame {
	TAILQ_ENTRY(frame)	 entry;
	word_t			 pc;	/* Value of PC register. */
	word_t			 sp;	/* Address of the call frame. */
	word_t			 size;	/* In bytes. */
	word_t			 lrpos;	/* Word offset of saved LR value in the frame, counting from beginning of frame. */
	struct map		*map;	/* Memory map to which PC belongs. */
	struct {
		char		*name;	/* Name of function PC is pointing into. */
		word_t		 off;	/* Offset from beginning of function PC is pointing into. */
		word_t		 addr;	/* Value of PC translated into an "ELF address", this is what gdb will show you if you open the file and `i addr <function>`. */
	} func;
};

/*
 * Crashed process.
 */
struct proc {
	pid_t				 tid;			/* id of crashed thread */
	pid_t				 pid;			/* id of process */
	int				 sig;			/* signal which caused the dump */
	uid_t				 uid;			/* real user id of process */
	gid_t				 gid;			/* real group id of process */
	char				*exe;			/* path to executable file */
	struct map			*stack;			/* memory map which seems to be the stack of this thread */
	struct pt_regs			 regs;			/* registers at the moment of crash */
	char				*argv[PROC_MAX_ARGV];	/* argument vector of process */
	int				 nthreads;		/* number of threads in process */
	LIST_HEAD(maps, map)		 maps;			/* memory maps of process */
	TAILQ_HEAD(backtrace, frame)	 backtrace;		/* stack backtrace */
};

struct proc	*proc_attach(pid_t, pid_t, int, uid_t, gid_t);
void		 proc_detach(struct proc *);
word_t		 peek(struct proc *, word_t);

#endif
