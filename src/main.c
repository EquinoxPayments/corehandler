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

#include <sys/ptrace.h>
#include <asm/ptrace.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <linux/limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <pwd.h>
#include <grp.h>
#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <signal.h>
#include <time.h>

#include "config.h"
#include "xmalloc.h"
#include "util.h"
#include "unwind.h"
#include "version.h"

#define PASTE(x)		#x
#define STR(x)			PASTE(x)

#define PROGRAM_NAME		"corehandler"

#define TAG_SEPARATOR		"__"
#define CRASH_REPORT_PATH_FMT	CRASH_REPORT_DIR_PATH "/" CRASH_REPORT_FILENAME TAG_SEPARATOR "%s"
#define CORE_PATH_FMT		CRASH_REPORT_DIR_PATH "/" CORE_FILENAME TAG_SEPARATOR "%s"
#define CORE_PATTERN_PATH	PROC_DIR_PATH "/sys/kernel/core_pattern"
#define CORE_PIPE_LIMIT_PATH	PROC_DIR_PATH "/sys/kernel/core_pipe_limit"
#define EXE_PATH_FMT		PROC_DIR_PATH "/%d/exe"

static void		 usage(void);
static void		 install(const char *, int);
static const char	*generate_tag(pid_t);
static char		*get_tag(const char *);
static void		 generate_coredump(const char *);
static void		 generate_report(const char *, struct proc *, time_t);
static void		 open_report(const char *);
static uid_t		 to_uid(const char *);
static gid_t		 to_gid(const char *);
static void		 report_general_info(struct proc *, time_t);
static void		 report_memory_maps(struct proc *);
static void		 report_registers(struct pt_regs *);
static void		 report_stack(struct proc *);
static void		 report_backtrace(struct proc *);
static void		 report_stack_data(struct proc *);
static void		 unlink_old_reports(void);
static void		 open_std_output_streams(void);

/*
 * report_*() functions append information to the crash report.
 */
static void
report_general_info(struct proc *p, time_t t)
{
	char	 version[32] = "UNKNOWN";
	char	**argp;

	get_key_value(OS_INFO_PATH, OS_VERSION_KEY, STR, version, sizeof version);

	printf("{General Info}\n");
	printf("Date: %s", ctime(&t));
	printf("OS Release: %s\n", version);
	printf("TID: %d PID: %d, UID: %u, GID: %u\n", p->tid, p->pid, p->uid, p->gid);
	printf("Exe: %s\n", p->exe);
	printf("CmdLine:");
	for (argp = p->argv; *argp != NULL; ++argp)
		printf(" %s", *argp);
	printf("\n");
	printf("Threads: %d\n", p->nthreads);
	printf("Signal: %d\n", p->sig);
	printf("\n");
}

static void
report_memory_maps(struct proc *p)
{
	struct map	*map;

	printf("{Memory Maps}\n");
	LIST_FOREACH(map, &p->maps, entry)
		printf("%s\n", map->str);
	printf("\n");
}

static void
report_registers(struct pt_regs *r)
{
	printf("{Registers}\n");
	printf(
	    "  r0 %08x  r1 %08x\n"
	    "  r2 %08x  r3 %08x\n"
	    "  r4 %08x  r5 %08x\n"
	    "  r6 %08x  r7 %08x\n"
	    "  r8 %08x  r9 %08x\n"
	    " r10 %08x  fp %08x\n"
	    "  ip %08x  sp %08x\n"
	    "  lr %08x  pc %08x\n"
	    "cpsr %08x\n",
	    (unsigned int)r->ARM_r0,  (unsigned int)r->ARM_r1,
	    (unsigned int)r->ARM_r2,  (unsigned int)r->ARM_r3,
	    (unsigned int)r->ARM_r4,  (unsigned int)r->ARM_r5,
	    (unsigned int)r->ARM_r6,  (unsigned int)r->ARM_r7,
	    (unsigned int)r->ARM_r8,  (unsigned int)r->ARM_r9,
	    (unsigned int)r->ARM_r10, (unsigned int)r->ARM_fp,
	    (unsigned int)r->ARM_ip,  (unsigned int)r->ARM_sp,
	    (unsigned int)r->ARM_lr,  (unsigned int)r->ARM_pc,
	    (unsigned int)r->ARM_cpsr);
	printf("\n");
}

static void
report_stack_data(struct proc *p)
{
	size_t		 i;
	size_t		 n;
	word_t		 sp;
	word_t		 data;

	sp = p->regs.ARM_sp;
	if (sp < p->stack->start)
		sp = p->stack->start;

	n = (p->stack->end - sp) / sizeof(word_t);
	if (n > MAX_STACKDUMP)
		n = MAX_STACKDUMP;

	for (i = 0; i < n; ++i) {
		data = peek(p, sp);
		if (i % 2 == 0)
			printf("\n0x%08x:", sp);
		printf(" 0x%08x", data);
		sp += sizeof(word_t);
	}
	printf("\n\n");
}

static void
report_backtrace(struct proc *p)
{
	int		 count = 0;
	struct frame	*frame;
	const char	*elfpath;
	const char	*funcname;
	const char	*funcoff;

	TAILQ_FOREACH(frame, &p->backtrace, entry) {
		if ((elfpath = strrchr(frame->map->str, ' ')) != NULL)
			elfpath++;
		else
			elfpath = "??";

		if (frame->func.name != NULL) {
			funcname = frame->func.name;
			funcoff = format("+ %lu", frame->func.off);
		} else {
			funcname = "??";
			funcoff = "";
		}

		printf("#%-2d 0x%08x in %s %s () from %s\n",
		    count,
		    frame->pc,
		    funcname,
		    funcoff,
		    elfpath);

		if (frame->pc != frame->func.addr || frame->size > 0)
			printf("    ");
		if (frame->pc != frame->func.addr)
			printf("0x%08x in ELF; ", frame->func.addr);
		if (frame->size > 0) {
			printf("frame 0x%08x, size %u", frame->sp, frame->size);
			if (frame->lrpos != ~0)
				printf(", lr@%u", frame->lrpos);
		}

		putchar('\n');

		++count;
	}
}

static void
report_stack(struct proc *p)
{
	printf("{Call Stack}\n");
	report_backtrace(p);
	report_stack_data(p);
}

static uid_t
to_uid(const char *user)
{
	struct passwd	*p;

	p = getpwnam(user);
	if (p == NULL)
		fatal("%s: failed to convert to uid", user);
	return p->pw_uid;
}

static gid_t
to_gid(const char *grname)
{
	struct group	*g;

	g = getgrnam(grname);
	if (g == NULL)
		fatal("%s: failed to convert to gid", grname);
	return g->gr_gid;
}

/*
 * Redirect stdout to report file.
 */
static void
open_report(const char *tag)
{
	const char	*path;
	struct stat	 st;
	uid_t		 uid;
	gid_t		 gid;
	mode_t		 mask;

	path = format(CRASH_REPORT_PATH_FMT, tag);

	if (stat(path, &st) == 0 || errno != ENOENT)
		fatalx("%s: file already exists", path);

	mask = umask(~0200);
	if (freopen(path, "w", stdout) == NULL)
		fatal("%s: failed to redirect stdout to report file", path);
	(void)umask(mask);

	if (stat(path, &st) < 0)
		fatal("%s: failed to stat", path);
	uid = USER == NULL ? geteuid() : to_uid(USER);
	gid = GROUP == NULL ? getegid() : to_gid(GROUP);
	if (chown(path, uid, gid) < 0)
		fatal("%s: failed to change owner and group to %d:%d", path, USER, GROUP);

	if (chmod(path, CRASH_REPORT_MODE) < 0)
		fatal("%s: failed to set permissions to %o", CRASH_REPORT_MODE);
}

static void
generate_report(const char *tag, struct proc *p, time_t t)
{
	open_report(tag);
	report_general_info(p, t);
	report_registers(&p->regs);
	report_memory_maps(p);
	report_stack(p);
	fflush(stdout);
}

/*
 * Read coredump from stdin and save it to appropritate file in crash reports
 * directory.
 */
static void
generate_coredump(const char *tag)
{
	const char	*path;
	int		 fd;
	char		 buf[CORE_BUF_SIZE];
	char		 zero[sizeof buf] = { 0 };
	ssize_t		 nread;
	ssize_t		 nwrite;
	off_t		 off;
	uid_t		 uid;
	gid_t		 gid;

	path = format(CORE_PATH_FMT, tag);
	fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0);
	if (fd == -1) {
		warning("%s: cannot open coredump file", path);
		return;
	}
	uid = USER == NULL ? geteuid() : to_uid(USER);
	gid = GROUP == NULL ? getegid() : to_gid(GROUP);
	if (fchown(fd, uid, gid) == -1)
		fatal("%s: fchown %d:%d\n", path, uid, gid);
	if (fchmod(fd, CORE_MODE) == -1)
		fatal("%s: fchmod %o", CORE_MODE);
	while ((nread = read(STDIN_FILENO, buf, sizeof(buf))) > 0) {
		if (memcmp(buf, zero, nread) == 0) {
			/* Data is all zeros, put a hole to save disk space. */
			off = lseek(fd, 0, SEEK_END);
			if (off == (off_t)-1) {
				warning("%s: lseek", path);
				break;
			}
			if (ftruncate(fd, off + nread) == -1) {
				warning("%s: ftruncate", path);
				break;
			}
			off = lseek(fd, 0, SEEK_END);
			if (off == (off_t)-1) {
				warning("%s: lseek", path);
				break;
			}
			continue;
		}

		nwrite = write(fd, buf, nread);
		if (nwrite < 0) {
			warning("failed to write coredump data");
			break;
		} else if (nwrite != nread) {
			warning("failed to write coredump data: short write, %d of %d", nwrite, nread);
			break;
		}
	}
	if (nread < 0)
		warning("failed to read coredump data from pipe");
	close(fd);
}

static void
usage(void)
{
	printf(
	    "usage: corehandler <generate_coredump> <tid> <pid> <sig> <uid> <gid>\n"
	    "       corehandler --install [<generate_coredump>]\n"
	    "       corehandler --version\n"
	    "\n"
	    "  First synopsis -- is how the Linux kernel calls corehandler\n"
	    "when a process crashes. The coredump is fed to corehandler\n"
	    "via stdin.\n"
	    "	 <generate_coredump> -- \"1\" to enable generation of a coredump;\n"
	    "    <tid>               -- PID of crashed tid;\n"
	    "    <pid>               -- PID of process;\n"
	    "    <sig>               -- signal received by program;\n"
	    "    <uid>               -- UID of process;\n"
	    "    <gid>               -- GID of process;\n"
	    "\n"
	    "  Second synopsis -- hooks up corehandler into system by modifying\n"
	    "/proc/sys/kernel/{core_pattern,core_pipe_limit}. If <generate_coredump>\n"
	    "is \"1\", coredumps will be generated in addition to crash reports.\n"
	    "\n"
	    "  Third synopsis -- allows to retrive corehandler's version.\n"
	);
}

/*
 * Install corehandler into system.
 */
static void
install(const char *arg0, int enable_coredump)
{
	char	 path[PATH_MAX];
	ssize_t	 n;
	FILE	*fp;

	n = readlink(format(EXE_PATH_FMT, getpid()), path, sizeof(path) - 1);
	if (n == -1)
		fatal("failed to determine program's path");
	path[n] = '\0';

	fp = fopen(CORE_PATTERN_PATH, "w");
	if (fp == NULL)
		fatal("could not open core_pattern for installation");
	fprintf(fp, "|%s %i %%i %%p %%s %%u %%g\n", path, enable_coredump);
	fclose(fp);

	fp = fopen(CORE_PIPE_LIMIT_PATH, "w");
	if (fp == NULL)
		fatal("could not open core_pipe_limit for installation");
	fprintf(fp, "%d\n", CORE_PIPE_LIMIT);
	fclose(fp);
}

/*
 * Return the tag contained in either a crash report, or a core filename.
 */
static char *
get_tag(const char *filename)
{
	const char	*p;
	const size_t	 seplen = sizeof(TAG_SEPARATOR) - 1;

	p = filename + strlen(filename);
	while (p-- > filename) {
		if (strncmp(p, TAG_SEPARATOR, seplen) == 0)
			return (char *)p + seplen;
	}
	return NULL;
}

/*
 * Unlink a crash report and core which have tag in their filename. Return true
 * if both files were successfully unlinked.
 */
static bool
unlink_by_tag(const char *tag)
{
	const char	*path;

	if (tag == NULL)
		return false;

	path = format(CRASH_REPORT_PATH_FMT, tag);
	if (unlink(path) == -1 && errno != ENOENT) {
		warning("%s: unlink", path);
		return false;
	}

	path = format(CORE_PATH_FMT, tag);
	if (unlink(path) == -1 && errno != ENOENT) {
		warning("%s: unlink", path);
		return false;
	}

	return true;
}

/*
 * Unlink the oldest report until the number of reports is within the limit.
 */
static void
unlink_old_reports(void)
{
	DIR		*d;
	struct dirent	*e;
	struct stat	 st;
	const char	*path;
	char		 oldest[NAME_MAX + 1];
	time_t		 oldest_mtime;
	size_t		 count;

	d = opendir(CRASH_REPORT_DIR_PATH);
	if (d == NULL) {
		warning("%s: opendir", CRASH_REPORT_DIR_PATH);
		return;
	}

	for (;;) {
		count = 0;
		while ((e = readdir(d)) != NULL) {
			if (!starts_with(e->d_name, CRASH_REPORT_FILENAME))
				continue;

			path = format(CRASH_REPORT_DIR_PATH "/%s", e->d_name);
			if (stat(path, &st) == -1) {
				if (errno != ENOENT)
					warning("%s: stat", path);
				continue;
			}

			if (count++ == 0 || st.st_mtime < oldest_mtime) {
				strcpy(oldest, e->d_name);
				oldest_mtime = st.st_mtime;
			}
		}
		rewinddir(d);

		if (count > MAX_CRASH_REPORTS) {
			if (!unlink_by_tag(get_tag(oldest)))
				break; /* avoid infinite loop */
		} else
			break;
	}

	closedir(d);
}

/*
 * Return a pointer to statically allocated buffer containing a tag for use
 * in core and crash report filenames of the form "<pid>.<n>".
 *
 * <n> is just an integer to make the filename unique, e.g. when generating a
 * core/report after a reboot for a <pid> for which a core/report
 * already exists.
 */
static const char *
generate_tag(pid_t pid)
{
	static char	 tag[sizeof(STR(LONG_MAX) "." STR(INT_MAX))];
	int		 i;
	const char	*path;
	struct stat	 st;
	const char	*pathfmts[] = {
		CRASH_REPORT_PATH_FMT,
		CORE_PATH_FMT,
		NULL
	}, **fmt;

	/*
	 * To avoid a filename collision with existing core/report, start off
	 * with <pid>.<n> where <n> is zero and increment <n> until we see
	 * there are no files using such tag.
	 */
	for (i = 0; i < INT_MAX; ++i) {
		snprintf(tag, sizeof tag, "%ld.%d", (long)pid, i);
		for (fmt = pathfmts; *fmt != NULL; ++fmt) {
			path = format(*fmt, tag);
			if (stat(path, &st) == -1 && errno == ENOENT)
				continue;
			break;
		}
		if (*fmt == NULL)
			return tag;
	}
	fatalx("failed to generate a tag for pid %ld", (long)pid);
	return NULL; /* not reached */
}

/*
 * Open/redirect the stdout and stderr file descriptors to /dev/null, so that
 * the numbers of file descriptors that we open afterwards do not conflict with
 * standard I/O stream file descriptor numbers.
 */
static void
open_std_output_streams(void)
{
	const struct tab {
		int	 stdfd;
		int	 openflags;
	} *tab = (const struct tab[]){
		{ STDOUT_FILENO, O_WRONLY },
		{ STDERR_FILENO, O_RDWR },
		{ -1 }
	};
	const char	 path[] = "/dev/null";
	int		 fd;

	while (tab->stdfd != -1) {
		fd = open(path, tab->openflags);
		if (fd < 0)
			exit(EXIT_FAILURE);
		if (dup2(fd, tab->stdfd) < 0)
			exit(EXIT_FAILURE);
		if (fd != tab->stdfd)
			close(fd);
		tab++;
	}
}

int
main(int argc, char **argv)
{
	struct proc	*p;
	int		 enable_coredump = 0;
	pid_t		 tid;
	pid_t		 pid;
	int		 sig;
	int		 uid;
	int		 gid;
	const char	*tag;
	time_t		 t;

	if (argc >= 2 && !strcmp(argv[1], "--install")) {
		if (argc >= 3)
			enable_coredump = atoi(argv[2]);
		install(argv[0], enable_coredump);
		return EXIT_SUCCESS;
	} else if (argc == 2 && !strcmp(argv[1], "--version")) {
		puts(STR(MAJOR_VERSION) "." STR(MINOR_VERSION) "." STR(PATCH_VERSION));
		return EXIT_SUCCESS;
	} else if (argc != 7) {
		usage();
		return EXIT_FAILURE;
	}

	t = time(NULL);

	open_std_output_streams();

	openlog(PROGRAM_NAME, 0, LOG_DAEMON);
	(void)atexit(closelog);

	++argv;
	enable_coredump = atoi(*argv++);
	tid = atol(*argv++);
	pid = atol(*argv++);
	sig = atoi(*argv++);
	uid = atoi(*argv++);
	gid = atoi(*argv++);

	tag = generate_tag(pid);
	if (enable_coredump)
		generate_coredump(tag);
	p = proc_attach(tid, pid, sig, uid, gid);
	unwind(p);
	generate_report(tag, p, t);
	proc_detach(p);
	unlink_old_reports();

	return EXIT_SUCCESS;
}

