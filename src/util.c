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

#include <syslog.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include <errno.h>

#include "util.h"

/*
 * Return a pointer to static buffer containing the formatted string.
 */
char *
format(const char *fmt, ...)
{
	va_list		 ap;
	static char	 buf[4096];
	int		 n;

	va_start(ap, fmt);
	n = vsnprintf(buf, sizeof buf, fmt, ap);
	va_end(ap);
	if (n < 0)
		fatal("%s: failed to format string", fmt);
	if (n > strlen(buf))
		fatal("%s: string truncated", buf);
	return buf;
}

/*
 * Remove the last '\n' character from s.
 */
char *
chop_newline(char *s)
{
	size_t	 len;

	len = strlen(s);
	if (len > 0 && s[len - 1] == '\n')
		s[len - 1] = '\0';
	return s;
}

/*
 * Return true if line starts with word.
 */
bool
starts_with(const char *line, const char *word)
{
	size_t	 len;

	len = strlen(word);
	if (!strncmp(line, word, len))
		return true;
	return false;
}

/*
 * Return pointer to first non-whitespace, non-delimiter character in s.
 */
static char *
skip_separators(const char *s)
{
	while (isspace(*s) || *s == '=' || *s == ':')
		++s;
	return (char *)s;
}

/*
 * Retrieve the value of key from the file at path, return true if successful.
 *
 * Usage examples:
 *
 * int	 i;
 * get_key_value("/path/to/file", "NUM_THREADS", INT, &i);
 *
 * char	 version[32];
 * get_key_value("/path/to/file", "Version", STR, &version, sizeof version);
 */
bool
get_key_value(const char *path, const char *key, enum types type, ...)
{
	bool	 retval = false;
	FILE	*fp;
	char	 line[1024];
	char	*valp;
	va_list	 ap;
	int	*ip;
	char	*sp;
	size_t	 size;

	fp = fopen(path, "r");
	if (fp == NULL) {
		warning("%s: failed to open", path);
		return false;
	}
	while (fgets(line, sizeof line, fp)) {
		if (!starts_with(line, key))
			continue;
		retval = true;
		chop_newline(line);
		valp = line + strlen(key);
		valp = skip_separators(valp);
		va_start(ap, type);
		switch (type) {
		case INT:
			ip = va_arg(ap, int *);
			*ip = atoi(valp);
			break;
		case STR:
			sp = va_arg(ap, char *);
			size = va_arg(ap, size_t);
			strncpy(sp, valp, size);
			sp[size - 1] = '\0';
			break;
		}
		va_end(ap);
		break;
	}
	fclose(fp);

	return retval;
}

/*
 * Output an error message to syslog and exit the program with unsuccessful
 * exit code.
 */
void
fatalx(const char *fmt, ...)
{
	va_list		 ap;

	va_start(ap, fmt);
	vsyslog(LOG_CRIT, fmt, ap);
	va_end(ap);

	exit(EXIT_FAILURE);
}

/*
 * Same as fatalx(), but appends errno and description of errno to message.
 */
void
fatal(const char *fmt, ...)
{
	va_list		 ap;
	char		 buf[4096];
	size_t		 len;
	int		 code;

	code = errno;

	va_start(ap, fmt);
	(void) vsnprintf(buf, sizeof buf, fmt, ap);
	va_end(ap);

	len = strlen(buf);
	(void) snprintf(buf + len, sizeof(buf) - len, ": %d, %s", code, strerror(code));
	
	syslog(LOG_CRIT, "%s", buf);

	exit(EXIT_FAILURE);
}

/*
 * Output a warning message to syslog.
 */
void
warningx(const char *fmt, ...)
{
	va_list	 ap;

	va_start(ap, fmt);
	vsyslog(LOG_WARNING, fmt, ap);
	va_end(ap);
}

/*
 * Same as warningx(), but appends errno and description of errno to message.
 */
void
warning(const char *fmt, ...)
{
	va_list		 ap;
	char		 buf[4096];
	size_t		 len;
	int		 code;

	code = errno;

	va_start(ap, fmt);
	(void) vsnprintf(buf, sizeof buf, fmt, ap);
	va_end(ap);

	len = strlen(buf);
	(void) snprintf(buf + len, sizeof(buf) - len, ": %d, %s", code, strerror(code));

	syslog(LOG_WARNING, "%s", buf);
}

#ifndef NDEBUG
/*
 * Output a debug message to syslog.
 */
void
debugf(const char *fmt, ...)
{
	va_list	 ap;

	va_start(ap, fmt);
	vsyslog(LOG_DEBUG, fmt, ap);
	va_end(ap);
}
#endif
