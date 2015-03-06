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

#ifndef UTIL_H
#define UTIL_H

#include <stdbool.h>

enum types {
	INT,
	STR
};

bool	 get_key_value(const char *, const char *, enum types, ...);
bool	 starts_with(const char *, const char *);
char	*chop_newline(char *);
char	*format(const char *, ...);
void	 fatalx(const char *, ...);
void	 fatal(const char *, ...);
void	 warningx(const char *, ...);
void	 warning(const char *, ...);
#ifdef NDEBUG
#define debug(...)
#else
#define debug(...)		_debug(__VA_ARGS__, 0)
#define _debug(fmt, ...)	debugf("%s(): " fmt, __func__, __VA_ARGS__)
void	 debugf(const char *, ...);
#endif

#endif
