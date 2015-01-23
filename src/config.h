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

#ifndef CONFIG_H
#define CONFIG_H

/* Maximum number of crash reports, before files start getting reused. */
#define MAX_CRASH_REPORTS	10

/* Path to directory where crash reports and coredumps will be stored. */
#define CRASH_REPORT_DIR_PATH	"/var/crash_reports"

/* Path to proc-filesystem mount point. */
#define PROC_DIR_PATH		"/proc"

/* File which contains OS version. */
#define OS_INFO_PATH		"/etc/os-release"

/* The field of OS_INFO_PATH file, which contains the version of the OS. */
#define OS_VERSION_KEY		"VERSION_ID"

/* Basename of a crash report file; an underscore and an index will also be appended. */
#define CRASH_REPORT_FILENAME	"crash_report"

/* Basename of a coredump file; an underscore and an index will also be appended. */
#define CORE_FILENAME		"core"

/* Access mode for a crash report file. */
#define CRASH_REPORT_MODE	0640

/* Access mode for a coredump file. */
#define CORE_MODE		0640

/* How much of coredump data to read from stdin in one iteration. */
#define CORE_BUF_SIZE		65536

/* Change user of crash report and coredump files to this; NULL means effective user. */
#define USER			NULL

/* Change group of crash report and coredump files to this; NULL means effective group. */
#define GROUP			"gr_crash_reports"

/* Maximum amount of stack data to hexdump; in machine words. */
#define MAX_STACKDUMP		128

/* Maximum number of call frames to unwind. */
#define MAX_UNWIND		100

/* Maximum number of instructions to disassemble looking for prologue or
 * epilogue of a function before giving up.
 */
#define MAX_DISASSEMBLE		10000

/* Maximum number of crashes the system will be able to handle simultaneously.
 * The value must be greater than 1.
 */
#define CORE_PIPE_LIMIT		3

#endif
