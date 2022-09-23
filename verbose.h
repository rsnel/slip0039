/* verbose.h - some verbosity stuff
 *
 * Copyright (C) 2020  Rik Snel <rik@snel.it>
 *
 * This file is part of slip0039.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef SLIP0039_VERBOSE_H
#define SLIP0039_VERBOSE_H 1

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

/* these macros are for textual user readable output, the first argument
 * to each macro must be a double quoted string, so: VERBOSE(msg); is wrong
 * and VERBOSE("%s", msg); is correct (and also good practise). */
#define WHINE(a,...) fprintf(stderr, "%s:" a "\n", exec_name, ## __VA_ARGS__)
extern char *exec_name;
extern int debug;
//extern int verbose;
extern int quiet;

#define WARNING(a,...) do { if (!quiet) WHINE("warning:" a, ## __VA_ARGS__); } while (0)
#define ERROR(a,...) WHINE("error:" a, ## __VA_ARGS__)
#define DEBUG(a,...) do { \
	if (debug) WHINE("debug:" a, ## __VA_ARGS__); } while (0)
//#define VERBOSE(a,...) do { if (verbose) WHINE(a, ## __VA_ARGS__); } while (0)
#define ABORT(msg,...)	do { \
	WHINE(msg, ## __VA_ARGS__); \
	exit(EXIT_FAILURE); \
} while (0)
#define BUG(msg,...)            ABORT("fatal:BUG:" msg, ## __VA_ARGS__)
#define FATAL(msg,...)            ABORT("fatal:" msg, ## __VA_ARGS__)
#define FATAL_errno(msg,...) \
        FATAL(msg ": %s", ## __VA_ARGS__ , strerror(errno))
#define ERROR_errno(msg,...) \
        ERROR(msg ": %s", ## __VA_ARGS__ , strerror(errno))

void verbose_init(char*);

#endif /* SLIP0039_VERBOSE_H */
