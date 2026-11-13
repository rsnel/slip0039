/* utils.c - some utilities
 *
 * Copyright 2020 Rik Snel <rik@snel.it>
 *
 * This file is part of slip0039.
 *
 * slip0039 is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * slip0039 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with slip0039.  If not, see <https://www.gnu.org/licenses/>.
 */
#include <stdarg.h>
#include <stdlib.h>
#include <assert.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <termios.h>

#include "utils.h"
#include "fixnum.h"
#include "wordlists.h"
#include "verbose.h"
#include "cthelp.h"

displayline_t dl;

int memzero(const uint8_t *a, size_t n) {
	int or = 0;

	for (size_t i = 0; i < n; i++) or |= a[i];

	return !or;
}

int memeq(const uint8_t *a, const uint8_t *b, size_t n) {
	int xor = 0;
	for (size_t i = 0; i < n; i++) {
		xor |= a[i]^b[i];
	}

	return !xor;
}

// check if unknown string is equal to target, comparison
// time should not depend on the length of unknown,
// unknown can be terminated by SPC or by LF
int wordeq(const char *unknown, const char *target, const char **end,
		int req_terminator) {
	int eq = 0, boolean;

	do {
		eq |= (*unknown)^(*target);

		// increment pointer if current value is not SPC or NUL
		unknown += cthelp_neq(*unknown, ' ')&cthelp_neq(*unknown, '\0');
	} while (*(++target));

	boolean = cthelp_neq(eq, 0);

	if (req_terminator) {
		boolean |= cthelp_neq(*unknown, ' ')&cthelp_neq(*unknown, '\0');
		unknown += (cthelp_neq(*unknown, ' ') - 1)&1;
	}

	// set *end to point to the value after the last letter of the
	// word if there is a match (if there is a match *end should be
	// NULL, if there is no match, end is not modified
	*end = (void*)((((long int)unknown)&(boolean - 1))|(long int)*end);

	return boolean;
}

// like wordeq(), but unknown may also be a prefix of target of at least
// min characters, the end of unknown is always required to be SPC or NUL
int wordpfxeq(const char *unknown, const char *target, const char **end,
		size_t min) {
	int eq = 0, done = 0, shrt = 0, term;
	size_t i = 0;

	do {
		// unknown ends here
		term = cthelp_eq(*unknown, ' ')|cthelp_eq(*unknown, '\0');

		// it ends before min characters, while target goes on
		shrt |= term&(1 - done)&(i < min);
		done |= term;

		// compare as long as unknown has not ended
		eq |= ((*unknown)^(*target))&(done - 1);

		unknown += 1 - term;
		i++;
	} while (*(++target));

	// unknown must not be longer than target
	term = cthelp_eq(*unknown, ' ')|cthelp_eq(*unknown, '\0');

	int boolean = cthelp_neq(eq, 0)|shrt|(1 - term);

	unknown += cthelp_eq(*unknown, ' ');

	*end = (void*)((((long int)unknown)&(boolean - 1))|(long int)*end);

	return boolean;
}

// 1 if c is a space, a tab or a CR, 0 otherwise
static int is_space(char c) {
	return cthelp_eq(c, ' ')|cthelp_eq(c, '\t')|cthelp_eq(c, '\r');
}

// replace tabs and CRs by spaces, remove leading and trailing spaces,
// replace runs of spaces by a single space and, if lower is set, convert
// the ASCII letters to lower case; without branches that depend on the
// characters, the result is never longer than the input
size_t normalize_words(char *buf, int lower) {
	size_t i, j = 0;
	int prev = 1; // drop leading spaces

	for (i = 0; buf[i]; i++) {
		char c = buf[i];
		int sp = is_space(c);
		int upper = (uint8_t)(c - 'A') < 26;
		c ^= (c^' ')&(-sp);
		c |= 0x20&(-(upper&lower));
		buf[j] = c;
		j += 1 - (sp&prev);
		prev = sp;
	}

	if (j > 0 && buf[j - 1] == ' ') j--;

	memset(buf + j, 0, i - j);

	return j;
}

// escape unprintable char as \ooo so that error messages
// will never mess up the terminal
void sbuf_putchar(sbuf_t *s, char c) {
	if (isprint(c)) sbuf_printf(s, "%c", c);
	else sbuf_printf(s, "\\%o", (unsigned char)c);
}

void sbuf_wordlist_dereference(wordlist_t *w, sbuf_t *s, uint16_t idx) {
	assert(s);
	s->len += wordlist_dereference(w, s->buf + s->len,
			s->size - s->len, idx);
}

int vsnprintf_strict(char *str, size_t size, const char *format, va_list ap) {
	int ret = vsnprintf(str, size, format, ap);

	if (ret < 0) FATAL("error writing to buffer");
	else if ((size_t)ret >= size) BUG("buffer too small");

	return ret;
}

int snprintf_strict(char *str, size_t size, const char *format, ...) {
	va_list ap;
	va_start(ap, format);

	return vsnprintf_strict(str, size, format, ap);
}

int sbuf_printf(sbuf_t *s, const char *format, ...) {
	int ret;
	va_list ap;
	va_start(ap, format);

	s->len += (ret = vsnprintf_strict(s->buf + s->len,
				s->size - s->len, format, ap));

	return ret;
}

void sbuf_printf_base16(sbuf_t *s, const uint8_t *buf, size_t len) {
	fixnum_t f;
	fixnum_init(&f, (uint8_t*)buf, len);

	for (int nibble = (len<<1) - 1; nibble >= 0; nibble--)
		sbuf_wordlist_dereference(&wordlist_base16, s,
				fixnum_peek(&f, nibble<<2, 4));
}

void wipestackmemory(const size_t len) {
	// only support GCC or C99+ compiler
	uint8_t fodder[len];
	if (len > 0)
		wipememory(fodder, len);
}

// the number of the line of input that was read last
int input_line = 0;

// the standard input is a terminal, the user is prompted for the input
int interactive = 0;

// the terminal settings before echo was switched off
static struct termios saved_termios;
static volatile int echo_off = 0;

// switch the echo of the terminal back on, this is also called from
// the signal handler, so only async-signal-safe functions are used
void tty_restore(void) {
	if (echo_off) {
		tcsetattr(STDIN_FILENO, TCSAFLUSH, &saved_termios);
		echo_off = 0;
	}
}

static void tty_noecho(void) {
	struct termios t;

	if (tcgetattr(STDIN_FILENO, &saved_termios) < 0)
		FATAL_errno("reading the terminal settings");
	t = saved_termios;
	t.c_lflag &= ~ECHO;
	echo_off = 1;
	if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &t) < 0)
		FATAL_errno("switching the echo of the terminal off");
}

// show a prompt on stderr, if the user types the input
void prompt(const char *format, ...) {
	va_list ap;

	if (!interactive) return;

	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
}

// read a line from fp into buf, a CR before the LF is removed and a
// missing LF at the end of the input is accepted; returns 0 if the input
// ends before the first character and READ_EOF_OK is in flags (this is
// an error otherwise), 1 if a line was read, its length is stored in
// *len if len is not NULL; with READ_SECRET in flags, the input is not
// echoed if it is typed on a terminal
int read_string_lf(char *buf, size_t size, FILE *fp, const char *desc,
		int flags, size_t *len) {
	assert(size > 0);
	int c, ret = 1;
	size_t i = 0;

	if (interactive && (flags&READ_SECRET)) tty_noecho();

	while (1) {
		c = fgetc(fp);
		if (c == EOF) {
			if (ferror(fp)) FATAL("error %d reading %s: %s",
					errno, desc, strerror(errno));
			if (i == 0) {
				if (flags&READ_EOF_OK) ret = 0;
				else FATAL("end of input while reading %s",
						desc);
			}
			break;
		}
		if (c == '\n') break;
		if (i == size - 1) FATAL("%s on line %d is too long, at most "
				"%zu bytes are supported", desc,
				input_line + 1, size - 1);
		buf[i++] = c;
	}

	if (interactive && (flags&READ_SECRET)) {
		tty_restore();
		fputc('\n', stderr);
	}

	if (i > 0 && buf[i - 1] == '\r') i--;
	buf[i] = '\0';
	if (ret) input_line++;
	if (len) *len = i;

	return ret;
}

unsigned long int parse_number(const char *arg, const char *name,
		unsigned long int min, unsigned long int max,
		char **end, int empty) {
	unsigned long int ret = strtoul(arg, end, 0);

	if (*end == arg) FATAL("expected %s, found \"%s\" instead", name, arg);
	if (ret > max) FATAL("%s must be <= %lu", name, max);
	if (ret < min) FATAL("%s must be >= %lu", name, min);
	if (empty && **end != '\0') FATAL("junk found while parsing %s", name);

	return ret;
}
