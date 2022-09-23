/* utils.c - some utilties
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
#include <assert.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>

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
int wordeq(const char *unknown, const char *target, const char **end, int req_terminator) {
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
	
	// set *end to point to the value after the last letter of the word
	// if there is a match (if there is a match *end should be NULL, if there is
	// no match, end is not modified
	*end = (void*)((((long int)unknown)&(boolean - 1))|(long int)*end);

        return boolean;
}

// escape unprintable char as \ooo so that error messages
// will never mess up the terminal
void sbufputchar(sbuf_t *s, char c) {
	if (isprint(c)) sbufprintf(s, "%c", c);
	else sbufprintf(s, "\\%o", (unsigned char)c);
}

int wordlist_dereference(wordlist_t *w, char *buf, int buf_size, uint16_t idx) {
	assert(w && idx < w->m.value && buf_size > w->max_word_length);
	int ret = 0;

	for (int i = 0; i < w->max_word_length + 1; i++)
		assert(*(buf + i) == '\0');

	for (int i = 0; i < w->m.value; i++) {
		char *cur = w->words[i];
		int eq = cthelp_eq(i, idx);
		while (*cur) {
			*(buf + (cur - w->words[i])) |= *cur&(-eq);
			ret += 1&(-eq);
			cur++;
		}
	}

	return ret;
}

void sbufwordlist_dereference(wordlist_t *w, sbuf_t *s, uint16_t idx) {
	assert(s);
	s->len += wordlist_dereference(w, s->buf + s->len, s->size - s->len, idx);
}

uint16_t wordlist_search(wordlist_t *w, const char *word, const char **end) {
	int match = -1; /* 0xffffffff */
	*end = NULL;

        for (int i = 0; i < w->m.value; i++)
                match &= i|(-(wordeq(word, w->words[i], end, w->max_word_length != w->min_word_length)));
	
	if (match == -1) {
		sbuf_t sbuf = { .buf = dl, .size = sizeof(dl) };

		sbufprintf(&sbuf, "word '");

		while (*word != '\0' && *word != ' ' && *word != '\n')
			sbufputchar(&sbuf, *word++);

		sbufprintf(&sbuf, "' not found in %s wordlist", w->name);
		FATAL("%s", dl);
	}

	return match;
}

int vsnprintf_strict(char *str, size_t size, const char *format, va_list ap) {
	int ret = vsnprintf(str, size, format, ap);

	if (ret >= size) BUG("buffer too small");
	else if (ret < 0) FATAL("error writing to buffer");

	return ret;
}

int snprintf_strict(char *str, size_t size, const char *format, ...) {
	va_list ap;
	va_start(ap, format);

	return vsnprintf_strict(str, size, format, ap);
}

int sbufprintf(sbuf_t *s, const char *format, ...) {
	int ret;
	va_list ap;
	va_start(ap, format);

	s->len += (ret = vsnprintf_strict(s->buf + s->len, s->size - s->len, format, ap));

	return ret;
}

void sbufprintf_base16(sbuf_t *s, const uint8_t *buf, size_t len) {
	fixnum_t f;
	fixnum_init(&f, (uint8_t*)buf, len);

	for (int nibble = (len<<1) - 1; nibble >= 0; nibble--)
		sbufwordlist_dereference(&wordlist_base16, s, fixnum_peek(&f, nibble<<2, 4));
}

void wipestackmemory(const size_t len) {
    // only support GCC or C99+ compiler
    unsigned char fodder[len];
    if (len > 0)
		wipememory(fodder, len);
}

// read \n delimited string from FILE* and return lenght of string that was read
// without the terminating \0
// eof_acceptable means: if we encounter EOF when we try to read the first
// character of input, we don't complain and return an empty string
size_t read_stringLF(char *buf, size_t size, FILE *fp, const char *desc, int eof_acceptable) {
	assert(size > 0);
	int c;
	size_t i = 0;
	while (i < size) {
		c = fgetc(fp);
		if (c == EOF) {
			if (feof(fp)) {
				if (i == 0 && eof_acceptable) break;
				else FATAL("EOF encountered before \\n while reading %s", desc);
			}
			else FATAL("error %d reading %s: %s", errno, desc, strerror(errno));
		}
		if (c == '\n') break;
		if (i == size - 1) FATAL("buffer full before encountering \\n while reading %s", desc);
		buf[i++] = c;
	}
	buf[i] = '\0';
	return i;
}
