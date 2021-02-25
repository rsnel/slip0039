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
#include "utils.h"
#include "fixnum.h"
#include "wordlists.h"
#include "charlists.h"
#include "verbose.h"

int memeq(const uint8_t *a, const uint8_t *b, size_t n) {
	int xor = 0;
	for (int i = 0; i < n; i++) {
		xor |= a[i]^b[i];
	}

	return !xor;
}

// check if unknown string is equal to target, comparison
// time should not depend on the length of unknown,
// unknown can be terminated by space or by NUL
int streq(const char *unknown, const char *target) {
        int eq = 0;

        goto entry;

        while (*(++target)) {
                unknown += (*unknown != '\0') && (*unknown != ' ') && (*unknown != '\n');

entry:
                eq |= (*unknown)^(*target);
        }

        return eq != 0;
}

// search word in wordlist, return -1 if not found
// the time this function takes to run should not
// depend on the input
int search(const char *word, wordlist_t *w) {
        int res = -1; /* == 0xffffffff */

        for (int i = 0; i < w->no_words; i++)
                res &= i|(-(streq(word, w->words[i])));

        return res;
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

int sbufprintf_base16(sbuf_t *s, const uint8_t *buf, size_t len) {
	fixnum_t f;
	fixnum_init(&f, (uint8_t*)buf, len);
	int ret;

	for (int nibble = (len<<1) - 1; nibble >= 0; nibble--)
		ret += sbufprintf(s, "%c", charlist_dereference(&charlist_base16,
					fixnum_peek(&f, nibble<<2, 4)));

	return ret;
}
