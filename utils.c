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
#include "wordlist.h"
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
int search(const char *word) {
        int res = -1; /* == 0xffffffff */

        for (int i = 0; i < sizeof_array(wordlist); i++)
                res &= i|(-(streq(word, wordlist[i])));

        return res;
}

void sbufprintf(sbuf_t *s, const char *format, ...) {
	int ret;
	va_list ap;
	va_start(ap, format);

	ret = vsnprintf(s->buf + s->len, s->size - s->len, format, ap);

	if (ret >= s->size - s->len) BUG("buffer too small");
	else if (ret < 0) FATAL("error writing to buffer");

	s->len += ret;
}

void snprintf_strict(char *str, size_t size, const char *format, ...) {
	int ret;
	va_list ap;
	va_start(ap, format);

	ret = vsnprintf(str, size, format, ap);

	if (ret >= size) BUG("buffer too small");
}
