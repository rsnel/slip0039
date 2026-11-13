/* normalize.c - Unicode normalization of the input
 *
 * Copyright 2026 Rik Snel <rik@snel.it>
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
#include <assert.h>
#include <string.h>

#include "normalize.h"
#include "utils.h"
#include "verbose.h"
#include "utf8proc.h"

/* the code points of the decomposition, the same buffer is used for the
 * UTF-8 encoding of the result, it is cleared after use and at exit */
utf8proc_int32_t nfkd_scratch[NFKD_SCRATCH];

#define NFKD_OPTIONS (UTF8PROC_STABLE|UTF8PROC_COMPAT|UTF8PROC_DECOMPOSE)

/* convert the string in buf to Unicode normalization form NFKD in place,
 * like the wordlists of BIP39, so that, for example, an accented letter
 * that is typed as one code point matches the same letter in the
 * wordlist, where it is a letter followed by a combining accent; this is
 * not done in constant time, ASCII strings are left alone */
size_t nfkd(char *buf, size_t size, const char *desc) {
	utf8proc_ssize_t len;
	size_t i, n = strlen(buf);
	int ascii = 1;

	assert(size > n);

	for (i = 0; i < n; i++) ascii &= (uint8_t)buf[i] < 0x80;
	if (ascii) return n;

	len = utf8proc_decompose((const utf8proc_uint8_t*)buf, n,
			nfkd_scratch, NFKD_SCRATCH, NFKD_OPTIONS);
	if (len < 0) FATAL("%s is not valid UTF-8: %s", desc,
			utf8proc_errmsg(len));
	if (len > NFKD_SCRATCH) FATAL("%s is too long", desc);

	/* the UTF-8 encoding is written over the code points */
	len = utf8proc_reencode(nfkd_scratch, len, NFKD_OPTIONS);
	if (len < 0) FATAL("%s can not be normalized: %s", desc,
			utf8proc_errmsg(len));
	if ((size_t)len >= size) FATAL("%s is too long after normalization",
			desc);

	memcpy(buf, nfkd_scratch, len);
	buf[len] = '\0';
	wipememory(nfkd_scratch, sizeof(nfkd_scratch));

	return len;
}
