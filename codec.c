/* codec.c - code to encode en decode data into MS
 *
 * Copyright 2022 Rik Snel <rik@snel.it>
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
#include "codec.h"
#include "utils.h"
#include "verbose.h"
#include "shashtbl.h"
#include "base.h"

static void rawhex_encode(uint8_t *out, size_t *n, lrcipher_t *l, uint16_t *scratch, size_t scratch_size, const char *in) {
	size_t no_input = 0;
	const char *cur = in;

	while (*cur) {
		if (no_input == scratch_size)
			FATAL("plaintext is too large, maximum size is %ld bytes", scratch_size>>1);

		scratch[no_input++] = wordlist_search(&wordlist_base16, cur, &cur);
	}

        if (no_input%4) FATAL("size of plaintext must be multiple of 16 bits");
        if (no_input>>1 < 16) FATAL("size of plaintext must be at least 16 bytes");

	base_decode_buffer(out, no_input>>1, &wordlist_base16.m, scratch, no_input);

	*n = no_input>>1;
}

static void rawhex_decode(char *out, size_t out_size, lrcipher_t *l,
		uint16_t *scratch, size_t scratch_size, const uint8_t *in, size_t n) {
	sbuf_t sbuf = { .buf = out, .size = out_size };

	sbufprintf_base16(&sbuf, in, n);
}

codec_t codecs_array[] = {
	{
		.elt.key = "rawhex",
		.encode = rawhex_encode,
		.decode = rawhex_decode
	}
};

size_t no_codecs = sizeof(codecs_array)/sizeof(*codecs_array);

shashtbl_t codecs;

codec_t *codec = &codecs_array[0];

void codec_init() {
	shashtbl_init_simple(&codecs, 4, 1);
	for (int i = 0; i < no_codecs; i++)
		shashtbl_add_elt(&codecs, &codecs_array[i]);
}

codec_t *codec_find(const char *key) {
	return shashtbl_search_elt_bykey(&codecs, key);
}
