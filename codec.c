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
#include <assert.h>
#include "codec.h"
#include "utils.h"
#include "verbose.h"
#include "shashtbl.h"
#include "base.h"
#include "wordlists.h"

static void base16_encode(uint8_t *out, size_t *n,
		lrcipher_t *l, uint16_t *scratch,
		size_t scratch_size, const char *in, wordlist_t *w) {
	size_t no_input = 0;
	const char *cur = in;

	while (*cur) {
		if (no_input == scratch_size)
			FATAL("plaintext is too large, maximum size "
					"is %ld bytes", scratch_size>>1);

		scratch[no_input++] = wordlist_search(w, cur, &cur);
	}

        if (no_input%4)
		FATAL("size of plaintext must be multiple of 16 bits");
        if (no_input>>1 < 16)
		FATAL("size of plaintext must be at least 16 bytes");

	base_decode_buffer(out, no_input>>1, &w->m,
			scratch, no_input, 0);

	*n = no_input>>1;
}

static void base16_decode(char *out, size_t out_size, lrcipher_t *l,
		uint16_t *scratch, size_t scratch_size,
		const uint8_t *in, size_t n, wordlist_t *w, base_scratch_t *bs) {
	sbuf_t sbuf = { .buf = out, .size = out_size };

	sbufprintf_base16(&sbuf, in, n);
}

static void bip39_encode(uint8_t *out, size_t *n,
		lrcipher_t *l, uint16_t *scratch,
		size_t scratch_size, const char *in, wordlist_t *w) {
	size_t no_input = 0;
	uint8_t *s = (uint8_t*)scratch; // (ab)use scratch to store sha256 checksum

	assert(scratch_size >= 16); // space for sha256 hash
	assert(WORDS >= 24);

	while (*in) {
		if (no_input == 24) FATAL("input too big, max 24 words supported");

		scratch[no_input++] = wordlist_search(w, in, &in);
	}

	if (no_input < 12 || no_input > 24 || no_input%3) {
		FATAL("number of words %ld not supported, BIP39 only supports mnemonics of 12, 15, 18, 21 and 24 words", no_input);
	}

	base_decode_buffer(out, 4*no_input/3 + 1, &w->m,
			scratch, no_input, 8 - no_input/3);

	*n = 4*no_input/3;

	sha256(s, out, *n);

	uint8_t checksum = (*s)&(0xff<<(8 - no_input/3));

	if (checksum != *(out + *n)) FATAL("invalid mnemonic, checksum does not match");
}

static void bip39_decode(char *out, size_t out_size, lrcipher_t *l,
		uint16_t *scratch, size_t scratch_size,
		const uint8_t *in, size_t n, wordlist_t *w, base_scratch_t *bs) {

	if (n < 16 || n > 32 || n%4 != 0)
		FATAL("length of plaintext is not suitable for BIP39 "
				"entropy, lenght is %ld and it should "
				"be 16, 20, 24, 28, or 32 bytes", n);

	sbuf_t sbuf = { .buf = out, .size = out_size };

	assert(BLOCKS >= 32); /* this means there is space for */
			      /* the sha256 hash of the plaintext */
			      /* after the plaintext */

	// calculate the checksum
	sha256(((uint8_t*)in) + n, in, n);

	base_encode_buffer(scratch, n/4*3, &w->m, in, n + 1, bs, 8 - n/4);

	int k = 0;
	goto start;
	while (++k < n/4*3) {
		sbufprintf(&sbuf, " ");
start:
		sbufwordlist_dereference(w, &sbuf, scratch[k]);
	}
}

codec_t codecs_array[] = {
	{
		.elt.key = "base16",
		.encode = base16_encode,
		.decode = base16_decode,
		.default_language = ""

	}, {
		.elt.key = "bip39",
		.encode = bip39_encode,
		.decode = bip39_decode,
		.default_language = "english"
	}, {
		.elt.key = "slip0039",
		.encode = NULL,
		.decode = NULL,
		.default_language = ""
	}, {
		.elt.key = "diceware",
		.encode = NULL,
		.decode = NULL,
		.default_language = "english"
	}, {
		.elt.key = "base58",
		.encode = NULL,
		.decode = NULL,
		.default_language = ""
	}, {
		.elt.key = "bech32",
		.encode = NULL,
		.decode = NULL,
		.default_language = ""
	}
};

size_t no_codecs = sizeof(codecs_array)/sizeof(*codecs_array);

shashtbl_t codecs;

codec_t *codec = &codecs_array[0];

void codec_init() {
	shashtbl_init_simple(&codecs, 4, 1);
	for (int i = 0; i < no_codecs; i++) {
		shashtbl_add_elt(&codecs, &codecs_array[i]);
		shashtbl_init_simple(&codecs_array[i].wordlists, 4, 1);
	}

}

codec_t *codec_find(const char *key) {
	return shashtbl_search_elt_bykey(&codecs, key);
}
