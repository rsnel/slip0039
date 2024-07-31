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
		size_t scratch_size, const char *in, wordlist_t *w,
		const char *seed, size_t seed_len, base_scratch_t *bs) {
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
		size_t scratch_size, const char *in, wordlist_t *w,
		const char *seed, size_t seed_len, base_scratch_t *bs) {
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

#if 0
void fixnum_printf(const fixnum_t *f) {
        char c[2];
        for (int nibble = (f->no_limbs<<1) - 1; nibble >= 0; nibble--) {
                memset(c, 0, sizeof(c));
                wordlist_dereference(&wordlist_base16, c, sizeof(c), fixnum_peek(f, nibble<<2, 4));
                putchar(c[0]);
        }
}

void fixnum_show(const fixnum_t *f, const char *name) {
        printf("%s: ", name);
        fixnum_printf(f);
        printf("\n");
}

void fixnum_divisor_show(const fixnum_divisor_t *d, const char *name) {
        printf("log2=%d pure=%d ", d->p.log2, d->p.pure);
        fixnum_show(&d->max_left_shift, "mls");
}
#endif

static void diceware_encode(uint8_t *out, size_t *n,
		lrcipher_t *l, uint16_t *scratch,
		size_t scratch_size, const char *in,
		wordlist_t *w, const char *seed, size_t seed_len,
		base_scratch_t *bs) {
	uint8_t *s = (uint8_t*)scratch;
	uint16_t ret;
	size_t no_input = 0;
	int blocks;
	fixnum_t f, g, h, m;
	fixnum_divisor_t d;
        assert(scratch_size == BLOCKS<<3);

	fixnum_init_uint16(&f, out, BLOCKS<<1, 1);

	while (*in) {
		ret = fixnum_mul16(&f, &w->m);
		if (ret) FATAL("too many words specified on input, maximum is %ld (based on a compile time setting of the maximum MS size of %d bytes)", no_input, BLOCKS<<4);

		//fixnum_show(&f, "max");
		//if (no_input == 24) FATAL("input too big, max 24 words supported");

		scratch[no_input++] = wordlist_search(w, in, &in);
	}
	for (int i = 0; i < no_input; i++) {
		printf("scratch[%d]=%d\n", i, scratch[i]);
	}
	uint16_t log2 = fixnum_calc_log2(&f);
	printf("log2=%d\n", log2);
	blocks = (log2+15)/16;
	printf("bytes=%d\n", blocks*2);
	if (blocks < 8) FATAL("not enough diceware word specified on input, w eneed at least 9 words");
	fixnum_show(&f, "before");

	// check if we have room for an extra word
	fixnum_mul16(&f, &w->m);
	uint16_t log2_new = fixnum_calc_log2(&f);
	printf("log2_new=%d\n", log2_new);
	fixnum_show(&f, "after");
	printf("new_bytes=%d\n", (log2_new+15)/16*2);

	if ((log2_new+15)/16 == blocks) FATAL("there is room for 1 more extra word, please generate an extra word randomly and add it");

	*n = blocks<<1;
	fixnum_init(&f, out, *n);
	printf("%ld\n", *n);

	base_decode_fixnum(&f, &w->m, scratch, no_input, 0);

	fixnum_init(&g, s, *n);
	fixnum_init_uint16(&h, s + (BLOCKS<<1), *n, 1);
	fixnum_init_pattern(&m, s + (BLOCKS<<2), *n, PATTERN_ZERO);
	fixnum_show(&h, "start");
	printf("h.no_limbs=%ld\n", h.no_limbs);

	// recompute max
	for (int i = 0; i < no_input; i++)
		fixnum_mul16(&h, &w->m);

	fixnum_sub_uint16(&h, 1);

	// check the length of the chain
	do {
		lrcipher_execute(l, s, out, *n, 1, LRCIPHER_ENCRYPT);
		fixnum_show(&g, "iteration");
		if (!fixnum_sub_fixnum(&h, &g, 0xff)) break;
		memcpy(out, s, *n);
		fixnum_add_fixnum(&h, &f, 0xff);
		fixnum_add_uint16(&m, 1);
	} while (1);
	//printf("times=%ld\n", times);

	if (!fixnum_popcnt(&m)) return;
	printf("h.no_limbs=%ld\n", h.no_limbs);

	fixnum_add_uint16(&m, 1);
	fixnum_show(&m, "count");
	fixnum_divisor_init_from_fixnum(&d, &m, s + 3*(BLOCKS<<1), *n);
	fixnum_divisor_show(&d, "divisor");
	printf("h.no_limbs=%ld\n", h.no_limbs);

	uint16_t rest = fixnum_div(&h, &d, &bs->s, 1);
	printf("rest=%d\n", rest);

	fixnum_show(&f, "out");
	fixnum_show(&h, "quotient");

	fixnum_show(&g, "random before");
	pbkdf2(s, "select", 6, seed, seed_len, 1, *n);
	fixnum_show(&g, "random after");

	//fixnum_multiplier16_t p;
	//fixnum_multiplier16_init(&p, 101);
	//fixnum_show(&h, "quotientbeforemul");
	//fixnum_mul16(&h, &p);
	//fixnum_show(&h, "quotientmul");

	fixnum_sub_uint16(&m, 1);
	fixnum_show(&m, "max");

	fixnum_divisor_init_from_fixnum(&d, &h, s + 3*(BLOCKS<<1), *n);

	//memcpy(h.limbs, g.limbs, *n);
	//fixnum_div(&g, &d, &bs->s, 0);
	//fixnum_show(&g, "random divided");

	goto start;

	while (fixnum_sub_fixnum(&m, &g, 0xff)) {
		FATAL("this is very unlikely");
		fixnum_add_fixnum(&m, &g, 0xff);
		lrcipher_execute(l, g.limbs, h.limbs, *n, 1, LRCIPHER_ENCRYPT);
start:
		memcpy(h.limbs, g.limbs, *n);
		fixnum_div(&g, &d, &bs->s, 0);
		fixnum_show(&g, "random divided");
	}

	while (!fixnum_sub_uint16(&g, 1)) {
		lrcipher_execute(l, h.limbs, out, *n, 1, LRCIPHER_DECRYPT);
		memcpy(out, h.limbs, *n);
	}
}

static void diceware_decode(char *out, size_t out_size, lrcipher_t *l,
		uint16_t *scratch, size_t scratch_size,
		const uint8_t *in, size_t n, wordlist_t *w, base_scratch_t *bs) {
	uint8_t *s = (uint8_t*)scratch;
	assert(scratch_size<<1 >= n);
	assert(bs->s.a.no_limbs >= n);
	assert(bs->s.b.no_limbs >= n);
	assert(n >= 16 && n%2 == 0); // as defined by slip0039 and ensured somewhere else

	assert(w && !w->m.p.pure && w->m.value == 7776);
	// let's find out the length of the wordlist we can completely represent
	// temporarily limit the size of bs->s.a/b to the size of the input
	size_t restore_limbs_a = bs->s.a.no_limbs;
	size_t restore_limbs_b = bs->s.b.no_limbs;
	bs->s.a.no_limbs = n;
	fixnum_set_uint16(&bs->s.a, 1);
	fixnum_set_fixnum(&bs->s.b, &bs->s.a);

	bs->s.a.no_limbs = n;
	bs->s.b.no_limbs = n;
	int no_words = 0;
	while (!fixnum_mul16(&bs->s.a, &w->m)) {
		no_words++;
		fixnum_set_fixnum(&bs->s.b, &bs->s.a);
	}
	printf("no_words=%d\n", no_words);

	fixnum_show(&bs->s.b, "max+1");
	fixnum_sub_uint16(&bs->s.b, 1);
	fixnum_show(&bs->s.b, "max");

	fixnum_set_buffer(&bs->s.a, in, n);
	fixnum_show(&bs->s.a, "in");

	// iterate until input is not larger than target
	while (fixnum_sub_fixnum(&bs->s.b, &bs->s.a, 0xff)) {
		fixnum_add_fixnum(&bs->s.b, &bs->s.a, 0xff);
		lrcipher_execute(l, s, bs->s.a.limbs, n, 1, LRCIPHER_DECRYPT);
		memcpy(bs->s.a.limbs, s, n);
		fixnum_show(&bs->s.a, "after decrypt");
	}
	fixnum_show(&bs->s.a, "final");

	bs->s.a.no_limbs = restore_limbs_a;
	bs->s.b.no_limbs = restore_limbs_b;

	printf("no_words=%d, n=%ld\n", no_words, n);
	for (int i = 0; i < n; i++) {
		printf("in[%d] = %d\n", i, in[i]);
	}
	base_encode_buffer(scratch, no_words, &w->m, bs->s.a.limbs, n, bs, 0);

	sbuf_t sbuf = { .buf = out, .size = out_size };
	for (int i = 0; i < no_words; i++) {
		printf("scratch[%d] = %d\n", i, scratch[i]);
	}

	int k = 0;
	goto start;
	while (++k < no_words) {
		sbufprintf(&sbuf, " ");
start:
		sbufwordlist_dereference(w, &sbuf, scratch[k]);
	}
//	FATAL("not implemented");


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
		.encode = diceware_encode,
		.decode = diceware_decode,
		.default_language = "english"
	}, {
		.elt.key = "base58",
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
