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
#include "honey.h"
#include "pbkdf2.h"

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
		const uint8_t *in, size_t n, wordlist_t *w,
		base_scratch_t *bs) {
	sbuf_t sbuf = { .buf = out, .size = out_size };

	sbuf_printf_base16(&sbuf, in, n);
}

static void bip39_encode(uint8_t *out, size_t *n,
		lrcipher_t *l, uint16_t *scratch,
		size_t scratch_size, const char *in, wordlist_t *w,
		const char *seed, size_t seed_len, base_scratch_t *bs) {
	size_t no_input = 0;
	// (ab)use scratch to store sha256 checksum
	uint8_t *s = (uint8_t*)scratch;

	assert(scratch_size >= 16); // space for sha256 hash
	assert(WORDS >= 24);

	while (*in) {
		if (no_input == 24)
			FATAL("input too big, max 24 words supported");

		scratch[no_input++] = wordlist_search(w, in, &in);
	}

	if (no_input < 12 || no_input > 24 || no_input%3) {
		FATAL("number of words %ld not supported, BIP39 only "
				"supports mnemonics of 12, 15, 18, 21 and 24 "
				"words", no_input);
	}

	base_decode_buffer(out, 4*no_input/3 + 1, &w->m,
			scratch, no_input, 8 - no_input/3);

	*n = 4*no_input/3;

	hash(s, sizeof(scratch), out, *n, HASH_SHA256);

	uint8_t checksum = (*s)&(0xff<<(8 - no_input/3));

	if (checksum != *(out + *n))
		FATAL("invalid mnemonic, checksum does not match");
}

static void bip39_decode(char *out, size_t out_size, lrcipher_t *l,
		uint16_t *scratch, size_t scratch_size,
		const uint8_t *in, size_t n, wordlist_t *w,
		base_scratch_t *bs) {

	if (n < 16 || n > 32 || n%4 != 0)
		FATAL("length of plaintext is not suitable for BIP39 "
				"entropy, length is %ld and it should "
				"be 16, 20, 24, 28, or 32 bytes", n);

	sbuf_t sbuf = { .buf = out, .size = out_size };

	assert(BLOCKS >= 32); /* this means there is space for */
			      /* the sha256 hash of the plaintext */
			      /* after the plaintext */

	// calculate the checksum
	hash(((uint8_t*)in) + n, n, in, n, HASH_SHA256);

	base_encode_buffer(scratch, n/4*3, &w->m, in, n + 1, bs, 8 - n/4);

	size_t k = 0;
	goto start;
	while (++k < n/4*3) {
		sbuf_printf(&sbuf, " ");
start:
		sbuf_wordlist_dereference(w, &sbuf, scratch[k]);
	}

}

#if 0
void fixnum_printf(const fixnum_t *f) {
	char c[2];
	for (int nibble = (f->no_limbs<<1) - 1; nibble >= 0; nibble--) {
		memset(c, 0, sizeof(c));
		wordlist_dereference(&wordlist_base16, c, sizeof(c),
				fixnum_peek(f, nibble<<2, 4));
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

/* the diceware codec stores the passphrase as a number k, with
 * 0 <= k < j = 7776^w (w is the number of words), honey encoded with
 * the modular DTE in a master secret of n bits, so that every master
 * secret decodes to a passphrase of w words; the number of words is
 * given with -c diceware:[WORDLIST]:NO_WORDS, when splitting it must
 * match the passphrase */

/* j = m^w in a fixnum of L limbs, returns nonzero on overflow */
static int diceware_range(fixnum_t *j, const wordlist_t *w, size_t words) {
	fixnum_set_uint16(j, 1);
	for (size_t i = 0; i < words; i++)
		if (fixnum_mul16(j, &w->m)) return 1;
	return 0;
}

static void diceware_encode(uint8_t *out, size_t *n,
		lrcipher_t *l, uint16_t *scratch,
		size_t scratch_size, const char *in,
		wordlist_t *w, const char *seed, size_t seed_len,
		base_scratch_t *bs) {
	size_t no_input = 0;
	const size_t L_max = BLOCKS<<1;
	fixnum_t k, j;

	assert(w && w->m.value == 7776);

	while (*in) {
		if (no_input == scratch_size)
			FATAL("too many words in diceware passphrase");
		scratch[no_input++] = wordlist_search(w, in, &in);
	}
	if (no_input != (size_t)codec_words) FATAL("the diceware passphrase "
			"has %zu words, but -c specifies %d words", no_input,
			codec_words);

	/* size of the master secret: enough bits for j and for the gain,
	 * at least 128 bits and a multiple of 16 bits */
	fixnum_init(&j, codec_scratch, L_max);
	if (diceware_range(&j, w, no_input))
		FATAL("diceware passphrase of %zu words does not fit "
				"in the largest master secret of %d bits",
				no_input, BLOCKS<<4);
	size_t bits = fixnum_calc_log2(&j) + 1 + honey_extra_bits(gain);
	if (bits < 128) bits = 128;
	bits = (bits + 15)&~(size_t)15;
	if (bits > BLOCKS<<4) FATAL("diceware passphrase of %zu words "
			"needs a master secret of %zu bits with gain %g, "
			"the maximum is %d bits", no_input, bits, gain,
			BLOCKS<<4);

	size_t L = bits>>3;
	fixnum_init(&j, codec_scratch, L);
	fixnum_init(&k, codec_scratch + L, L);
	uint8_t *random = codec_scratch + 2*L;
	uint8_t *honey_scratch = codec_scratch + 3*L;

	diceware_range(&j, w, no_input);
	base_decode_fixnum(&k, &w->m, scratch, no_input, 0);

	/* the randomness for the DTE comes from SEED, it is independent
	 * of the passphrase and of the master secret */
	pbkdf2(random, "honey", 5, seed, seed_len, 1, L, HASH_SHA256);

	fixnum_t x;
	fixnum_init(&x, out, L);
	honey_encode(&x, &k, &j, bits, random, honey_scratch);

	*n = L;
}

static void diceware_decode(char *out, size_t out_size, lrcipher_t *l,
		uint16_t *scratch, size_t scratch_size,
		const uint8_t *in, size_t n, wordlist_t *w,
		base_scratch_t *bs) {
	sbuf_t sbuf = { .buf = out, .size = out_size };
	fixnum_t k, j, x;

	// as defined by slip0039 and ensured somewhere else
	assert(n >= 16 && n%2 == 0 && n <= BLOCKS<<1);
	assert(w && w->m.value == 7776);

	fixnum_init(&j, codec_scratch, n);
	fixnum_init(&k, codec_scratch + n, n);
	fixnum_init(&x, codec_scratch + 2*n, n);
	uint8_t *honey_scratch = codec_scratch + 3*n;

	/* the largest number of words that fits in the master secret */
	size_t max_words = 0;
	while (!diceware_range(&j, w, max_words + 1)) max_words++;

	assert(codec_words > 0);
	if ((size_t)codec_words > max_words) FATAL("a diceware passphrase of %d "
			"words does not fit in a master secret of %zu bits, "
			"at most %zu words fit", codec_words, n<<3, max_words);
	assert(scratch_size >= (size_t)codec_words);

	diceware_range(&j, w, codec_words);
	fixnum_set_buffer(&x, in, n);
	honey_decode(&k, &x, &j, honey_scratch);

	base_encode_fixnum(scratch, codec_words, &w->m, &k, bs, 0);

	size_t i = 0;
	goto start;
	while (++i < (size_t)codec_words) {
		sbuf_printf(&sbuf, " ");
start:
		sbuf_wordlist_dereference(w, &sbuf, scratch[i]);
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
		.encode = diceware_encode,
		.decode = diceware_decode,
		.default_language = "english",
		.needs_words = 1
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

int codec_words = 0;

/* the modular DTE may give a guesser that tries passphrases a factor
 * of at most 1 + gain over plain guessing, see honey_extra_bits() */
double gain = 0.01;

uint8_t codec_scratch[CODEC_SCRATCH_SIZE];

void codec_init() {
	shashtbl_init_simple(&codecs, 4, 1);
	for (size_t i = 0; i < no_codecs; i++) {
		shashtbl_add_elt(&codecs, &codecs_array[i]);
		shashtbl_init_simple(&codecs_array[i].wordlists, 4, 1);
	}

}

codec_t *codec_find(const char *key) {
	return shashtbl_search_elt_bykey(&codecs, key);
}
