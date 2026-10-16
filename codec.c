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
#include <string.h>
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

	assert(scratch_size<<1 >= SHA256_LEN); // space for sha256 hash
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

	hash(s, SHA256_LEN, out, *n, HASH_SHA256);

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

static int codec_words = 0;

static void diceware_parse_arg(const char *arg) {
	char *end;

	codec_words = parse_number(arg, "number of words", 1, WORDS, &end, 1);
}

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

/* the bip32 codec stores a BIP32 root extended private key (depth 0,
 * no parent fingerprint and child number 0) as a master secret of 64
 * bytes: the private key k followed by the chain code c, which is the
 * output I = IL || IR of HMAC-SHA512 from which BIP32 derives the root
 * key; the version (xprv, yprv, zprv, ...) is not stored, it is given
 * with -c bip32::VERSION, when splitting it must match the key
 *
 * every master secret decodes to a valid key, except when k = 0 or
 * k >= the order of secp256k1, which happens with probability < 2^-127
 *
 * extended public keys are not supported: the compressed public key
 * needs the x coordinate and one bit for the parity of y, so it does
 * not fit in 64 bytes together with the chain code */

#define BIP32_LEN	82	/* 78 bytes of data and 4 checksum bytes */
#define BIP32_DIGITS	112	/* 58^112 > 2^(8*BIP32_LEN) */

/* SLIP-0132 */
static const struct {
	const char *name;
	uint32_t version;
	int private;
} bip32_versions[] = {
	{ "xpub", 0x0488b21e, 0 }, { "xprv", 0x0488ade4, 1 },
	{ "ypub", 0x049d7cb2, 0 }, { "yprv", 0x049d7878, 1 },
	{ "zpub", 0x04b24746, 0 }, { "zprv", 0x04b2430c, 1 },
	{ "Ypub", 0x0295b43f, 0 }, { "Yprv", 0x0295b005, 1 },
	{ "Zpub", 0x02aa7ed3, 0 }, { "Zprv", 0x02aa7a99, 1 },
	{ "tpub", 0x043587cf, 0 }, { "tprv", 0x04358394, 1 },
	{ "upub", 0x044a5262, 0 }, { "uprv", 0x044a4e28, 1 },
	{ "vpub", 0x045f1cf6, 0 }, { "vprv", 0x045f18bc, 1 },
	{ "Upub", 0x024289ef, 0 }, { "Uprv", 0x024285b5, 1 },
	{ "Vpub", 0x02575483, 0 }, { "Vprv", 0x02575048, 1 }
};

#define BIP32_NO_VERSIONS (sizeof(bip32_versions)/sizeof(*bip32_versions))

/* the order of the group of secp256k1 */
static const uint8_t bip32_order[32] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
	0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
	0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41
};

static int bip32_version = -1; /* index in bip32_versions */

static void bip32_parse_arg(const char *arg) {
	for (size_t i = 0; i < BIP32_NO_VERSIONS; i++) {
		if (strcmp(arg, bip32_versions[i].name)) continue;
		if (!bip32_versions[i].private) FATAL("%s is the version "
				"of an extended public key, codec bip32 only "
				"supports extended private keys", arg);
		bip32_version = i;
		return;
	}

	FATAL("unknown version \"%s\" for codec bip32, supported are xprv, "
			"yprv, zprv, Yprv, Zprv and, for testnet, tprv, "
			"uprv, vprv, Uprv and Vprv", arg);
}

/* layout of codec_scratch: the hash (first, because sha256 stores
 * 32 bit words), the serialized key, and the private key and the order
 * as fixnums, followed by the scratch space for base58 encoding */
#define BIP32_KEY	SHA256_LEN
#define BIP32_K		(BIP32_KEY + BIP32_LEN)
#define BIP32_ORDER	(BIP32_K + 32)
#define BIP32_BASE	(BIP32_ORDER + 32)

static void bip32_encode(uint8_t *out, size_t *n,
		lrcipher_t *l, uint16_t *scratch,
		size_t scratch_size, const char *in, wordlist_t *w,
		const char *seed, size_t seed_len, base_scratch_t *bs) {
	uint8_t *key = codec_scratch + BIP32_KEY, *h = codec_scratch;
	size_t no_input = 0;
	fixnum_t k, order;

	assert(scratch_size >= BIP32_DIGITS);
	assert(BIP32_BASE <= CODEC_SCRATCH_SIZE);
	assert(BLOCKS<<1 >= 64);
	assert(bip32_version >= 0);

	while (*in) {
		if (no_input == BIP32_DIGITS)
			FATAL("extended key is too long");
		scratch[no_input++] = wordlist_search(&wordlist_base58,
				in, &in);
	}

	if (!no_input) FATAL("no extended key given");

	if (base_decode_buffer(key, BIP32_LEN, &wordlist_base58.m,
				scratch, no_input, 0))
		FATAL("extended key is too long");

	hash(h, SHA256_LEN, key, BIP32_LEN - 4, HASH_SHA256D);
	if (memcmp(h, key + BIP32_LEN - 4, 4))
		FATAL("invalid extended key, checksum does not match");

	uint32_t version = (uint32_t)key[0]<<24|key[1]<<16|key[2]<<8|key[3];
	if (version != bip32_versions[bip32_version].version) {
		for (size_t i = 0; i < BIP32_NO_VERSIONS; i++)
			if (version == bip32_versions[i].version)
				FATAL("the version of the extended key is %s, "
						"but -c specifies %s",
						bip32_versions[i].name,
						bip32_versions[bip32_version].name);
		FATAL("unknown version 0x%08x of extended key", version);
	}

	for (int i = 4; i < 13; i++) if (key[i])
		FATAL("the extended key is not a root key, depth, parent "
				"fingerprint and child number must be zero");

	if (key[45]) FATAL("invalid extended private key, the key data "
			"does not start with 0x00");

	/* 0 < k < order */
	fixnum_init_buffer(&k, codec_scratch + BIP32_K, 32, key + 46, 32);
	fixnum_init_buffer(&order, codec_scratch + BIP32_ORDER, 32,
			bip32_order, 32);
	if (!fixnum_popcnt(&k) || !fixnum_sub_fixnum(&k, &order, 0xff))
		FATAL("invalid extended private key, the private key "
				"is not in the range [1, n-1]");

	memcpy(out, key + 46, 32);
	memcpy(out + 32, key + 13, 32);

	*n = 64;
}

static void bip32_decode(char *out, size_t out_size, lrcipher_t *l,
		uint16_t *scratch, size_t scratch_size,
		const uint8_t *in, size_t n, wordlist_t *w,
		base_scratch_t *bs) {
	sbuf_t sbuf = { .buf = out, .size = out_size };
	uint8_t *key = codec_scratch + BIP32_KEY, *h = codec_scratch;
	uint32_t version;
	base_scratch_t b;

	assert(scratch_size >= BIP32_DIGITS);
	assert(BIP32_BASE + 4*BIP32_LEN <= CODEC_SCRATCH_SIZE);
	assert(bip32_version >= 0);

	if (n != 64) FATAL("the master secret has %zu bytes, codec bip32 "
			"needs 64 bytes: a private key and a chain code", n);

	version = bip32_versions[bip32_version].version;
	key[0] = version>>24;
	key[1] = version>>16;
	key[2] = version>>8;
	key[3] = version;
	memset(key + 4, 0, 9); /* depth, fingerprint and child number */
	memcpy(key + 13, in + 32, 32);
	key[45] = 0x00;
	memcpy(key + 46, in, 32);

	hash(h, SHA256_LEN, key, BIP32_LEN - 4, HASH_SHA256D);
	memcpy(key + BIP32_LEN - 4, h, 4);

	/* the first byte of the version is not zero, so there are
	 * no leading 1s in the base58 encoding */
	assert(key[0]);

	base_init_scratch(&b, codec_scratch + BIP32_BASE, BIP32_LEN);
	base_encode_buffer(scratch, BIP32_DIGITS, &wordlist_base58.m,
			key, BIP32_LEN, &b, 0);

	size_t i = 0;
	while (!scratch[i]) i++;
	while (i < BIP32_DIGITS)
		sbuf_wordlist_dereference(&wordlist_base58, &sbuf, scratch[i++]);
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
		.parse_arg = diceware_parse_arg,
		.arg_name = "number of words",
		.arg_example = "diceware::12"
	}, {
		.elt.key = "bip32",
		.encode = bip32_encode,
		.decode = bip32_decode,
		.default_language = NULL,
		.parse_arg = bip32_parse_arg,
		.arg_name = "version of the extended key",
		.arg_example = "bip32::xprv"
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

const char *codec_arg = NULL;

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
