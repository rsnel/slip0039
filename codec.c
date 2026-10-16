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
#include "bech32.h"

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

/* the modular codecs store a secret of count symbols, each of which
 * has one of m values (the words of a wordlist, the characters of an
 * alphabet or the values of a byte), as a number k, with
 * 0 <= k < j = m^count, honey encoded with the modular DTE in a master
 * secret of n bits, so that every master secret decodes to a secret
 * of count symbols; count is given with -c CODEC:[WORDLIST]:COUNT,
 * when splitting it must match the secret */

static int codec_count = 0;

static void count_parse_arg(const char *arg) {
	char *end;

	codec_count = parse_number(arg, codec->arg_name, 1, BLOCKS<<4,
			&end, 1);
}

/* j = m^count, returns nonzero on overflow */
static int modular_range(fixnum_t *j, const fixnum_multiplier16_t *m,
		size_t count) {
	fixnum_set_uint16(j, 1);
	for (size_t i = 0; i < count; i++)
		if (fixnum_mul16(j, m)) return 1;
	return 0;
}

/* stores the number with count digits in base m in out */
static void modular_encode(uint8_t *out, size_t *n,
		const fixnum_multiplier16_t *m, const uint16_t *digits,
		size_t count, const char *unit,
		const char *seed, size_t seed_len) {
	const size_t L_max = BLOCKS<<1;
	fixnum_t k, j, x;

	assert(count > 0);

	/* size of the master secret: enough bits for j and for the gain,
	 * at least 128 bits and a multiple of 16 bits */
	fixnum_init(&j, codec_scratch, L_max);
	if (modular_range(&j, m, count))
		FATAL("a secret of %zu %s does not fit in the largest "
				"master secret of %d bits", count, unit,
				BLOCKS<<4);
	size_t bits = fixnum_calc_log2(&j) + 1 + honey_extra_bits(gain);
	if (bits < 128) bits = 128;
	bits = (bits + 15)&~(size_t)15;
	if (bits > BLOCKS<<4) FATAL("a secret of %zu %s needs a master "
			"secret of %zu bits with gain %g, the maximum is %d "
			"bits", count, unit, bits, gain, BLOCKS<<4);

	size_t L = bits>>3;
	fixnum_init(&j, codec_scratch, L);
	fixnum_init(&k, codec_scratch + L, L);
	uint8_t *random = codec_scratch + 2*L;
	uint8_t *honey_scratch = codec_scratch + 3*L;

	modular_range(&j, m, count);
	base_decode_fixnum(&k, m, digits, count, 0);

	/* the randomness for the DTE comes from SEED, it is independent
	 * of the secret and of the master secret */
	pbkdf2(random, "honey", 5, seed, seed_len, 1, L, HASH_SHA256);

	fixnum_init(&x, out, L);
	honey_encode(&x, &k, &j, bits, random, honey_scratch);

	*n = L;
}

/* recovers count digits in base m from the master secret in */
static void modular_decode(uint16_t *digits, size_t digits_size,
		size_t count, const fixnum_multiplier16_t *m,
		const char *unit, const uint8_t *in, size_t n,
		base_scratch_t *bs) {
	fixnum_t k, j, x;

	// as defined by slip0039 and ensured somewhere else
	assert(n >= 16 && n%2 == 0 && n <= BLOCKS<<1);
	assert(count > 0);

	fixnum_init(&j, codec_scratch, n);
	fixnum_init(&k, codec_scratch + n, n);
	fixnum_init(&x, codec_scratch + 2*n, n);
	uint8_t *honey_scratch = codec_scratch + 3*n;

	/* the largest number of symbols that fits in the master secret */
	size_t max_count = 0;
	while (!modular_range(&j, m, max_count + 1)) max_count++;

	if (count > max_count) FATAL("a secret of %zu %s does not fit in a "
			"master secret of %zu bits, at most %zu %s fit",
			count, unit, n<<3, max_count, unit);
	assert(digits_size >= count);

	modular_range(&j, m, count);
	fixnum_set_buffer(&x, in, n);
	honey_decode(&k, &x, &j, honey_scratch);

	base_encode_fixnum(digits, count, m, &k, bs, 0);
}

/* the diceware, password and numeric codecs: the symbols are the words
 * of the wordlist separated by spaces, or the characters of the
 * alphabet if all words have length 1 */
static const char *symbols_unit(const wordlist_t *w) {
	return w->max_word_length > 1 ? "words" : "characters";
}

static void symbols_encode(uint8_t *out, size_t *n,
		lrcipher_t *l, uint16_t *scratch,
		size_t scratch_size, const char *in,
		wordlist_t *w, const char *seed, size_t seed_len,
		base_scratch_t *bs) {
	size_t no_input = 0;

	assert(w);

	while (*in) {
		if (no_input == scratch_size)
			FATAL("too many %s in secret", symbols_unit(w));
		scratch[no_input++] = wordlist_search(w, in, &in);
	}

	if (no_input != (size_t)codec_count) FATAL("the secret has %zu %s, "
			"but -c specifies %d", no_input, symbols_unit(w),
			codec_count);

	modular_encode(out, n, &w->m, scratch, no_input, symbols_unit(w),
			seed, seed_len);
}

static void symbols_decode(char *out, size_t out_size, lrcipher_t *l,
		uint16_t *scratch, size_t scratch_size,
		const uint8_t *in, size_t n, wordlist_t *w,
		base_scratch_t *bs) {
	sbuf_t sbuf = { .buf = out, .size = out_size };

	assert(w && codec_count > 0);

	modular_decode(scratch, scratch_size, codec_count, &w->m,
			symbols_unit(w), in, n, bs);

	for (size_t i = 0; i < (size_t)codec_count; i++) {
		if (i && w->max_word_length > 1) sbuf_printf(&sbuf, " ");
		sbuf_wordlist_dereference(w, &sbuf, scratch[i]);
	}
}

/* helpers for alphabets with letters of one case */

/* bit 0: c is a lower case letter, bit 1: c is an upper case letter */
static int letter_case(char c) {
	return ((uint8_t)(c - 'a') < 26)|((uint8_t)(c - 'A') < 26)<<1;
}

/* looks up c in alphabet w, letters are converted to lower case if
 * lower is set and to upper case otherwise */
static uint16_t alphabet_search(wordlist_t *w, char c, int lower) {
	char buf[2] = { 0, 0 };
	const char *end;
	int cs = letter_case(c);

	if (lower) buf[0] = c|(0x20&-((cs>>1)&1));
	else buf[0] = c&~(0x20&-(cs&1));

	return wordlist_search(w, buf, &end);
}

/* converts the lower case letters in buf to upper case */
static void to_upper(char *buf, size_t len) {
	for (size_t i = 0; i < len; i++)
		buf[i] &= ~(0x20&-(letter_case(buf[i])&1));
}

/* the totp codec stores the base32 (RFC 4648) secret of a TOTP or HOTP
 * authenticator (RFC 6238, RFC 4226) as a number of bytes with the
 * modular DTE (m = 256); the number of base32 characters (without
 * padding) is given with -c totp::NO_CHARS; spaces, padding (=) and
 * lower case letters are accepted when splitting */

static fixnum_multiplier16_t m256;

/* the number of bytes encoded in a base32 string of len characters,
 * 0 if len is not the length of the base32 encoding of whole bytes */
static size_t base32_bytes(size_t len) {
	size_t n = 5*len/8;
	return (8*n + 4)/5 == len ? n : 0;
}

static void totp_parse_arg(const char *arg) {
	count_parse_arg(arg);
	if (!base32_bytes(codec_count)) FATAL("a base32 string of %d "
			"characters does not encode a whole number of bytes",
			codec_count);
}

static void totp_encode(uint8_t *out, size_t *n,
		lrcipher_t *l, uint16_t *scratch,
		size_t scratch_size, const char *in,
		wordlist_t *w, const char *seed, size_t seed_len,
		base_scratch_t *bs) {
	uint8_t *buf = codec_scratch;
	size_t no_input = 0;

	for (; *in; in++) {
		if (*in == ' ' || *in == '=') continue;
		if (no_input == scratch_size)
			FATAL("TOTP secret is too long");
		scratch[no_input++] = alphabet_search(&wordlist_base32, *in, 0);
	}

	if (no_input != (size_t)codec_count) FATAL("the TOTP secret has %zu "
			"characters, but -c specifies %d", no_input,
			codec_count);

	size_t len = base32_bytes(no_input);
	int p = 5*no_input - 8*len; /* number of unused bits */
	assert(len > 0 && p >= 0 && p < 5);

	/* the unused bits end up in buf[len] */
	if (base_decode_buffer(buf, len + 1, &wordlist_base32.m,
				scratch, no_input, 8 - p))
		BUG("base32 string does not fit");
	if (buf[len]) FATAL("invalid base32 string, the unused bits of the "
			"last character are not zero");

	for (size_t i = 0; i < len; i++) scratch[i] = buf[i];

	modular_encode(out, n, &m256, scratch, len, "bytes", seed, seed_len);
}

static void totp_decode(char *out, size_t out_size, lrcipher_t *l,
		uint16_t *scratch, size_t scratch_size,
		const uint8_t *in, size_t n, wordlist_t *w,
		base_scratch_t *bs) {
	sbuf_t sbuf = { .buf = out, .size = out_size };
	uint8_t *buf = codec_scratch;
	size_t len = base32_bytes(codec_count);
	int p = 5*codec_count - 8*len;

	assert(len > 0 && p >= 0 && p < 5);

	modular_decode(scratch, scratch_size, len, &m256, "bytes",
			in, n, bs);

	/* modular_decode ensures that len < n */
	assert(len + 1 <= bs->max_limbs && scratch_size >= codec_count);
	for (size_t i = 0; i < len; i++) buf[i] = scratch[i];
	buf[len] = 0;

	base_encode_buffer(scratch, codec_count, &wordlist_base32.m,
			buf, len + 1, bs, 8 - p);

	for (size_t i = 0; i < (size_t)codec_count; i++)
		sbuf_wordlist_dereference(&wordlist_base32, &sbuf, scratch[i]);
}

/* secp256k1 private keys and base58check (bitcoin) strings, layout of
 * codec_scratch: the hash, the data (at most B58_MAX bytes), the
 * fixnums to check the range of a private key and the scratch space
 * for base58 encoding */

#define B58_MAX		82	/* the size of a BIP32 extended key */
#define B58_HASH	0
#define B58_DATA	SHA256_LEN
#define B58_KEY		(B58_DATA + B58_MAX)
#define B58_BASE	(B58_KEY + 64)

/* enough base58 digits for len bytes */
#define B58_DIGITS(len)	((len)*138/100 + 1)

/* the order of the group of secp256k1 */
static const uint8_t secp256k1_order[32] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
	0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
	0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41
};

/* 0 < k < order, every master secret decodes to a valid key, except
 * with probability < 2^-127 */
static int secp256k1_valid(const uint8_t *key) {
	fixnum_t k, order;

	assert(B58_BASE <= CODEC_SCRATCH_SIZE);

	fixnum_init_buffer(&k, codec_scratch + B58_KEY, 32, key, 32);
	fixnum_init_buffer(&order, codec_scratch + B58_KEY + 32, 32,
			secp256k1_order, 32);

	return fixnum_popcnt(&k) && fixnum_sub_fixnum(&k, &order, 0xff);
}

/* decodes the base58check string in to len bytes (including the 4
 * checksum bytes) at codec_scratch + B58_DATA */
static uint8_t *base58check_decode(size_t len, const char *in,
		uint16_t *scratch, size_t scratch_size, const char *what) {
	uint8_t *h = codec_scratch + B58_HASH;
	uint8_t *data = codec_scratch + B58_DATA;
	size_t no_input = 0;

	assert(len > 4 && len <= B58_MAX);
	assert(scratch_size >= B58_DIGITS(len));

	while (*in) {
		if (no_input == B58_DIGITS(len))
			FATAL("%s is too long", what);
		scratch[no_input++] = wordlist_search(&wordlist_base58,
				in, &in);
	}

	if (!no_input) FATAL("no %s given", what);

	if (base_decode_buffer(data, len, &wordlist_base58.m,
				scratch, no_input, 0))
		FATAL("%s is too long", what);

	hash(h, SHA256_LEN, data, len - 4, HASH_SHA256D);
	if (memcmp(h, data + len - 4, 4))
		FATAL("invalid %s, checksum does not match", what);

	return data;
}

/* encodes the len bytes at codec_scratch + B58_DATA, of which the last
 * 4 bytes are replaced by the checksum, as base58check */
static void base58check_encode(sbuf_t *sbuf, size_t len,
		uint16_t *scratch, size_t scratch_size) {
	uint8_t *h = codec_scratch + B58_HASH;
	uint8_t *data = codec_scratch + B58_DATA;
	size_t i = 0;
	base_scratch_t b;

	assert(len > 4 && len <= B58_MAX);
	assert(scratch_size >= B58_DIGITS(len));
	assert(B58_BASE + 4*B58_MAX <= CODEC_SCRATCH_SIZE);

	hash(h, SHA256_LEN, data, len - 4, HASH_SHA256D);
	memcpy(data + len - 4, h, 4);

	/* the first byte is a version byte, which is not zero, so there
	 * are no leading 1s in the base58 encoding */
	assert(data[0]);

	base_init_scratch(&b, codec_scratch + B58_BASE, len);
	base_encode_buffer(scratch, B58_DIGITS(len), &wordlist_base58.m,
			data, len, &b, 0);

	while (!scratch[i]) i++;
	while (i < B58_DIGITS(len))
		sbuf_wordlist_dereference(&wordlist_base58, sbuf, scratch[i++]);
}

/* the bip32 codec stores a BIP32 root extended private key (depth 0,
 * no parent fingerprint and child number 0) as a master secret of 64
 * bytes: the private key k followed by the chain code c, which is the
 * output I = IL || IR of HMAC-SHA512 from which BIP32 derives the root
 * key; the version (xprv, yprv, zprv, ...) is not stored, it is given
 * with -c bip32::VERSION, when splitting it must match the key
 *
 * extended public keys are not supported: the compressed public key
 * needs the x coordinate and one bit for the parity of y, so it does
 * not fit in 64 bytes together with the chain code */

#define BIP32_LEN	82	/* 78 bytes of data and 4 checksum bytes */

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

static int bip32_version = -1; /* index in bip32_versions */

static void bip32_parse_arg(const char *arg) {
	for (size_t i = 0; i < sizeof_array(bip32_versions); i++) {
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

static void bip32_encode(uint8_t *out, size_t *n,
		lrcipher_t *l, uint16_t *scratch,
		size_t scratch_size, const char *in, wordlist_t *w,
		const char *seed, size_t seed_len, base_scratch_t *bs) {
	uint8_t *key;

	assert(BLOCKS<<1 >= 64);
	assert(bip32_version >= 0);

	key = base58check_decode(BIP32_LEN, in, scratch, scratch_size,
			"extended key");

	uint32_t version = (uint32_t)key[0]<<24|key[1]<<16|key[2]<<8|key[3];
	if (version != bip32_versions[bip32_version].version) {
		for (size_t i = 0; i < sizeof_array(bip32_versions); i++)
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

	if (!secp256k1_valid(key + 46))
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
	uint8_t *key = codec_scratch + B58_DATA;
	uint32_t version;

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

	base58check_encode(&sbuf, BIP32_LEN, scratch, scratch_size);
}

/* the wif codec stores a secp256k1 private key k in the Wallet Import
 * Format as a master secret of 32 bytes; the network and whether the
 * key is used with a compressed public key are not stored, they are
 * given with -c wif::TYPE, when splitting it must match the key */

static const struct {
	const char *name;
	uint8_t version;
	int compressed;
} wif_types[] = {
	{ "compressed", 0x80, 1 },
	{ "uncompressed", 0x80, 0 },
	{ "testnet-compressed", 0xef, 1 },
	{ "testnet-uncompressed", 0xef, 0 }
};

static int wif_type = -1; /* index in wif_types */

static void wif_parse_arg(const char *arg) {
	for (size_t i = 0; i < sizeof_array(wif_types); i++) {
		if (strcmp(arg, wif_types[i].name)) continue;
		wif_type = i;
		return;
	}

	FATAL("unknown type \"%s\" for codec wif, supported are compressed, "
			"uncompressed, testnet-compressed and "
			"testnet-uncompressed", arg);
}

static void wif_encode(uint8_t *out, size_t *n,
		lrcipher_t *l, uint16_t *scratch,
		size_t scratch_size, const char *in, wordlist_t *w,
		const char *seed, size_t seed_len, base_scratch_t *bs) {
	int compressed;
	uint8_t *key;

	assert(wif_type >= 0);
	compressed = wif_types[wif_type].compressed;

	/* uncompressed keys have 51 characters, compressed keys 52 */
	if (strlen(in) == 52 - compressed)
		FATAL("the WIF key is %scompressed, but -c specifies %s",
				compressed?"un":"", wif_types[wif_type].name);

	key = base58check_decode(33 + compressed + 4, in,
			scratch, scratch_size, "WIF key");

	if (key[0] != wif_types[wif_type].version)
		FATAL("the WIF key has version 0x%02x, but -c specifies %s "
				"(version 0x%02x)", key[0],
				wif_types[wif_type].name,
				wif_types[wif_type].version);

	if (compressed && key[33] != 0x01) FATAL("invalid WIF key, the "
			"compression flag is not 0x01");

	if (!secp256k1_valid(key + 1)) FATAL("invalid WIF key, the private "
			"key is not in the range [1, n-1]");

	memcpy(out, key + 1, 32);

	*n = 32;
}

static void wif_decode(char *out, size_t out_size, lrcipher_t *l,
		uint16_t *scratch, size_t scratch_size,
		const uint8_t *in, size_t n, wordlist_t *w,
		base_scratch_t *bs) {
	sbuf_t sbuf = { .buf = out, .size = out_size };
	uint8_t *key = codec_scratch + B58_DATA;
	int compressed;

	assert(wif_type >= 0);
	compressed = wif_types[wif_type].compressed;

	if (n != 32) FATAL("the master secret has %zu bytes, codec wif "
			"needs 32 bytes", n);

	key[0] = wif_types[wif_type].version;
	memcpy(key + 1, in, 32);
	key[33] = 0x01; /* overwritten by the checksum if uncompressed */

	base58check_encode(&sbuf, 33 + compressed + 4, scratch, scratch_size);
}

/* the nostr codec stores a nostr private key (NIP-19, bech32 with the
 * human readable part nsec) as a master secret of 32 bytes */

#define NSEC_HRP	"nsec"
#define NSEC_CHARS	52	/* 32 bytes and 4 padding bits */

static void nostr_encode(uint8_t *out, size_t *n,
		lrcipher_t *l, uint16_t *scratch,
		size_t scratch_size, const char *in, wordlist_t *w,
		const char *seed, size_t seed_len, base_scratch_t *bs) {
	const size_t len = NSEC_CHARS + BECH32_CHECKSUM_LEN;
	uint8_t *key = codec_scratch;
	size_t no_input = 0;
	int cases = 0;

	assert(scratch_size >= len);

	for (const char *p = NSEC_HRP "1"; *p; p++, in++) {
		cases |= letter_case(*in);
		if ((*in|0x20) != *p) FATAL("nostr private key does not start "
				"with %s1", NSEC_HRP);
	}

	while (*in) {
		if (no_input == len) FATAL("nostr private key is too long");
		cases |= letter_case(*in);
		scratch[no_input++] = alphabet_search(&wordlist_bech32,
				*in++, 1);
	}

	if (cases == 3) FATAL("nostr private key mixes upper and lower case");
	if (no_input != len) FATAL("nostr private key is too short");

	if (!bech32_verify(NSEC_HRP, scratch, len))
		FATAL("invalid nostr private key, checksum does not match");

	/* the padding bits end up in key[32] */
	if (base_decode_buffer(key, 33, &wordlist_bech32.m,
				scratch, NSEC_CHARS, 4))
		BUG("nostr private key does not fit");
	if (key[32]) FATAL("invalid nostr private key, the padding bits "
			"are not zero");

	if (!secp256k1_valid(key)) FATAL("invalid nostr private key, the "
			"private key is not in the range [1, n-1]");

	memcpy(out, key, 32);

	*n = 32;
}

static void nostr_decode(char *out, size_t out_size, lrcipher_t *l,
		uint16_t *scratch, size_t scratch_size,
		const uint8_t *in, size_t n, wordlist_t *w,
		base_scratch_t *bs) {
	sbuf_t sbuf = { .buf = out, .size = out_size };
	const size_t len = NSEC_CHARS + BECH32_CHECKSUM_LEN;
	uint8_t *key = codec_scratch;

	assert(scratch_size >= len);

	if (n != 32) FATAL("the master secret has %zu bytes, codec nostr "
			"needs 32 bytes", n);

	memcpy(key, in, 32);
	key[32] = 0;

	base_encode_buffer(scratch, NSEC_CHARS, &wordlist_bech32.m,
			key, 33, bs, 4);
	bech32_checksum(NSEC_HRP, scratch, NSEC_CHARS, scratch + NSEC_CHARS);

	sbuf_printf(&sbuf, "%s1", NSEC_HRP);
	for (size_t i = 0; i < len; i++)
		sbuf_wordlist_dereference(&wordlist_bech32, &sbuf, scratch[i]);
}

/* the codex32 codec stores a codex32 secret (BIP-0093, share index s)
 * as a master secret that is the BIP32 master seed (16, 20, 24, 28, 32
 * or 64 bytes) it encodes; the threshold and the identifier are not
 * stored, they are given with -c codex32::HEADER, for example
 * -c codex32::0test, when splitting they must match the secret; the
 * secret is recovered in the case of HEADER (upper case is
 * recommended for handwriting); the padding bits are not stored, they
 * are zero when recovering, which encodes the same master seed */

#define CODEX32_HEADER_LEN	5	/* threshold and identifier */
#define CODEX32_S		16	/* value of the share index s */

static uint16_t codex32_header[CODEX32_HEADER_LEN];
static int codex32_upper;

static int codex32_seed_size(size_t n) {
	return n == 16 || n == 20 || n == 24 || n == 28 || n == 32 || n == 64;
}

static void codex32_parse_arg(const char *arg) {
	int cases = 0;

	if (strlen(arg) != CODEX32_HEADER_LEN) FATAL("the header of a "
			"codex32 secret is the threshold followed by the 4 "
			"character identifier, as in 0test");

	if (arg[0] != '0' && (arg[0] < '2' || arg[0] > '9')) FATAL("the "
			"threshold of a codex32 secret must be 0 or 2-9");

	for (int i = 0; i < CODEX32_HEADER_LEN; i++) {
		cases |= letter_case(arg[i]);
		codex32_header[i] = alphabet_search(&wordlist_bech32,
				arg[i], 1);
	}

	if (cases == 3) FATAL("the header of a codex32 secret must not mix "
			"upper and lower case");

	codex32_upper = cases == 2;
}

static void codex32_encode(uint8_t *out, size_t *n,
		lrcipher_t *l, uint16_t *scratch,
		size_t scratch_size, const char *in, wordlist_t *w,
		const char *seed, size_t seed_len, base_scratch_t *bs) {
	uint8_t *key = codec_scratch;
	size_t no_input = 0;
	const char *data;
	int cases = 0, checksum_len;

	for (const char *p = "ms1"; *p; p++, in++) {
		cases |= letter_case(*in);
		if ((*in|0x20) != *p) FATAL("codex32 secret does not start "
				"with ms1");
	}

	data = in;
	while (*in) {
		if (no_input == scratch_size)
			FATAL("codex32 secret is too long");
		cases |= letter_case(*in);
		scratch[no_input++] = alphabet_search(&wordlist_bech32,
				*in++, 1);
	}

	if (cases == 3) FATAL("codex32 secret mixes upper and lower case");

	if (!(checksum_len = ms32_verify(scratch, no_input)))
		FATAL("invalid codex32 secret, the checksum does not match "
				"or the length is invalid");

	if (no_input < CODEX32_HEADER_LEN + 1 + checksum_len)
		FATAL("codex32 secret is too short");

	for (int i = 0; i < CODEX32_HEADER_LEN; i++)
		if (scratch[i] != codex32_header[i])
			FATAL("the header of the codex32 secret is %.*s, but "
					"-c specifies %s", CODEX32_HEADER_LEN,
					data, codec_arg);

	if (scratch[CODEX32_HEADER_LEN] != CODEX32_S) FATAL("this is a "
			"codex32 share, not a codex32 secret (the share index "
			"is not s)");

	size_t P = no_input - CODEX32_HEADER_LEN - 1 - checksum_len;
	size_t len = 5*P/8;
	int p = 5*P - 8*len; /* number of padding bits */

	if (p > 4 || !codex32_seed_size(len)) FATAL("the codex32 secret does "
			"not encode a master seed of 16, 20, 24, 28, 32 or 64 "
			"bytes");

	/* the padding bits end up in key[len] */
	if (base_decode_buffer(key, len + 1, &wordlist_bech32.m,
				scratch + CODEX32_HEADER_LEN + 1, P, 8 - p))
		BUG("master seed does not fit");
	if (key[len]) WARNING("the padding bits of the codex32 secret are "
			"not zero, they are not stored; recover gives the "
			"codex32 secret with zero padding bits, which encodes "
			"the same master seed");

	memcpy(out, key, len);

	*n = len;
}

static void codex32_decode(char *out, size_t out_size, lrcipher_t *l,
		uint16_t *scratch, size_t scratch_size,
		const uint8_t *in, size_t n, wordlist_t *w,
		base_scratch_t *bs) {
	sbuf_t sbuf = { .buf = out, .size = out_size };
	uint8_t *key = codec_scratch;
	size_t P = (8*n + 4)/5, len = CODEX32_HEADER_LEN + 1 + P;
	int p = 5*P - 8*n, checksum_len = ms32_checksum_len(len);
	base_scratch_t b;

	if (!codex32_seed_size(n)) FATAL("the master secret has %zu bytes, "
			"codex32 supports master seeds of 16, 20, 24, 28, 32 "
			"or 64 bytes", n);

	assert(checksum_len && scratch_size >= len + checksum_len);
	assert(B58_MAX + 4*(n + 1) <= CODEC_SCRATCH_SIZE);

	memcpy(scratch, codex32_header, sizeof(codex32_header));
	scratch[CODEX32_HEADER_LEN] = CODEX32_S;

	memcpy(key, in, n);
	key[n] = 0;

	/* the scratch space of bs is too small for a seed of 64 bytes */
	base_init_scratch(&b, codec_scratch + B58_MAX, n + 1);
	base_encode_buffer(scratch + CODEX32_HEADER_LEN + 1, P,
			&wordlist_bech32.m, key, n + 1, &b, 8 - p);

	ms32_checksum(scratch, len, scratch + len);

	sbuf_printf(&sbuf, "ms1");
	for (size_t i = 0; i < len + checksum_len; i++)
		sbuf_wordlist_dereference(&wordlist_bech32, &sbuf, scratch[i]);

	if (codex32_upper) to_upper(out, sbuf.len);
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
		.encode = symbols_encode,
		.decode = symbols_decode,
		.default_language = "english",
		.parse_arg = count_parse_arg,
		.arg_name = "number of words",
		.arg_example = "diceware::12"
	}, {
		.elt.key = "password",
		.encode = symbols_encode,
		.decode = symbols_decode,
		.default_language = "alnum",
		.parse_arg = count_parse_arg,
		.arg_name = "length of the password",
		.arg_example = "password::20 or -c password:ascii:16"
	}, {
		.elt.key = "numeric",
		.encode = symbols_encode,
		.decode = symbols_decode,
		.default_language = "",
		.parse_arg = count_parse_arg,
		.arg_name = "number of digits",
		.arg_example = "numeric::6"
	}, {
		.elt.key = "totp",
		.encode = totp_encode,
		.decode = totp_decode,
		.default_language = NULL,
		.parse_arg = totp_parse_arg,
		.arg_name = "number of base32 characters",
		.arg_example = "totp::32"
	}, {
		.elt.key = "bip32",
		.encode = bip32_encode,
		.decode = bip32_decode,
		.default_language = NULL,
		.parse_arg = bip32_parse_arg,
		.arg_name = "version of the extended key",
		.arg_example = "bip32::xprv"
	}, {
		.elt.key = "wif",
		.encode = wif_encode,
		.decode = wif_decode,
		.default_language = NULL,
		.parse_arg = wif_parse_arg,
		.arg_name = "type of the key",
		.arg_example = "wif::compressed"
	}, {
		.elt.key = "nostr",
		.encode = nostr_encode,
		.decode = nostr_decode,
		.default_language = NULL
	}, {
		.elt.key = "codex32",
		.encode = codex32_encode,
		.decode = codex32_decode,
		.default_language = NULL,
		.parse_arg = codex32_parse_arg,
		.arg_name = "threshold and identifier",
		.arg_example = "codex32::0test"
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

	fixnum_multiplier16_init(&m256, 256);
}

codec_t *codec_find(const char *key) {
	return shashtbl_search_elt_bykey(&codecs, key);
}
