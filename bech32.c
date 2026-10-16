/* bech32.c - checksums of bech32 (BIP-0173) and codex32 (BIP-0093)
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
#include "bech32.h"
#include "utils.h"

/* bech32, BIP-0173 */

static uint32_t bech32_add_value(uint32_t chk, uint16_t value) {
	const uint32_t gen[] = {
		0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3
	};
	uint32_t b = chk>>25;

	assert(value < 32);
	chk = ((chk&0x1ffffff)<<5)^value;

	for (size_t i = 0; i < sizeof_array(gen); i++) {
		/* constant time version of: if ((b>>i)&1) chk ^= gen[i]; */
		chk ^= gen[i]&(-((b>>i)&1));
	}

	return chk;
}

/* polymod of the expansion of hrp, followed by data */
static uint32_t bech32_polymod(const char *hrp, const uint16_t *data,
		size_t len) {
	uint32_t chk = 1;
	const char *c;

	for (c = hrp; *c; c++) chk = bech32_add_value(chk, (*c)>>5);
	chk = bech32_add_value(chk, 0);
	for (c = hrp; *c; c++) chk = bech32_add_value(chk, (*c)&31);

	for (size_t i = 0; i < len; i++)
		chk = bech32_add_value(chk, data[i]);

	return chk;
}

int bech32_verify(const char *hrp, const uint16_t *data, size_t len) {
	return bech32_polymod(hrp, data, len) == 1;
}

void bech32_checksum(const char *hrp, const uint16_t *data, size_t len,
		uint16_t *out) {
	uint32_t chk = bech32_polymod(hrp, data, len);

	for (int i = 0; i < BECH32_CHECKSUM_LEN; i++)
		chk = bech32_add_value(chk, 0);

	chk ^= 1;

	for (int i = 0; i < BECH32_CHECKSUM_LEN; i++)
		out[i] = (chk>>(5*(BECH32_CHECKSUM_LEN - 1 - i)))&31;
}

/* codex32, BIP-0093, the residue has 65 bits (regular checksum) or
 * 75 bits (long checksum), so we use two 64 bit words */

typedef struct ms32_s {
	uint64_t hi, lo;
} ms32_t;

typedef struct ms32_variant_s {
	int bits, checksum_len;
	ms32_t gen[5], constant;
} ms32_variant_t;

static const ms32_variant_t ms32_regular = {
	.bits = 65,
	.checksum_len = 13,
	.gen = {
		{ 0x001, 0x9dc500ce73fde210 },
		{ 0x001, 0xbfae00def77fe529 },
		{ 0x001, 0xfbd920fffe7bee52 },
		{ 0x001, 0x739640bdeee3fdad },
		{ 0x000, 0x7729a039cfc75f5a }
	},
	.constant = { 0x001, 0x0ce0795c2fd1e62a }
};

static const ms32_variant_t ms32_long = {
	.bits = 75,
	.checksum_len = 15,
	.gen = {
		{ 0x3d5, 0x9d273535ea62d897 },
		{ 0x7a9, 0xbecb6361c6c51507 },
		{ 0x543, 0xf9b7e6c38d8a2a0e },
		{ 0x0c5, 0x77eaeccf1990d13c },
		{ 0x188, 0x7f74f8dc71b10651 }
	},
	.constant = { 0x433, 0x81e570bf4798ab26 }
};

/* the length of the expansion of the human readable part "ms" */
#define MS32_HRP_LEN 5

static void ms32_add_value(ms32_t *r, const ms32_variant_t *v,
		uint16_t value) {
	const int top = v->bits - 5; /* 60 or 70 */
	uint64_t b;

	assert(value < 32 && top > 59 && top < 128 - 5);

	/* b = r>>top, r &= (1<<top) - 1 */
	if (top < 64) {
		b = r->lo>>top|r->hi<<(64 - top);
		r->lo &= ((uint64_t)1<<top) - 1;
		r->hi = 0;
	} else {
		b = r->hi>>(top - 64);
		r->hi &= ((uint64_t)1<<(top - 64)) - 1;
	}

	/* r = r<<5^value */
	r->hi = r->hi<<5|r->lo>>59;
	r->lo = r->lo<<5^value;

	for (int i = 0; i < 5; i++) {
		/* constant time version of: if ((b>>i)&1) r ^= gen[i]; */
		uint64_t mask = -((b>>i)&1);
		r->hi ^= v->gen[i].hi&mask;
		r->lo ^= v->gen[i].lo&mask;
	}
}

static void ms32_polymod(ms32_t *r, const ms32_variant_t *v,
		const uint16_t *data, size_t len) {
	r->hi = 0;
	r->lo = 0x23181b3;
	for (size_t i = 0; i < len; i++) ms32_add_value(r, v, data[i]);
}

/* the variant for a data part of len characters (including the
 * checksum), or NULL if the length is invalid */
static const ms32_variant_t *ms32_variant(size_t len) {
	if (MS32_HRP_LEN + len <= 93) return &ms32_regular;
	if (MS32_HRP_LEN + len >= 96 && MS32_HRP_LEN + len <= 1023)
		return &ms32_long;
	return NULL;
}

int ms32_checksum_len(size_t len) {
	const ms32_variant_t *v;

	if (MS32_HRP_LEN + len + ms32_regular.checksum_len <= 93)
		v = &ms32_regular;
	else v = &ms32_long;

	if (ms32_variant(len + v->checksum_len) != v) return 0;

	return v->checksum_len;
}

int ms32_verify(const uint16_t *data, size_t len) {
	const ms32_variant_t *v = ms32_variant(len);
	ms32_t r;

	if (!v || len < (size_t)v->checksum_len) return 0;

	ms32_polymod(&r, v, data, len);

	if (r.hi != v->constant.hi || r.lo != v->constant.lo) return 0;

	return v->checksum_len;
}

void ms32_checksum(const uint16_t *data, size_t len, uint16_t *out) {
	int checksum_len = ms32_checksum_len(len);
	const ms32_variant_t *v = ms32_variant(len + checksum_len);
	ms32_t r;

	assert(checksum_len && v);

	ms32_polymod(&r, v, data, len);
	for (int i = 0; i < checksum_len; i++) ms32_add_value(&r, v, 0);

	r.hi ^= v->constant.hi;
	r.lo ^= v->constant.lo;

	for (int i = 0; i < checksum_len; i++) {
		int shift = 5*(checksum_len - 1 - i);
		uint64_t x = shift >= 64 ? r.hi>>(shift - 64) :
			r.lo>>shift|(shift ? r.hi<<(64 - shift) : 0);
		out[i] = x&31;
	}
}
