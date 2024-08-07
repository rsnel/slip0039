/* base.c - base encoding and decoding
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
#include <assert.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "base.h"
#include "fixnum.h"

void base_init_scratch(base_scratch_t *bs, uint8_t *scratch, size_t max_limbs) {
	assert(bs && scratch && max_limbs >= 2);
	bs->divisor_limbs = scratch;
	bs->data_limbs = scratch + max_limbs;
	fixnum_scratch_init(&bs->s, scratch + 2*max_limbs, max_limbs, scratch + 3*max_limbs, max_limbs);
	bs->max_limbs = max_limbs;
}

static void base_encode_fixnum_destructive(uint16_t *out, size_t out_size,
                const fixnum_multiplier16_t *m,
                fixnum_t *in, base_scratch_t *bs, uint8_t shift) {
	fixnum_divisor_t d;
	fixnum_divisor_init_from_multiplier16(&d, m,  bs->divisor_limbs, in->no_limbs);
	fixnum_shr(in, shift);
	for (int i = out_size - 1; i >= 0; i--)
		out[i] = fixnum_div(in, &d, &bs->s, 0);
}

void base_encode_buffer(uint16_t *out, size_t out_size,
		const fixnum_multiplier16_t *m,
		const uint8_t *in, size_t in_size,
		base_scratch_t *bs, uint8_t shift) {
	assert(bs->max_limbs >= in_size);
        fixnum_t d;
	fixnum_init_buffer(&d, bs->data_limbs, in_size, in, in_size);
	base_encode_fixnum_destructive(out, out_size, m, &d, bs, shift);
}

void base_encode_fixnum(uint16_t *out, size_t out_size,
		const fixnum_multiplier16_t *m,
		const fixnum_t *in, base_scratch_t *bs, uint8_t shift) {
	assert(out && m && m->value> 1 && in && bs && in->no_limbs <= bs->max_limbs);
	fixnum_t data;
	fixnum_init_fixnum(&data, bs->data_limbs, in->no_limbs, in);
	base_encode_fixnum_destructive(out, out_size, m, &data, bs, shift);
}

int base_decode_buffer(uint8_t *out, size_t out_size, const fixnum_multiplier16_t *m,
		const uint16_t *in, size_t in_size, uint8_t shift) {
	fixnum_t d;
	fixnum_init(&d, out, out_size);
	return base_decode_fixnum(&d, m, in, in_size, shift);
}

int base_decode_fixnum(fixnum_t *d, const fixnum_multiplier16_t *m,
		const uint16_t *in, size_t in_size, uint8_t shift) {
	int i = 0;

	fixnum_set_pattern(d, PATTERN_ZERO);
	goto start;

	do {
		if (fixnum_mul16(d, m)) return 1; // overflow
	start:
		assert(in[i] < m->value);
		fixnum_add_uint16(d, in[i]);
	} while (++i < in_size);

	fixnum_shl(d, shift);

	return 0; // ok
}


