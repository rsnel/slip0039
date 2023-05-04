/* fixnum.h - a constant time bignum implementation for positive integers
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
#ifndef SLIP0039_FIXNUM_H
#define SLIP0039_FIXNUM_H

#include <stddef.h>
#include <stdint.h>

#include "config.h"

/* we work in a context where our binary data is processed in chunks
 * of 16 bits, but since we need to account for endianness, we represent
 * our fixnums as arrays of uint8_t's */

typedef struct fixnum_properties_s {
	uint8_t pure;
	uint8_t log2;
} fixnum_properties_t;

typedef struct fixnum_s {
	uint8_t *limbs; /* limbs stored in big endian order */
	size_t no_limbs; /* we need at least 2 limbs */
} fixnum_t;

typedef struct fixnum_multiplier16_s {
	uint16_t value;
	fixnum_properties_t p;
} fixnum_multiplier16_t;

typedef struct fixnum_divisor_s {
	//const fixnum_multiplier_t *m;
	fixnum_properties_t p;
	//uint8_t pure; // power of two?
	//uint8_t log2;
	fixnum_t max_left_shift;
} fixnum_divisor_t;

void fixnum_init(fixnum_t*, uint8_t*, size_t);

typedef enum fixnum_pattern_e {
	PATTERN_ZERO, PATTERN_MAX, PATTERN_ADD11
} fixnum_pattern_t;

typedef struct fixnum_scratch_s {
	fixnum_t a, b;
} fixnum_scratch_t;

void fixnum_scratch_init(fixnum_scratch_t*, uint8_t*, size_t, uint8_t*, size_t);

void fixnum_set_pattern(fixnum_t*, fixnum_pattern_t);

void fixnum_set_uint16(fixnum_t*, uint16_t);

void fixnum_set_fixnum(fixnum_t*, const fixnum_t*);

void fixnum_init_pattern(fixnum_t*, uint8_t*, size_t, fixnum_pattern_t);

void fixnum_init_uint16(fixnum_t*, uint8_t*, size_t, uint16_t);

void fixnum_init_buffer(fixnum_t*, uint8_t*, size_t, const uint8_t*, size_t);

void fixnum_init_fixnum(fixnum_t*, uint8_t*, size_t, const fixnum_t*);

void fixnum_multiplier16_init(fixnum_multiplier16_t*, uint16_t);

void fixnum_divisor_init_from_multiplier16(fixnum_divisor_t*, const fixnum_multiplier16_t*,
		uint8_t*, size_t);

uint32_t fixnum_peek(const fixnum_t*, size_t, uint8_t);

void fixnum_poke(fixnum_t*, size_t, uint8_t, uint32_t);

uint16_t fixnum_add_uint16(fixnum_t*, uint16_t);

uint16_t fixnum_add_fixnum(fixnum_t*, const fixnum_t*, uint8_t);

uint16_t fixnum_sub_fixnum(fixnum_t*, const fixnum_t*, uint8_t);

uint16_t fixnum_shl(fixnum_t*, uint8_t);

uint16_t fixnum_shl_in(fixnum_t*, uint8_t, uint16_t);

uint16_t fixnum_shr(fixnum_t*, uint8_t);

uint16_t fixnum_shr_in(fixnum_t*, uint8_t, uint16_t);

uint16_t fixnum_mul16(fixnum_t*, const fixnum_multiplier16_t*);

uint16_t fixnum_div(fixnum_t*, const fixnum_divisor_t*, fixnum_scratch_t*);

#endif /* SLIP0039_FIXNUM_H */
