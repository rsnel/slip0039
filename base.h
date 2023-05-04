/* base.h - base encoding and decoding
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
#ifndef SLIP0039_BASE_H
#define SLIP0039_BASE_H

#include <stdint.h>

#include "fixnum.h"

typedef struct base_scratch_s {
	fixnum_scratch_t s;
	uint8_t *divisor_limbs, *data_limbs;
	size_t max_limbs;
} base_scratch_t;

void base_init_scratch(base_scratch_t*, uint8_t*, size_t);

void base_encode_buffer(uint16_t*, size_t, const fixnum_multiplier16_t*,
		const uint8_t*, size_t, base_scratch_t*);

void base_encode_fixnum(uint16_t*, size_t, const fixnum_multiplier16_t*,
		const fixnum_t*, base_scratch_t*);

int base_decode_buffer(uint8_t*, size_t, const fixnum_multiplier16_t*,
		const uint16_t*, size_t);

int base_decode_fixnum(fixnum_t*, const fixnum_multiplier16_t*,
		const uint16_t*, size_t);

#endif /* SLIP0039_BASE_H */
