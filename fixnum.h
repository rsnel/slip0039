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

/* we work in a context where our binary data is processed in chunks
 * of 16 bits, so we represent our integers as arrays of uint16_t's */

typedef struct fixnum_s {
	uint16_t *limbs; /* limbs stored in big endian order */
	size_t no_limbs;
} fixnum_t;

void fixnum_init_uint16(fixnum_t*, uint16_t*, size_t, uint16_t);

uint16_t fixnum_add_uint16(fixnum_t*, uint16_t);

uint16_t fixnum_mul_uint16(fixnum_t*, uint16_t);

#endif /* SLIP0039_FIXNUM_H */
