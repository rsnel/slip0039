/* fixnum.c - a constant time bignum implementation for positive integers
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
#include <string.h>

#include "fixnum.h"

void fixnum_init_uint16(fixnum_t *f, uint16_t *limbs, size_t no_limbs, uint16_t val) {
	assert(f && limbs && no_limbs > 0);
	limbs[no_limbs-1] = val;
	memset(limbs, 0, sizeof(uint16_t)*(no_limbs - 1));
	f->limbs = limbs;
	f->no_limbs = no_limbs;
}

uint16_t fixnum_add_uint16(fixnum_t *f, uint16_t operand) {
	uint32_t acc;
	size_t idx = f->no_limbs;

	while (--idx >= 0) {
		acc = f->limbs[idx] + operand;
		f->limbs[idx] = acc&0xffff;
		operand = acc>>16;
	}

	return operand;
}

uint16_t fixnum_mul_uint16(fixnum_t *f, uint16_t operand) {
	uint32_t acc;
	uint16_t carry = 0;
	size_t idx = f->no_limbs;

	while (--idx >= 0) {
		acc = f->limbs[idx]*operand;
		acc += carry;
		f->limbs[idx] = acc&0xffff;
		carry = acc>>16;
	}

	return carry;
}


