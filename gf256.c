/* gf256.c - implementation of arithmetic operations in gf(256)
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
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

// GF(256) artithmetic is nicely explained in
// https://www.cs.utsa.edu/~wagner/laws/FFM.html
#include "gf256.h"

// our polynomial is x^8 + x^4 + x^3 + x + 1 = 0x11b
// the 8th bit is implied
#define GF256_POL 0x1b

uint8_t gf256_add(uint8_t a, uint8_t b) {
	return a^b;
}

uint8_t gf256_mul(uint8_t a, uint8_t b) {
	uint8_t res = 0;
	int i = 7;

	goto entry;

	while (i--) {
		/* multiplying elements of gf256
		 * needs two conditional xors per bit,
		 * since we do not like conditionals
		 * in constant-time code, we use the
		 * same trick as in rs1024.c */

		/* xor a<<1 with POL if highest
		 * bit of a is set */
		a = (a<<1)^((-((a>>7)&1))&GF256_POL);
		b >>= 1;

entry:
		/* add a to res if last
		 * bit of b is 1 */
		res ^= (-(b&1))&a;
	}

	return res;
}

uint8_t gf256_pow(uint8_t a, int n) {
	uint8_t res = 1;
	for (int i = 0; i < n; i++) res = gf256_mul(res, a);
	return res;
}

uint8_t gf256_inv(uint8_t a) {
	assert(a);
	return gf256_pow(a, 254);
}

uint8_t gf256_div(uint8_t a, uint8_t b) {
	return gf256_mul(a, gf256_inv(b));
}

