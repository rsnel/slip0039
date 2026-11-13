/* lagrange.c - implementation of Lagrange interpolation
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
#include "lagrange.h"
#include "gf256.h"

static void lagrange_byte(slip0039_set_t *s, int no_idx,
		uint8_t *idx, uint8_t x, size_t offset, uint8_t *out) {
	// x-coordinates 254 and 255 are the digest and the secret,
	// SLIP0039_SLOT() maps every x-coordinate to its slot
	uint8_t sum = 0;
	for (int i = 0; i < no_idx; i++) {
		assert(s->slots[SLIP0039_SLOT(idx[i])]);
		uint8_t prod = s->slots[SLIP0039_SLOT(idx[i])][offset];
		for (int j = 0; j < no_idx; j++) {
			if (i == j) continue;

			prod = gf256_mul(prod,
					gf256_div(gf256_add(x, idx[j]),
						gf256_add(idx[i], idx[j])));
		}
		sum = gf256_add(sum, prod);
	}
	out[offset] = sum;
}

/* the value at x of the polynomial through the no_idx shares with the
 * x-coordinates in idx, stored in out */
void lagrange(slip0039_set_t *s, size_t n,
		int no_idx, uint8_t *idx, uint8_t x, uint8_t *out) {
	for (size_t i = 0; i < n; i++)
		lagrange_byte(s, no_idx, idx, x, i, out);
}
