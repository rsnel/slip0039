/* honey.c - honey encryption
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

#include "honey.h"

/* number of bits the seed must have on top of log2(j), so that the
 * modular DTE gives a guesser a factor of at most 1 + gain, for any j
 *
 * with R = floor(N/j) the worst case factor is N/(j*R) < 1 + 1/R and
 * R >= N/j - 1, so N/j >= 1/gain + 1 suffices */
int honey_extra_bits(double gain) {
	assert(gain >= 1.0/(1ULL<<62));
	int bits = 0;
	while ((double)(1ULL<<bits) < 1/gain + 1) bits++;
	return bits;
}
