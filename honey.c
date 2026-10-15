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
#include <string.h>

#include "honey.h"
#include "verbose.h"

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

/* the modular DTE (distribution transforming encoder)
 *
 * a message k with 0 <= k < j is encoded as a seed x = k + j*r with
 * 0 <= x < 2^n, where r is uniform over all values for which x < 2^n;
 * decoding is x mod j; every seed decodes to a message, and with
 * 2^n = j*R + t (0 <= t < j) the messages k < t own R + 1 seeds and the
 * others own R seeds
 *
 * all fixnums have the same number of limbs L, and n <= 8*L
 *
 * the running time depends on j, n and L, but not on k or r: the
 * divisions are by j, R and R + 1, which are public, and r is selected
 * from r0 = u mod R and r1 = u mod (R + 1) without branching */

/* compute R and t, with 2^n = j*R + t, R in q, t in t */
static void honey_split_range(fixnum_t *q, fixnum_t *t, const fixnum_t *j,
		uint16_t n, uint8_t *dl, fixnum_scratch_t *s) {
	fixnum_divisor_t d;
	size_t L = q->no_limbs;
	int max_plus_1 = (n == L<<3);

	fixnum_set_pattern(q, FIXNUM_PATTERN_ZERO);
	if (!max_plus_1) fixnum_poke(q, n, 1, 1);

	fixnum_divisor_init_from_fixnum(&d, j, dl, L);
	fixnum_div(q, &d, s, max_plus_1);
	fixnum_set_fixnum(t, &s->b);
}

/* x = k + j*r, with r (nearly) uniform on { r : k + j*r < 2^n }
 *
 * - k < j, 2 <= j < 2^(n-1), so every k has at least two choices for r
 * - random points to L bytes of fresh output of a CSPRNG; they must not
 *   be derived from the passphrase or from k, and should be discarded
 *   after use; r is computed as u mod R or u mod (R + 1), with u these
 *   8*L random bits, so the bias in r is at most about 2^(n - 8*L)/j
 * - scratch points to HONEY_SCRATCH_SIZE(L) bytes */
void honey_encode(fixnum_t *x, const fixnum_t *k, const fixnum_t *j,
		uint16_t n, const uint8_t *random, uint8_t *scratch) {
	size_t L = x->no_limbs;
	assert(x && k && j && random && scratch);
	assert(k->no_limbs == L && j->no_limbs == L && L >= 2);
	assert(n >= 2 && n <= L<<3);

	fixnum_t q, q1, t, u, r0, r1, tmp;
	fixnum_divisor_t d0, d1;
	fixnum_scratch_t s;
	fixnum_init(&q, scratch, L);
	fixnum_init(&q1, scratch + L, L);
	fixnum_init(&t, scratch + 2*L, L);
	fixnum_init(&u, scratch + 3*L, L);
	fixnum_init(&r0, scratch + 4*L, L);
	fixnum_init(&r1, scratch + 5*L, L);
	fixnum_init(&tmp, scratch + 6*L, L);
	uint8_t *dl0 = scratch + 7*L, *dl1 = scratch + 8*L;
	fixnum_scratch_init(&s, scratch + 9*L, L, scratch + 10*L, L);

	/* j is public, so these checks need not be constant time */
	assert(fixnum_calc_log2(j) < n - 1);
	fixnum_set_fixnum(&tmp, k);
	assert(fixnum_sub_fixnum(&tmp, j, 0xff)); // k < j

	honey_split_range(&q, &t, j, n, dl0, &s);
	fixnum_set_fixnum(&q1, &q);
	if (fixnum_add_uint16(&q1, 1)) BUG("R + 1 overflows");

	/* r0 = u mod R, r1 = u mod (R + 1) */
	fixnum_init_buffer(&u, u.limbs, L, random, L);
	fixnum_divisor_init_from_fixnum(&d0, &q, dl0, L);
	fixnum_set_fixnum(&tmp, &u);
	fixnum_div(&tmp, &d0, &s, 0);
	fixnum_set_fixnum(&r0, &s.b);
	fixnum_divisor_init_from_fixnum(&d1, &q1, dl1, L);
	fixnum_set_fixnum(&tmp, &u);
	fixnum_div(&tmp, &d1, &s, 0);
	fixnum_set_fixnum(&r1, &s.b);

	/* k owns R + 1 seeds if k < t, select r1 then, r0 otherwise */
	fixnum_set_fixnum(&tmp, k);
	uint8_t mask = -(uint8_t)fixnum_sub_fixnum(&tmp, &t, 0xff);
	for (size_t i = 0; i < L; i++)
		r0.limbs[i] = (r1.limbs[i]&mask)|(r0.limbs[i]&~mask);

	/* x = j*r by shift-and-add, the same steps for every r; this
	 * cannot overflow, since k + j*r < 2^n */
	fixnum_set_pattern(x, FIXNUM_PATTERN_ZERO);
	for (size_t bit = L<<3; bit-- > 0; ) {
		fixnum_shl(x, 1);
		fixnum_add_fixnum(x, j, -(uint8_t)fixnum_peek(&r0, bit, 1));
	}

	/* x = k + j*r */
	fixnum_add_fixnum(x, k, 0xff);
}

/* k = x mod j, scratch points to HONEY_SCRATCH_SIZE(L) bytes */
void honey_decode(fixnum_t *k, const fixnum_t *x, const fixnum_t *j,
		uint8_t *scratch) {
	size_t L = k->no_limbs;
	assert(k && x && j && scratch);
	assert(x->no_limbs == L && j->no_limbs == L && L >= 2);

	fixnum_t q;
	fixnum_divisor_t d;
	fixnum_scratch_t s;
	fixnum_init(&q, scratch, L);
	fixnum_scratch_init(&s, scratch + L, L, scratch + 2*L, L);

	fixnum_set_fixnum(&q, x);
	fixnum_divisor_init_from_fixnum(&d, j, scratch + 3*L, L);
	fixnum_div(&q, &d, &s, 0);
	fixnum_set_fixnum(k, &s.b);
}
