/* fixnum.c - a constant time bignum implementation for base encoding 
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
#include <stdio.h>

#include "fixnum.h"
#include "cthelp.h"

void fixnum_init(fixnum_t *f, uint8_t *limbs, size_t no_limbs) {
	assert(f && no_limbs > 0 && limbs);
	f->no_limbs = no_limbs;
	f->limbs = limbs;
}

void fixnum_set_pattern(fixnum_t *f, fixnum_pattern_t pattern) {
	uint8_t tmp = 0x01;
	switch (pattern) {
		case PATTERN_ZERO:
			memset(f->limbs, 0, f->no_limbs);
			break;
		case PATTERN_MAX:
			memset(f->limbs, 0xff, f->no_limbs);
			break;
		case PATTERN_ADD11:
			for (size_t i = 0; i < f->no_limbs; i++) {
				f->limbs[i] = tmp;
				tmp += 0x22;
			}
	}
}

void fixnum_init_pattern(fixnum_t *f, uint8_t *limbs,
		size_t no_limbs, fixnum_pattern_t pattern) {
	fixnum_init(f, limbs, no_limbs);
	fixnum_set_pattern(f, pattern);
}

void fixnum_set_uint16(fixnum_t *f, uint16_t val) {
	fixnum_set_pattern(f, PATTERN_ZERO);
	f->limbs[f->no_limbs-1] = val&0xff;
	f->limbs[f->no_limbs-2] = val>>8;
}

void fixnum_init_uint16(fixnum_t *f, uint8_t *limbs, size_t no_limbs, uint16_t val) {
	assert(no_limbs >= 2);
	fixnum_init(f, limbs, no_limbs);
	fixnum_set_uint16(f, val);
}

void fixnum_set_fixnum(fixnum_t *dest, const fixnum_t *src) {
	assert(dest && src && dest->no_limbs == src->no_limbs);
	memcpy(dest->limbs, src->limbs, dest->no_limbs);
}

void fixnum_init_fixnum(fixnum_t *out, uint8_t *limbs, size_t no_limbs, const fixnum_t *in) {
	assert(out && in && in->no_limbs == no_limbs);
	fixnum_init(out, limbs, no_limbs);
	fixnum_set_fixnum(out, in);
}

void fixnum_scratch_init(fixnum_scratch_t *s, uint8_t *a, size_t no_a,
		uint8_t *b, size_t no_b) {
	assert(s && no_a == no_b && no_a >= 2);
	fixnum_init(&s->a, a, no_a);
	fixnum_init(&s->b, b, no_b);
}

uint16_t fixnum_shl(fixnum_t *f, uint8_t shift) {
	assert(f && f->no_limbs > 0 && shift <= 16);
	uint16_t carry = 0;

	if (shift >= 8) {
		carry = f->limbs[0];
		memmove(&f->limbs[0], &f->limbs[1], f->no_limbs - 1);
		f->limbs[f->no_limbs-1] = 0;
		shift -= 8;
	}

        uint8_t	mask = 0xff<<(8 - shift);

	carry <<= shift;
	carry |= (f->limbs[0]&mask)<<(8 - shift);
	f->limbs[0] <<= shift;

	for (size_t idx = 1; idx < f->no_limbs; idx++) {
		f->limbs[idx - 1] |= (f->limbs[idx]&mask)>>(8 - shift);
		f->limbs[idx] <<= shift;
	}

	return carry;
}

uint16_t fixnum_shl_in(fixnum_t *f, uint8_t shift, uint16_t in) {
	assert(in < 1<<shift);
	uint16_t carry = fixnum_shl(f, shift);
	assert(fixnum_peek(f, 0, shift) == 0);
	fixnum_poke(f, 0, shift, in);
	return carry;
}

uint16_t fixnum_shr(fixnum_t *f, uint8_t shift) {
	assert(f && f->no_limbs > 0 && shift <= 16);
	uint16_t carry = 0;

	if (shift >= 8) {
		carry = (f->limbs[f->no_limbs-1])<<8;
		memmove(&f->limbs[1], &f->limbs[0], f->no_limbs - 1);
		f->limbs[0] = 0;
		shift -= 8;
	}

	uint8_t mask = 0xff>>(8 - shift);

	carry >>= shift;
	carry |= (f->limbs[f->no_limbs-1]&mask)<<(16 - shift);
	f->limbs[f->no_limbs-1] >>= shift;

	for (size_t idx = f->no_limbs - 1; idx > 0; idx--) {
		f->limbs[idx] |= (f->limbs[idx-1]&mask)<<(8 - shift);
		f->limbs[idx-1] >>= shift;
	}
	
	return carry;
}

uint16_t fixnum_shr_in(fixnum_t *f, uint8_t shift, uint16_t in) {
	assert(in < 1<<shift);
	uint16_t carry = fixnum_shr(f, shift);
	assert(fixnum_peek(f, f->no_limbs*8 - shift, shift) == 0);
	fixnum_poke(f, (f->no_limbs<<3) - shift, shift, in);
	return carry;
}

void fixnum_factor_init(fixnum_factor_t *d, uint8_t *limbs, size_t no_limbs, uint16_t value) {
	assert(d && value);
	fixnum_init_uint16(&d->max_left_shift, limbs, no_limbs, value);
	d->value = value;
	d->log2 = 0;
	while (value >>= 1) d->log2++;
	d->max_left_shift.limbs[0] = d->max_left_shift.limbs[d->max_left_shift.no_limbs-2];
	if (no_limbs > 3) d->max_left_shift.limbs[d->max_left_shift.no_limbs-2] = 0;
	d->max_left_shift.limbs[1] = d->max_left_shift.limbs[d->max_left_shift.no_limbs-1];
	if (no_limbs > 2) d->max_left_shift.limbs[d->max_left_shift.no_limbs-1] = 0;
	fixnum_shl(&d->max_left_shift, 16 - d->log2 - 1);
	d->pure = cthelp_eq(d->value, 1<<d->log2);
}

uint32_t fixnum_peek(const fixnum_t *f, size_t offset, uint8_t size) {
	assert(f);
	if (offset + size > f->no_limbs<<3) {
		size -= offset + size - (f->no_limbs<<3);
	}
	assert(size <= 17); // size 17 is required for long division
	assert(offset + size <= (f->no_limbs<<3));

	//       01101101101100101100101011010110
	// byte  33333333222222221111111100000000
	// bit   76543210765432107654321076543210
	size_t offset_limb = f->no_limbs - 1 - (offset>>3);
	uint8_t offset_bit = offset%8;
	uint8_t ssize[3] = { };
	ssize[0] = 8 - offset_bit;
	if (ssize[0] >= size) ssize[0] = size;
	else {
		assert(offset_limb > 0);
		ssize[1] = size - ssize[0];
		if (ssize[1] > 8) {
			assert(offset_limb > 1);
			ssize[2] = ssize[1] - 8;
			ssize[1] = 8;
		}
	}
	assert(ssize[0] + ssize[1] + ssize[2] == size);

	//printf("size = %u, ssize[0] = %u, ssize[1] = %u, ssize[2] = %u, offset_bit=%u\n",
	//		size, ssize[0], ssize[1], ssize[2], offset_bit);

	uint32_t out = (f->limbs[offset_limb]>>offset_bit)&(0xff>>(8-ssize[0]));
	if (ssize[1]) {
		out |= (f->limbs[offset_limb-1]<<ssize[0])&(0xffff>>(16-ssize[0]-ssize[1]));
		if (ssize[2]) {
			out |= (f->limbs[offset_limb-2]<<(ssize[0]+ssize[1]))&(0xffff>>(16-size));
		}
	}
	
	return out;
}

void fixnum_poke(fixnum_t *f, size_t offset, uint8_t size, uint32_t in) {
	if (offset + size > f->no_limbs<<3) {
		size -= offset + size - (f->no_limbs<<3);
	}
	assert(offset + size <= (f->no_limbs<<3));
	assert(size <= 17); // use 17 as max, same as peek
	assert(in < 1<<size);

	size_t offset_limb = f->no_limbs - 1 - (offset>>3);
	uint8_t offset_bit = offset%8;
	uint8_t ssize[3] = { };
	uint8_t smask[3] = { };
	ssize[0] = 8 - offset_bit;
	smask[0] = (((1<<size) - 1))<<offset_bit;
	if (ssize[0] >= size) {
		ssize[0] = size;
	} else {
		assert(offset_limb > 0);
		ssize[1] = size - ssize[0];
		smask[1] = (1<<ssize[1]) - 1;
		if (ssize[1] > 8) {
			assert(offset_limb > 1);
			ssize[2] = ssize[1] - 8;
			ssize[1] = 8;
			smask[2] = (1<<ssize[2]) - 1;
		}
	}
	assert(ssize[0] + ssize[1] + ssize[2] == size);

	//printf("size = %u, ssize[0] = %u, ssize[1] = %u, ssize[2] = %u, offset_bit=%u, smask[0]=%u, smask[1]=%u, smask[2]=%u\n",
	//		size, ssize[0], ssize[1], ssize[2], offset_bit, smask[0], smask[1], smask[2]);

	f->limbs[offset_limb] &= ~smask[0];
	f->limbs[offset_limb] |= in<<offset_bit;
	f->limbs[offset_limb-1] &= ~smask[1];
	f->limbs[offset_limb-1] |= in>>(8-offset_bit);
	f->limbs[offset_limb-2] &= ~smask[2];
	f->limbs[offset_limb-2] |= in>>(16-offset_bit);
}

uint16_t fixnum_add_uint16(fixnum_t *f, uint16_t operand) {
	assert(f && f->no_limbs >= 2);
	uint16_t acc;
	uint8_t carry;
	size_t idx = f->no_limbs - 2;

	acc = f->limbs[f->no_limbs-1] + (operand&0xff);
	f->limbs[f->no_limbs-1] = acc&0xff;
	carry = acc>>8;

	acc = f->limbs[f->no_limbs-2] + (operand>>8) + carry;
	f->limbs[f->no_limbs-2] = acc&0xff;
	carry = acc>>8;

	while (idx-- > 0) {
		acc = f->limbs[idx] + carry;
		f->limbs[idx] = acc&0xff;
		carry = acc>>8;
	}

	return carry;
}

uint16_t fixnum_sub_fixnum(fixnum_t *f, const fixnum_t *s, uint8_t mask) {
	assert(f && s && f->no_limbs && s->no_limbs);
	uint16_t acc = 0;
	size_t idx = f->no_limbs;

	while (idx--) {
		acc = f->limbs[idx] - (s->limbs[idx]&mask) - acc;
		f->limbs[idx] = acc&0xff;
		acc = (acc>>8)&0x01;
	}

	return acc;
}

uint16_t fixnum_mul_factor(fixnum_t *f, const fixnum_factor_t *m) {
	assert(f && m && f->no_limbs >= 2 && f->no_limbs == m->max_left_shift.no_limbs);

	if (m->pure)
		return fixnum_shl(f, m->log2);

	uint8_t low = m->value&0xff, high = m->value>>8;
        uint16_t acc_low = 0, acc_high = 0;
	size_t idx = f->no_limbs;

	while (idx-- > 0) {
		acc_low += low*f->limbs[idx] + (acc_high&0xff);
		acc_high >>= 8;
		acc_high += high*f->limbs[idx];
		f->limbs[idx] = acc_low&0xff;
		acc_low >>= 8;
	}

	return acc_high + acc_low;
}

uint16_t fixnum_div_factor(fixnum_t *f, const fixnum_factor_t *d, fixnum_scratch_t *s) {
	assert(f && d && f->no_limbs == d->max_left_shift.no_limbs && f->no_limbs >= 2);

	// s->a is used as a shift register and s->b is brought to zero
	if (d->pure) 
		return fixnum_shr(f, d->log2);

	assert(s->a.no_limbs == f->no_limbs && s->b.no_limbs == f->no_limbs);

	fixnum_set_fixnum(&s->b, f);
	fixnum_set_pattern(f, PATTERN_ZERO);
	fixnum_set_fixnum(&s->a, &d->max_left_shift);
	size_t bit = (f->no_limbs<<3) - d->log2;
	uint32_t test;
	uint16_t ret;

	while (bit-- > 0) {
		fixnum_shl(f, 1);
		test = (fixnum_peek(&s->b, bit, d->log2 + 2) - d->value)>>31;
		fixnum_add_uint16(f, 1 - test);
		fixnum_sub_fixnum(&s->b, &s->a, 0xff+test);
		fixnum_shr(&s->a, 1);
	}

	ret = s->b.limbs[s->b.no_limbs-1] + (s->b.limbs[s->b.no_limbs-2]<<8);

	s->b.limbs[s->b.no_limbs-1] = s->b.limbs[s->b.no_limbs-2] = 0;

	return ret;
}
