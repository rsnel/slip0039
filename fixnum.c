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

void fixnum_init(fixnum_t *f, uint8_t *limbs, size_t no_limbs) {
	assert(f && no_limbs > 0 && limbs);
	f->no_limbs = no_limbs;
	f->limbs = limbs;
}

void fixnum_init_pattern(fixnum_t *f, uint8_t *limbs,
		size_t no_limbs, fixnum_pattern_t pattern) {
	fixnum_init(f, limbs, no_limbs);
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

void fixnum_init_uint16(fixnum_t *f, uint8_t *limbs, size_t no_limbs, uint16_t val) {
	assert(no_limbs >= 2);
	fixnum_init(f, limbs, no_limbs);
	f->limbs[f->no_limbs-1] = val&0xff;
	f->limbs[f->no_limbs-2] = val>>8;
	memset(f->limbs, 0, sizeof(uint8_t)*(f->no_limbs - 2));
}

void fixnum_init_fixnum(fixnum_t *out, uint8_t *limbs, size_t no_limbs, const fixnum_t *in) {
	assert(in && in->no_limbs == no_limbs);
	assert(out && in && out->no_limbs == in->no_limbs);
	fixnum_init(out, limbs, no_limbs);
	memcpy(out->limbs, in->limbs, out->no_limbs);
}

void fixnum_show(const fixnum_t *f, const char *name) {
	printf("%s: ", name);
	for (size_t i = 0; i < f->no_limbs; i++) {
		printf("%02x", f->limbs[i]);
	}
	printf("\n");
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
	d->pure = (d->value == 1<<d->log2);
}

void fixnum_factor_show(const fixnum_factor_t *d, const char *name) {
	printf("value=%04x log2=%d pure=%d ", d->value, d->log2, d->pure);
	fixnum_show(&d->max_left_shift, "mls");
}

uint16_t fixnum_peek(fixnum_t *f, size_t offset, uint8_t size) {
	assert(size <= 16);
	assert(f && offset + size <= (f->no_limbs<<3));
	uint16_t out = 0;
	//       01101101101100101100101011010110
	// byte  33333333222222221111111100000000
	// bit   76543210765432107654321076543210
	size_t offset_limb = f->no_limbs - 1 - (offset>>3);
	uint8_t offset_bit = offset%8;
	uint8_t ssize[3] = { };
	ssize[0] = 8 - offset_bit;
	if (ssize[0] > size) ssize[0] = size;
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

	printf("size = %u, ssize[0] = %u, ssize[1] = %u, ssize[2] = %u, offset_bit=%u\n",
			size, ssize[0], ssize[1], ssize[2], offset_bit);

	out = (f->limbs[offset_limb]>>offset_bit)&(0xff>>(8-ssize[0]));
	if (ssize[1]) {
		out |= (f->limbs[offset_limb-1]<<ssize[0])&(0xffff>>(16-ssize[0]-ssize[1]));
		if (ssize[2]) {
			out |= (f->limbs[offset_limb-2]<<(ssize[0]+ssize[1]))&(0xffff>>(16-size));
		}
	}
	
	return out;
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

uint16_t fixnum_mul(fixnum_t *f, const fixnum_factor_t *m) {
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

#if 0
uint16_t fixnum_div(fixnum_t *f, const fixnum_factor_t *d) {
	fixnum_t shiftreg, quotient = { };

	if (d->pure) 
		return fixnum_shr(f, d->log2);

	fixnum_set_fixnum(&shiftreg, &d->max_left_shift);
	fixnum_show(&quotient, "q");

	for (size_t i = (NO_LIMBS<<4) - d->log2; i >= 0; i--) {
		printf("here! %ld\n", i);
		uint32_t check = fixnum_peek(f, i, d->log2);
		printf("check %08x\n", check - d->value);
	}
	return 0;
}
#endif
