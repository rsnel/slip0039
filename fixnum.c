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
	assert(f && f->no_limbs > 0 && shift < 16);
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
	assert(f && f->no_limbs > 0 && shift < 16);
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
	d->max_left_shift.limbs[d->max_left_shift.no_limbs-2] = 0;
	d->max_left_shift.limbs[1] = d->max_left_shift.limbs[d->max_left_shift.no_limbs-1];
	d->max_left_shift.limbs[d->max_left_shift.no_limbs-1] = 0;
	fixnum_shl(&d->max_left_shift, 16 - d->log2 - 1);
	d->pure = (d->value == 1<<d->log2);
}

void fixnum_factor_show(const fixnum_factor_t *d, const char *name) {
	printf("value=%04x log2=%d pure=%d ", d->value, d->log2, d->pure);
	fixnum_show(&d->max_left_shift, "mls");
}

#if 0
uint16_t fixnum_peek(fixnum_t *f, size_t offset, uint8_t size) {
	//      |<  limbs[30]   |<  limbs[31]   |
	// 00011001101010101101001011010101010101
	//                              |       ^
	//                              |    offset 0
	// so fixnum_peek(f, 8, 3) gives|
	//                            101
	assert(size <= 16);
	assert(offset + size <= NO_LIMBS<<4);
	printf("offset=%ld, size=%d\n", offset, size);
	size_t limb = NO_LIMBS - (offset>>4) - 1;
	printf("limb=%ld\n", limb);
	uint32_t tmp = f->limbs[limb];
	if (limb > 0) tmp |= (f->limbs[limb-1])<<16;
	printf("tmp=%08x\n", tmp);
	printf("tmp>>(offset&0xf)=%08x\n", tmp>>(offset&0xf));
	printf("mask %08x\n", 0xffffffff>>(32-size));
	return (tmp>>(offset&0xf))&(0xffffffff>>(32 - size));
}

uint16_t fixnum_add_uint16(fixnum_t *f, uint16_t operand) {
	uint32_t acc;
	uint16_t carry = operand;
	size_t idx = NO_LIMBS;

	while (idx-- > 0) {
		acc = f->limbs[idx] + carry;
		f->limbs[idx] = acc&0xffff;
		carry = acc>>16;
	}

	return carry;
}

uint16_t fixnum_mul(fixnum_t *f, const fixnum_factor_t *m) {
	uint32_t acc;
	uint16_t carry = 0;
	size_t idx = NO_LIMBS;

	if (m->pure)
		return fixnum_shl(f, m->log2);

	while (idx-- > 0) {
		acc = f->limbs[idx]*m->value;
		acc += carry;
		f->limbs[idx] = acc&0xffff;
		carry = acc>>16;
	}

	return carry;
}

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
