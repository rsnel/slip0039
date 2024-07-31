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
#include "utils.h"

void fixnum_init(fixnum_t *f, uint8_t *limbs, size_t no_limbs) {
	assert(f && no_limbs > 0 && limbs);
	f->no_limbs = no_limbs;
	f->limbs = limbs;
}

void fixnum_set_buffer(fixnum_t *f, const uint8_t *buffer, size_t buffer_size) {
	assert(buffer_size <= f->no_limbs);
	for (size_t i = 0; i < f->no_limbs - buffer_size; i++) f->limbs[i] = 0;
	memcpy(f->limbs + (f->no_limbs - buffer_size), buffer, buffer_size);
}

void fixnum_init_buffer(fixnum_t *f, uint8_t *limbs, size_t no_limbs,
		const uint8_t *buffer, size_t buffer_size) {
	fixnum_init(f, limbs, no_limbs);
	fixnum_set_buffer(f, buffer, buffer_size);
}

void fixnum_printf(const fixnum_t *f) {
        char c[2];
        for (int nibble = (f->no_limbs<<1) - 1; nibble >= 0; nibble--) {
                memset(c, 0, sizeof(c));
                wordlist_dereference(&wordlist_base16, c, sizeof(c), fixnum_peek(f, nibble<<2, 4));
                putchar(c[0]);
        }
}

void fixnum_show(const fixnum_t *f, const char *name) {
        printf("%s: ", name);
        fixnum_printf(f);
        printf("\n");
}

void fixnum_divisor_show(const fixnum_divisor_t *d, const char *name) {
        printf("log2=%d pure=%d ", d->p.log2, d->p.pure);
        fixnum_show(&d->max_left_shift, "mls");
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
				tmp += 0x11;
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
	assert(dest && src && dest->no_limbs >= src->no_limbs);
	fixnum_set_buffer(dest, src->limbs, src->no_limbs);
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
	uint8_t origshift = shift;
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

	return carry>>(16-origshift);
}

uint16_t fixnum_shr_in(fixnum_t *f, uint8_t shift, uint16_t in) {
	assert(in < 1<<shift);
	uint16_t carry = fixnum_shr(f, shift);
	assert(fixnum_peek(f, f->no_limbs*8 - shift, shift) == 0);
	fixnum_poke(f, (f->no_limbs<<3) - shift, shift, in);
	return carry;
}

void fixnum_multiplier16_init(fixnum_multiplier16_t *m, uint16_t value) {
	assert(m && value);
	m->value = value;
	m->p.log2 = 0;
	while (value >>= 1) m->p.log2++;
	m->p.pure = cthelp_eq(m->value, 1<<m->p.log2);
}

void fixnum_divisor_init_from_multiplier16(fixnum_divisor_t *d, const fixnum_multiplier16_t *m, uint8_t *limbs, size_t no_limbs) {
	assert(d && m && limbs && no_limbs > 1 && m->value > 1);
	d->p = m->p;
	fixnum_init_uint16(&d->max_left_shift, limbs, no_limbs, m->value);
	d->max_left_shift.limbs[0] = d->max_left_shift.limbs[d->max_left_shift.no_limbs-2];
	if (no_limbs > 3) d->max_left_shift.limbs[d->max_left_shift.no_limbs-2] = 0;
	d->max_left_shift.limbs[1] = d->max_left_shift.limbs[d->max_left_shift.no_limbs-1];
	if (no_limbs > 2) d->max_left_shift.limbs[d->max_left_shift.no_limbs-1] = 0;
	fixnum_shl(&d->max_left_shift, 16 - m->p.log2 - 1);
}

// a nice implementation of John Bollinger: https://stackoverflow.com/a/51388846
static uint16_t popcnt_helper(uint8_t n) {
        n = (n&0x55) + ((n>>1)&0x55);
        n = (n&0x33) + ((n>>2)&0x33);
        n = (n&0x0f) + ((n>>4)&0x0f);
        return n;
}

uint16_t fixnum_popcnt(const fixnum_t *f) {
	assert(f && f->limbs && f->no_limbs > 0);

	uint16_t n;

	for (int i = 0; i < f->no_limbs; i++) {
		n += popcnt_helper(f->limbs[i]);
	}

	return n;
}

void fixnum_divisor_init_from_fixnum(fixnum_divisor_t *d, const fixnum_t *in, uint8_t *limbs, size_t no_limbs) {
	assert(d && in && limbs && no_limbs > 1);
	uint16_t popcnt = fixnum_popcnt(in);

	// we dont want the divisor to be 0
	assert(popcnt > 0);
	d->p.pure = (popcnt == 1);
	fixnum_init_fixnum(&d->max_left_shift, limbs, no_limbs, in);

	fixnum_set_fixnum(&d->max_left_shift, in);

	uint16_t msb = d->p.log2 = 8*no_limbs - 1;

	// now check if the last bit is 1 and shift left until it is, we calculate log2
	// and compute the max left shifted value
	while (!fixnum_peek(&d->max_left_shift, msb, 1)) {
		d->p.log2--;
		fixnum_shl(&d->max_left_shift, 1);
	}

	// we want the divisor to be at least 2
	assert(d->p.log2);
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

uint16_t fixnum_sub_uint16(fixnum_t *f, uint16_t operand) {
	assert(f && f->no_limbs >= 2);
	uint16_t acc;
	uint8_t carry;
	size_t idx = f->no_limbs - 2;

	acc = f->limbs[f->no_limbs-1] - (operand&0xff);
	f->limbs[f->no_limbs-1] = acc&0xff;
	carry = acc>>15;

	acc = f->limbs[f->no_limbs-2] - (operand>>8) - carry;
	f->limbs[f->no_limbs-2] = acc&0xff;
	carry = acc>>15;

	while (idx-- > 0) {
		acc = f->limbs[idx] - carry;
		f->limbs[idx] = acc&0xff;
		carry = acc>>15;
	}

	return carry;
}

uint16_t fixnum_add_fixnum(fixnum_t *f, const fixnum_t *s, uint8_t mask) {
	assert(f && s && f->no_limbs > 1 && f->no_limbs == s->no_limbs);
	uint16_t acc = 0;
	size_t idx = f->no_limbs;

	while (idx--) {
		acc = f->limbs[idx] + (s->limbs[idx]&mask) + acc;
		f->limbs[idx] = acc&0xff;
		acc >>= 8;
		assert(acc == 0 || acc == 1);
	}

	return acc;
}

uint16_t fixnum_sub_fixnum(fixnum_t *f, const fixnum_t *s, uint8_t mask) {
	assert(f && s && f->no_limbs > 1 && f->no_limbs == s->no_limbs);
	uint16_t acc = 0;
	size_t idx = f->no_limbs;

	while (idx--) {
		acc = f->limbs[idx] - (s->limbs[idx]&mask) - acc;
		f->limbs[idx] = acc&0xff;
		acc = (acc>>8)&0x01;
	}

	return acc;
}

uint16_t fixnum_mul16(fixnum_t *f, const fixnum_multiplier16_t *m) {
	assert(f && m && f->no_limbs >= 2);

	if (m->p.pure)
		return fixnum_shl(f, m->p.log2);

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

uint16_t fixnum_div(fixnum_t *f, const fixnum_divisor_t *d, fixnum_scratch_t *s, int dividendmaxplus1) {
	assert(f && d && f->no_limbs == d->max_left_shift.no_limbs && f->no_limbs >= 2);
	assert(dividendmaxplus1 == 0 || dividendmaxplus1 == 1);

	for (int i = 0; i < f->no_limbs; i++)
		f->limbs[i] &= -(1 - dividendmaxplus1);

	// s->a is used as a shift register and s->b is brought to zero
	if (d->p.pure)
		return fixnum_shr_in(f, d->p.log2, dividendmaxplus1);

	assert(s->a.no_limbs >= f->no_limbs && s->b.no_limbs >= f->no_limbs);

	//printf("f->no_limbs=%ld\n", f->no_limbs);
	fixnum_set_fixnum(&s->b, f);
	if (s->b.no_limbs > f->no_limbs && dividendmaxplus1) s->b.limbs[s->b.no_limbs - f->no_limbs - 1] = 1;
	//fixnum_show(&s->b, "starttest");

	fixnum_set_pattern(f, PATTERN_ZERO);
	fixnum_set_fixnum(&s->a, &d->max_left_shift);
	size_t bit = (f->no_limbs<<3) - d->p.log2;
	uint32_t test;
	uint16_t ret;

	while (bit-- > 0) {
		fixnum_shl(f, 1);
		test = fixnum_sub_fixnum(&s->b, &s->a, 0xff)&(1 - dividendmaxplus1);
		//fixnum_show(&s->b, "test");
		fixnum_add_uint16(f, 1 - test);
		fixnum_add_fixnum(&s->b, &s->a, -test);
		fixnum_shr(&s->a, 1);
		//fixnum_show(&s->a, "remove");
		//fixnum_show(f, "quotient");
		dividendmaxplus1 = 0;
	}

	ret = s->b.limbs[s->b.no_limbs-1] + (s->b.limbs[s->b.no_limbs-2]<<8);

	s->b.limbs[s->b.no_limbs-1] = s->b.limbs[s->b.no_limbs-2] = 0;

	return ret;
}

uint16_t fixnum_calc_log2(const fixnum_t *f) {
	int bits = f->no_limbs*8;
	uint16_t log2 = 0xffff;
	for (int i = 0; i < bits; i++) {
		if (fixnum_peek(f, i, 1)) log2 = i;
	}
	assert(log2 != 0xffff);
	return log2;
}

