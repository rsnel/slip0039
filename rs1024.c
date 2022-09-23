/* rs1024.c - implementation of the checksum specified in SLIP-0039
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
#include "rs1024.h"
#include "utils.h"

static void invalidate_rs1024(rs1024_state_t *state) {
	state->count = (size_t)-1;
}

static void check_rs1024(rs1024_state_t *state) {
	assert(state->count != (size_t)-1);
}

void rs1024_init(rs1024_state_t *state) {
	rs1024_state_t s = RS1024_INIT;
	*state = s;
}

void rs1024_init_slip0039(rs1024_state_t *state) {
	/* customization string as specified bij SLIP-0039 */
	uint16_t cs[] = { 's', 'h', 'a', 'm', 'i', 'r' };

	rs1024_init(state);
	rs1024_add_array(state, cs, sizeof_array(cs));
}

void rs1024_add_value(rs1024_state_t *state, uint16_t value) {
	uint32_t gen[] = {
		0x00e0e040, 0x01c1c080, 0x03838100, 0x07070200, 0x0e0e0009,
		0x1c0c2412, 0x38086c24, 0x3090fc48, 0x21b1f890, 0x03f3f120
	};
	uint32_t b = state->chk>>20;

	check_rs1024(state);
	state->count++;

	state->chk = ((state->chk&0xfffff)<<10)^value;

	for (int i = 0; i < sizeof_array(gen); i++) {
		/* constant time version of: if ((b>>i)&1) chk ^= gen[i]; */
		state->chk ^= gen[i]&(-((b>>i)&1));
	}
}

void rs1024_add_array(rs1024_state_t *state,
		const uint16_t *data, size_t data_size) {
	for (int i = 0; i < data_size; i++)
		rs1024_add_value(state, data[i]);
}

void rs1024_checksum(rs1024_state_t *state, uint16_t *out) {
	uint16_t zeroes[3] = { 0, 0, 0 };
	rs1024_add_array(state, zeroes, sizeof_array(zeroes));

	invalidate_rs1024(state);

	state->chk ^= 1;

	for (int i = 0; i < 3; i++)
		out[i] = (state->chk>>10*(2-i))&0x3FF;
}

bool rs1024_verify(const uint16_t *input, size_t no_input) {
        rs1024_state_t ok = RS1024_INIT, s;

        rs1024_init_slip0039(&s);
        rs1024_add_array(&s, input, no_input);

        return ok.chk == s.chk;
}

void rs1024_add(uint16_t *input, size_t no_input) {
	        rs1024_state_t s;
        rs1024_init_slip0039(&s);
        rs1024_add_array(&s, input, no_input);
        rs1024_checksum(&s, input + no_input);
}
