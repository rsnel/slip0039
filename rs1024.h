/* rs1024.h - interface to the checksum specified in SLIP-0039
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
#ifndef SLIP0039_RS1024_H
#define SLIP0039_RS1024_H
#include <stdint.h>
#include <stddef.h>

typedef struct rs1024_state_s {
	uint32_t chk;
	size_t count;
} rs1024_state_t;

#define	RS1024_INIT { .chk = 1, .count = 0 }

// call this function before using the other (non-init) methods
void rs1024_init(rs1024_state_t*);

// initialize state of the checksum with
// customization string "shamir"
void rs1024_init_slip0039(rs1024_state_t*);

// add single uint16_t to checksum
void rs1024_add_value(rs1024_state_t*, uint16_t);

// add array of uint16_t checksum
void rs1024_add_array(rs1024_state_t*, uint16_t*, size_t);

// compute checksum of all added uint16_t's
// use this function to compute the last
// three words, the pointer uint16_t* must have room
// for at least three elements
void rs1024_checksum(rs1024_state_t*, uint16_t*);

#endif /* SLIP0039_RS1024_H */
