/* base1024.h - interface to functions to handle base1024 data
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
#ifndef SLIP0039_BASE1024_H
#define SLIP0039_BASE1024_H

#include <stdint.h>
#include "slip0039.h"
#include "config.h"

#if BITS_PER_WORD != 10
#error "constant BITS_PER_WORD must be 10"
#endif

typedef struct base1024_s {
	uint16_t words[WORDS];
	int no_words;
	int bit_idx, word_idx;
} base1024_t;

void base1024_to_string(base1024_t*, slip0039_mnemonic_t);

void base1024_empty(base1024_t*);

void base1024_rewind_and_truncate(base1024_t*, unsigned int);

void base1024_from_string(base1024_t*, const slip0039_mnemonic_t, int);

void base1024_verify_checksum(base1024_t*, int);

void base1024_append_checksum(base1024_t*);

void base1024_print(base1024_t*);

unsigned int base1024_read_bits(base1024_t*, unsigned int);

void base1024_write_bits(base1024_t*, unsigned int, unsigned int);

#endif /* SLIP0039_BASE1024_H */
