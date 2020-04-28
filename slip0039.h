/* slip0039.h - global data definititions used in the main program
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
#ifndef SLIP0039_H
#define SLIP0039_H
#include <stdint.h>
#include <stddef.h>
#include "config.h"
#include "lrcipher.h"

typedef struct slip0039_set_s {
	struct slip0039_set_s *parent;
	struct slip0039_set_s *children[MAX_SHARES];
	int line_numbers[MAX_SHARES];
	char names[MAX_SHARES][23];

	/* we allow for an undefined value for the number  
	 * of members, because the total amount of members
	 * in a group cannot be determined from the input  */
	uint8_t count;       /* total members (0x00=undef) */
	uint8_t available;   /* available members          */
        uint8_t threshold;   /* required members           */
	
	/* x-coordinate is (uint8_t) cast of index         */
	uint8_t *digest;     /* index -2 (=(int8_t)254)    */
	uint8_t *secret;     /* index -1 (=(int8_t)255)    */
	uint8_t *shares[MAX_SHARES]; /* 0 <= index < 16            */

	/* static storage for shares, digest and secret   
	 * this storage can be addressed in the same way 
	 * as the pointers above                           */
	uint8_t storage_digest[BLOCKS<<1];
	uint8_t storage_shares[MAX_SHARES][BLOCKS<<1];
} slip0039_set_t;

typedef struct slip0039_s {
        size_t n;    /* size of secret in bytes */
        int16_t id;  /* Identifier        15bit */
        int8_t e;    /* Iteration exponent 5bit */

	slip0039_set_t root, members[MAX_SHARES];

	uint8_t *plaintext;
	uint8_t storage_secret[BLOCKS<<1], storage_plaintext[BLOCKS<<1];

	// cipher state is initialized with the passphrase
	lrcipher_t l;

	// the title consists of the first two words (which
	// should be the same in all mnemonics in the input)
	// with some formatting, so that the function that
	// displays this struct can be simplified
	char title[22]; // first two words
} slip0039_t;

typedef char slip0039_mnemonic_t[LINE];

typedef enum slip0039_mode_e {
	SLIP0039_MODE_NULL,
	SLIP0039_MODE_RECOVER,
	SLIP0039_MODE_SPLIT
} slip0039_mode_t;

typedef enum slip0039_parse_state_e {
	SLIP0039_PARSE_STATE_SEED,
	SLIP0039_PARSE_STATE_EXP,
	SLIP0039_PARSE_STATE_GT,
	SLIP0039_PARSE_STATE_XOFY
} slip0039_parse_state_t;

#endif /* SLIP0039_RS1024_H */
