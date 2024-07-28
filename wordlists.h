/* wordlist.h - declaration of wordlist array
 *
 * Copyright 2020 Rik Snel <rik@snel.it>
 *
 * This file is part of slip0039
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
#ifndef SLIP0039_WORDLISTS_H
#define SLIP0039_WORDLISTS_H

#include <stdlib.h>
#include <stdint.h>

#include "fixnum.h"
#include "shashtbl.h"

typedef struct wordlist_s {
	shashtbl_elt_t elt;
	const char *family;
	fixnum_multiplier16_t m;
	uint8_t	max_word_length, min_word_length;
	char **words;
} wordlist_t;

extern wordlist_t wordlist_slip0039;

extern wordlist_t *wordlist;

extern wordlist_t wordlist_base16;
/*
extern wordlist_t wordlist_bip0039_english;

extern wordlist_t wordlist_bip0039_spanish;

// provided by Benjamin Tenne under the terms of the GNU GPL
extern wordlist_t wordlist_diceware_german;

// provided by Bart Van den Eynde under the GFDL
extern wordlist_t wordlist_diceware_dutch;


extern wordlist_t wordlist_base58;

extern wordlist_t wordlist_bech32;
*/

void wordlists_init();

#endif /* SLIP0039_WORDLISTS_H */

