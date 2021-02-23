/* lagrange.c - implementation of Lagrange interpolation
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
#include <ctype.h>

#include "verbose.h"
#include "charlists.h"

charlist_t charlist_base16 = {
	.name = "base16",
	.no_chars = 16,
	.chars = (char []){
		'0', '1', '2', '3', '4', '5', '6', '7',
		'8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
	}
};

charlist_t charlist_base58 = {
	.name = "base58",
	.no_chars = 58,
	.chars = (char []){
		'1', '2', '3', '4', '5', '6', '7', '8',
		'9', 'A', 'B', 'C', 'D', 'E', 'F', 'G',
		'H', 'J', 'K', 'L', 'M', 'N', 'P', 'Q',
		'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y',
		'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g',
		'h', 'i', 'j', 'k', 'm', 'n', 'o', 'p',
		'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
		'y', 'z'
	}
};

charlist_t charlist_bech32 = {
	.name = "bech32",
	.no_chars = 32,
	.chars = (char []){
		'q', 'p', 'z', 'r', 'y', '9', 'x', '8',
		'g', 'f', '2', 't', 'v', 'd', 'w', '0',
		's', '3', 'j', 'n', '5', '4', 'k', 'h',
		'c', 'e', '6', 'm', 'u', 'a', '7', 'l'
	}
};

// constant time implementation of charlist[idx]
char charlist_dereference(charlist_t *l, uint8_t idx) {
	assert(l && idx < l->no_chars);
	char out = 0;

	for (int i = 0; i < l->no_chars; i++)
		out |= l->chars[i]&(-(i == idx));

	return out;
}


uint8_t charlist_search(charlist_t *l, char in) {
	int match = -1; /* 0xffffffff */

	for (int i = 0; i < l->no_chars; i++)
		match &= i|(-(in != l->chars[i]));

	if (match == -1) {
		if (isprint(in)) FATAL("illegal character '%c' found in %s encoded data", in, l->name);
		else FATAL("illegal non-printable character \\%o found in %s encoded data", in, l->name);
	}
 
	return match;
}
