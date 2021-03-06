/* charlists.h - declaration of charlist array
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
#ifndef SLIP0039_CHARLISTS_H
#define SLIP0039_CHARLISTS_H

#include <stdint.h>

typedef struct charlist_s {
	char *name;
	int no_chars;
	char *chars;
} charlist_t;

charlist_t charlist_base16;

charlist_t charlist_base58;

charlist_t charlist_bech32;

#endif /* SLIP0039_CHARLISTS_H */

