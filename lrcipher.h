/* lrcipher.h - interface to the cipher specified in SLIP-0039
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
#ifndef SLIP0039_LRCIPHER_H
#define SLIP0039_LRCIPHER_H
#include <stdint.h>
#include <stddef.h>

#include "pbkdf2.h"

typedef struct lrcipher_s {
	pbkdf2_t rounds[4];
} lrcipher_t;

typedef enum lrcypher_dir_e { LRCIPHER_ENCRYPT = 0, LRCIPHER_DECRYPT = 3 } lrcipher_dir_t;

void lrcipher_init(lrcipher_t*);

void lrcipher_add_passphrase(lrcipher_t*, const char*, size_t);

void lrcipher_finalize_passphrase(lrcipher_t*, uint16_t);

void lrcipher_execute(lrcipher_t*, unsigned char*,
		const unsigned char*, size_t, uint64_t, lrcipher_dir_t);

#endif /* SLIP0039_LRCYPER_H */

