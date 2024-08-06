/* pbk2df.h - interface to PBKDF2_HMAC
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
#ifndef SLIP0039_PBKDF2_H
#define SLIP0039_PBKDF2_H
#include <stdint.h>
#include <stdlib.h>
#include "hmac.h"

typedef struct pbkdf2_s {
	int state; // 0: password, 1: salt, 2: output
	hmac_t pw, salt;
	uint64_t iterations;
	unsigned char tmp[HASH_MAX_LEN];
	size_t tmp_offset, generated;
	uint32_t index;
} pbkdf2_t;

void pbkdf2_init(pbkdf2_t*, hash_type_t);

void pbkdf2_update_password(pbkdf2_t*, const void*, size_t);

void pbkdf2_update_salt(pbkdf2_t*, const void*, size_t);

void pbkdf2_update_salt_uint8(pbkdf2_t*, uint8_t);

void pbkdf2_finalize_salt(pbkdf2_t*, uint64_t);

void pbkdf2_generate(pbkdf2_t*, void*, size_t);

void pbkdf2_finished(pbkdf2_t*);

void pbkdf2_done(pbkdf2_t*, void*, size_t, uint64_t);

void pbkdf2(void *, const void*, size_t, const void*, size_t, uint64_t, size_t, hash_type_t);

#endif /* SLIP0039_PBKDF2_H */
