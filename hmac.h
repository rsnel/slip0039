/* hmac.h - interface to HMAC_SHA256
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
#ifndef SLIP0039_HMAC_H
#define SLIP0039_HMAC_H
#include "sha256.h"

typedef struct hmac_s {
	int state; // 0: key_plain, 1: key_hash, 2: data
	struct sha256_ctx ctx; 
	unsigned char buf[SHA256_BLOCKSIZE];
	size_t size;
} hmac_t;

void hmac_init(hmac_t*);

void hmac_update_key(hmac_t*, const void*, size_t);

void hmac_update_data(hmac_t*, const void*, size_t);

void hmac_update_data_uint32be(hmac_t*, uint32_t);

void hmac_done(hmac_t*, uint8_t*, size_t);

void hmac(uint8_t *sha, size_t, const void*, size_t, const void*, size_t);

#endif /* SLIP0039_HMAC_H */
