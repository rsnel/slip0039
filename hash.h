/* hash.h - interface to SHA256/SHA512...
 *
 * ------
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
#ifndef SLIP0039_HASH_H
#define SLIP0039_HASH_H
#include <stdint.h>
#include <stdlib.h>
#include "sha256.h"
#include "sha512.h"

#define HASH_MAX_LEN		64
#define HASH_MAX_BLOCKSIZE	128

typedef struct hash_s {
	struct hash_function_s *f;
	union {
		struct sha256_ctx sha256;
		struct sha512_ctx sha512;
	} ctx;
} hash_t;

typedef struct hash_function_s {
	void (*init)(void*);
	void (*update)(void*, const void*, size_t);
	void (*finalize)(void*, uint8_t*, size_t);
	size_t len, blocksize;
} hash_function_t;

extern hash_function_t hash_functions[];

typedef enum hash_type_e {
	HASH_SHA256 = 0,
	HASH_SHA256D,
	HASH_SHA512
} hash_type_t;

void hash_init(hash_t*, hash_type_t);

void hash_update(hash_t*, const void*, size_t);

void hash_finalize(hash_t*, uint8_t*, size_t);

void hash(uint8_t*, size_t, const void*, size_t, hash_type_t);

#endif /* SLIP0039_HASH_H */
