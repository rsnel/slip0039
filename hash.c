/* hash.c - implementation generic hash interface
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
#include <string.h>
#include "hash.h"
#include "utils.h"

hash_function_t hash_functions[2] = { {
		.init = (void (*)(void*))sha256_init,
		.update = (void (*)(void*, const void*, size_t))sha256_update,
		.finalize = (void (*)(void*, uint8_t*, size_t))sha256_finalize,
		.len = SHA256_LEN,
		.blocksize = SHA256_BLOCKSIZE
	}, {
		.init = (void (*)(void*))sha512_init,
		.update = (void (*)(void*, const void*, size_t))sha512_update,
		.finalize = (void (*)(void*, uint8_t*, size_t))sha512_finalize,
		.len = SHA512_LEN,
		.blocksize = SHA512_BLOCKSIZE
	}
};

void hash_init(hash_t *h, hash_type_t type) {
	assert(type >= 0 && type < sizeof(hash_functions)/sizeof(*hash_functions));
	h->f = &hash_functions[type];
	(h->f->init)(&h->ctx);
}

void hash_update(hash_t *h, const void *p, size_t size) {
	(h->f->update)(&h->ctx, p, size);
}

void hash_finalize(hash_t *h, uint8_t *out, size_t size) {
	(h->f->finalize)(&h->ctx, out, size);
}

void hash(uint8_t *out, size_t out_size, const void *in, size_t in_size, hash_type_t type) {
	hash_t h;
	hash_init(&h, type);
	hash_update(&h, in, in_size);
	hash_finalize(&h, out, out_size);
}
