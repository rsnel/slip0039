/* hmac.c - implementation of HMAC
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
#include <stdbool.h>
#include <assert.h>
#include <string.h>
#include "hmac.h"
#include "utils.h"
#include "endian.h"

void hmac_init(hmac_t *h, hash_type_t type) {
	h->state = 0;
	h->type = type;
	hash_init(&h->h, type);
	h->size = 0;
}

void hmac_update_key(hmac_t *h, const void *buf, size_t size) {
	assert(h->state != 2);
	if (h->state == 0) {
		if (size + h->size > h->h.f->blocksize) {
			/* key has gotten longer than the blocksize
			 * of the selected hashfunction, reduce it */
			hash_update(&h->h, h->buf, h->size);
			h->state = 1;
		} else {
			memcpy(h->buf + h->size, buf, size);
			h->size += size;
		}
	}
	/* fallthrough in the case that h->state is set to 1 */
	if (h->state == 1) {
		hash_update(&h->h, buf, size);
	}
}

static void finish_processing_key(hmac_t *h) {
	assert(h->state != 2);
	if (h->state == 1) {
		uint8_t sha[h->h.f->len];
		hash_finalize(&h->h, sha, h->h.f->len);
		memcpy(h->buf, sha, h->h.f->len);
		h->size = h->h.f->len;

		// reinit h->h
		hash_init(&h->h, h->type);
	}

	// set remainder of buffer to zero
	memset(h->buf + h->size, 0, h->h.f->blocksize - h->size);

	// do XOR for ipad
	for (int i = 0; i < h->h.f->blocksize; i++) h->buf[i] ^= 0x36;

	hash_update(&h->h, h->buf, h->h.f->blocksize);
	h->state = 2;
}

void hmac_update_data(hmac_t *h, const void *buf, size_t size) {
	if (h->state != 2) finish_processing_key(h);
	hash_update(&h->h, buf, size);
}

void hmac_update_data_uint32be(hmac_t *h, uint32_t val) {
	uint32_t val32be = cpu_to_be32(val);
	hmac_update_data(h, &val32be, sizeof(val32be));
}

void hmac_done(hmac_t *h, uint8_t *sha, size_t size) {
	uint8_t buf[h->h.f->len];
	if (h->state != 2) finish_processing_key(h);
	hash_finalize(&h->h, buf, h->h.f->len);

	// remove XOR for ipad and do XOR for opad
	for (int i = 0; i < h->h.f->blocksize; i++)
		h->buf[i] ^= 0x36^0x5c;

	hash_init(&h->h, h->type);
	hash_update(&h->h, h->buf, h->h.f->blocksize);
	hash_update(&h->h, buf, h->h.f->len);
	hash_finalize(&h->h, sha, size);
	wipememory(h, sizeof(*h));
}

void hmac(uint8_t *sha, size_t sha_size, const void *k, size_t k_size, const void *p, size_t p_size, hash_type_t type)
{
	hmac_t h;

	hmac_init(&h, type);
	hmac_update_key(&h, k, k_size);
	hmac_update_data(&h, p, p_size);
	hmac_done(&h, sha, sha_size);
}
