/* hmac.c - implementation of HMAC_SHA256
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

void hmac_init(hmac_t *h) {
	h->state = 0;
	sha256_init(&h->ctx);
	h->size = 0;
}

void hmac_update_key(hmac_t *h, const void *buf, size_t size) {
	assert(h->state != 2);
	if (h->state == 0) {
		if (size + h->size > SHA256_BLOCKSIZE) {
			/* key has gotten longer than 64 bytes,
			 * use sha256 to hash it to 32 bytes */
			sha256_update(&h->ctx, h->buf, h->size);
			h->state = 1;
		} else {
			memcpy(h->buf + h->size, buf, size);
			h->size += size;
		}
	}
	/* fallthrough in the case that h->state is set to 1 */
	if (h->state == 1) {
		sha256_update(&h->ctx, buf, size);
	}
}

static void finish_processing_key(hmac_t *h) {
	assert(h->state != 2);
	if (h->state == 1) {
		uint8_t sha[SHA256_LEN];
		sha256_done(&h->ctx, sha, SHA256_LEN);
		memcpy(h->buf, sha, SHA256_LEN);
		h->size = SHA256_LEN;

		// reinit h->ctx
		sha256_init(&h->ctx);
	}

	// set remainder of buffer to zero
	memset(h->buf + h->size, 0, SHA256_BLOCKSIZE - h->size);

	// do XOR for ipad
	for (int i = 0; i < SHA256_BLOCKSIZE; i++) h->buf[i] ^= 0x36;

	sha256_update(&h->ctx, h->buf, SHA256_BLOCKSIZE);
	h->state = 2;
}

void hmac_update_data(hmac_t *h, const void *buf, size_t size) {
	if (h->state != 2) finish_processing_key(h);
	sha256_update(&h->ctx, buf, size);
}

void hmac_update_data_uint32be(hmac_t *h, uint32_t val) {
	uint32_t val32be = cpu_to_be32(val);
	hmac_update_data(h, &val32be, sizeof(val32be));
}

void hmac_done(hmac_t *h, uint8_t *sha, size_t size) {
	uint8_t buf[SHA256_LEN];
	if (h->state != 2) finish_processing_key(h);
	sha256_done(&h->ctx, buf, SHA256_LEN);

	// remove XOR for ipad and do XOR for opad
	for (int i = 0; i < SHA256_BLOCKSIZE; i++)
		h->buf[i] ^= 0x36^0x5c;

	sha256_init(&h->ctx);
	sha256_update(&h->ctx, h->buf, SHA256_BLOCKSIZE);
	sha256_update(&h->ctx, buf, SHA256_LEN);
	sha256_done(&h->ctx, sha, size);
	wipememory(h, sizeof(*h));
}

void hmac(uint8_t *sha, size_t sha_size, const void *k, size_t k_size, const void *p, size_t p_size)
{
	hmac_t h;

	hmac_init(&h);
	hmac_update_key(&h, k, k_size);
	hmac_update_data(&h, p, p_size);
	hmac_done(&h, sha, sha_size);
}
