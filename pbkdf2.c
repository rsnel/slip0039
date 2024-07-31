/* pbkdf2.c - implementation of PBKDF2_HMAC_SHA256
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
#include "sha256.h"
#include "pbkdf2.h"
#include "endian.h"
#include "utils.h"

void pbkdf2_init(pbkdf2_t *p) {
	assert(p);
	assert(SHA256_LEN%8 == 0);
	p->state = 0;
	p->index = 1;
	p->generated = 0;
	hmac_init(&p->pw);
	p->tmp_offset = SHA256_LEN;
}

void pbkdf2_update_password(pbkdf2_t *p, const void *buf, size_t size) {
	assert(p->state == 0);
	hmac_update_key(&p->pw, buf, size);
}

static void finish_processing_password(pbkdf2_t *p) {
	assert(p->state == 0);
	hmac_update_data(&p->pw, NULL, 0); // trigger finalization of the key
	p->salt = p->pw;
	p->state = 1;
}

void pbkdf2_update_salt(pbkdf2_t *p, const void *buf, size_t size) {
	if (p->state == 0) finish_processing_password(p);
	assert(p->state == 1);
	hmac_update_data(&p->salt, buf, size);
}

void pbkdf2_update_salt_uint8(pbkdf2_t *p, uint8_t val) {
	pbkdf2_update_salt(p, &val, 1);
}

void pbkdf2_finalize_salt(pbkdf2_t *p, uint64_t iterations) {
	assert(p->state == 0 || p->state == 1);
	assert(p->index == 1);
	if (p->state == 0) finish_processing_password(p);
	if (p->state == 1) {
		p->iterations = iterations;
		p->state = 2;
	}
	assert(p->iterations > 0);
}

static void helper(pbkdf2_t *p) {
	uint8_t sha[SHA256_LEN];
	hmac_t h = p->salt;
	hmac_update_data_uint32be(&h, p->index++);
	hmac_done(&h, sha, SHA256_LEN);
	memcpy(p->tmp, sha, SHA256_LEN);
	for (int i = 1; i < p->iterations; i++) {
		h = p->pw;
		hmac_update_data(&h, sha, SHA256_LEN);
		hmac_done(&h, sha, SHA256_LEN);
		for (int j = 0; j < SHA256_LEN/8; j++)
			((uint64_t*)p->tmp)[j] ^= ((uint64_t*)sha)[j];
	}
	p->tmp_offset = 0;
}

void pbkdf2_generate(pbkdf2_t *p, void *buf, size_t dkLen) {
	size_t len;
	assert(p->state == 2);
	assert(p->tmp_offset <= SHA256_LEN && p->tmp_offset >= 0);
	while (dkLen > 0) {
		if (p->tmp_offset == SHA256_LEN) helper(p);
		len = (dkLen > SHA256_LEN - p->tmp_offset)?(SHA256_LEN - p->tmp_offset):dkLen;
		memcpy(buf, p->tmp + p->tmp_offset, len);
		dkLen -= len;
		buf += len;
		p->generated += len;
		p->tmp_offset += len;
	}
}

void pbkdf2_finished(pbkdf2_t *p) {
	wipememory(p, sizeof(*p));
}

void pbkdf2_done(pbkdf2_t *p, void *buf, size_t dkLen, uint64_t iterations) {
	pbkdf2_finalize_salt(p, iterations);
	pbkdf2_generate(p, buf, dkLen);
	pbkdf2_finished(p);
}

void pbkdf2(void *buf, const void *password, size_t password_size,
		const void *salt, size_t salt_size, uint64_t iterations, size_t dkLen) {
	pbkdf2_t p;
	pbkdf2_init(&p);
	pbkdf2_update_password(&p, password, password_size);
	pbkdf2_update_salt(&p, salt, salt_size);
	pbkdf2_done(&p, buf, dkLen, iterations);
}

