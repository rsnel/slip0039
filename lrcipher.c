/* lrcipher.c - implementation of the cipher specified in SLIP-0039
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

#include "endian.h"
#include "string.h"
#include "pbkdf2.h"
#include "lrcipher.h"
#include "utils.h"

void lrcipher_init(lrcipher_t *l) {
	assert(l);
	for (uint8_t i = 0; i < 4; i++) {
		pbkdf2_init(&l->rounds[i]);
		pbkdf2_update_password(&l->rounds[i], &i, 1);
	}
}

void lrcipher_add_passphrase(lrcipher_t *l, const char *passphrase, size_t passphrase_len) {
	for (uint8_t i = 0; i < 4; i++) {
		pbkdf2_update_password(&l->rounds[i], passphrase, passphrase_len);
	}
}

void lrcipher_finalize_passphrase(lrcipher_t *l, uint16_t id) {
        uint16_t id_be16 = cpu_to_be16(id);
	for (uint8_t i = 0; i < 4; i++) {
		pbkdf2_update_salt(&l->rounds[i], "shamir", 6);
		pbkdf2_update_salt(&l->rounds[i], &id_be16, 2);
	}
}

static void helper(lrcipher_t *l, unsigned char *L,
		unsigned char *R, size_t size, int round, uint64_t iterations,
		int xchg) {
	pbkdf2_t p = l->rounds[round];
	unsigned char tmp[BLOCKS];
	pbkdf2_update_salt(&p, R, size);
	pbkdf2_done(&p, tmp, size, iterations);

	if (!xchg) for (int i = 0; i < size; i++) {
                tmp[i] ^= L[i];
                L[i] = R[i];
                R[i] = tmp[i];
        } else for (int i = 0; i < size; i++) {
		// do this, so we don't have to switch
		// L and R at the end of lrcipher
		L[i] ^= tmp[i];
	}
	wipememory(tmp, sizeof(tmp));
}

void lrcipher_execute(lrcipher_t *l, unsigned char *dst,
		const unsigned char *src, size_t size,
		uint64_t iterations, lrcipher_dir_t dir) {
	// use dst as scrath pad
	if (src != dst) memmove(dst, src, size);

	size >>= 1;

	// if dir == LRCRYPT_ENCRYPT, then the rounds are 0,1,2,3
	// if dir == LRCRYPT_DECRYPT, then the rounds are 3,2,1,0
        for (int i = 0; i < 4; i++)
                helper(l, dst, dst + size, size, i^dir,
				iterations, i == 3);
}
