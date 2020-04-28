/* shamir.c - implementation shamir splitting and recovery
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
#include "lagrange.h"
#include "digest.h"
#include "hmac.h"
#include "utils.h"
#include "verbose.h"

void digest_verify(const uint8_t *digest, const uint8_t *secret, size_t n) {
	assert(digest && secret && n >= 16);
	uint8_t computed[DIGEST_LEN];
	
	// compute HMAC-SHA256 with last n - 4 bytes of digest share (254)
	// as key and the secret share (255) as data
	hmac(computed, DIGEST_LEN, digest + DIGEST_LEN,
			n - DIGEST_LEN, secret, n);

	if (!memeq(digest, computed, DIGEST_LEN)) FATAL("digest failed");
}

void digest_compute(uint8_t *digest, const uint8_t *secret, size_t n) {
	assert(digest && secret && n >= 16);
	hmac(digest, DIGEST_LEN, digest + DIGEST_LEN,
			n - DIGEST_LEN, secret, n);
}
