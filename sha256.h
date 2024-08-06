/* sha256.h - interface to SHA256
 *
 * ------
 *
 * SHA256 core code translated from the Bitcoin project's C++:
 *
 * src/crypto/sha256.cpp commit 417532c8acb93c36c2b6fd052b7c11b6a2906aa2
 * Copyright (c) 2014 The Bitcoin Core developers
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
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
#ifndef SLIP0039_SHA256_H
#define SLIP0039_SHA256_H
#include <stdint.h>
#include <stdlib.h>

#define SHA256_LEN		32
#define SHA256_BLOCKSIZE	64

/**
 * struct sha256_ctx - structure to store running context for sha256
 */
struct sha256_ctx {
	uint32_t s[8];
	union {
		uint32_t u32[16];
		unsigned char u8[64];
	} buf;
	size_t bytes;
};

/**
 * sha256_init - initialize an SHA256 context.
 * @ctx: the sha256_ctx to initialize
 *
 * This must be called before sha256_update or sha256_done, or
 * alternately you can assign SHA256_INIT.
 *
 * If it was already initialized, this forgets anything which was
 * hashed before.
 *
 * Example:
 * static void hash_all(const char **arr, struct sha256 *hash)
 * {
 *	size_t i;
 *	struct sha256_ctx ctx;
 *
 *	sha256_init(&ctx);
 *	for (i = 0; arr[i]; i++)
 *		sha256_update(&ctx, arr[i], strlen(arr[i]));
 *	sha256_done(&ctx, hash);
 * }
 */
void sha256_init(struct sha256_ctx *ctx);

/**
 * SHA256_INIT - initializer for an SHA256 context.
 *
 * This can be used to statically initialize an SHA256 context (instead
 * of sha256_init()).
 *
 * Example:
 * static void hash_all(const char **arr, struct sha256 *hash)
 * {
 *	size_t i;
 *	struct sha256_ctx ctx = SHA256_INIT;
 *
 *	for (i = 0; arr[i]; i++)
 *		sha256_update(&ctx, arr[i], strlen(arr[i]));
 *	sha256_done(&ctx, hash);
 * }
 */
#define SHA256_INIT							\
	{ { 0x6a09e667ul, 0xbb67ae85ul, 0x3c6ef372ul, 0xa54ff53aul,	\
	    0x510e527ful, 0x9b05688cul, 0x1f83d9abul, 0x5be0cd19ul },	\
	  { { 0 } }, 0 }

/**
 * sha256_update - include some memory in the hash.
 * @ctx: the sha256_ctx to use
 * @p: pointer to memory,
 * @size: the number of bytes pointed to by @p
 *
 * You can call this multiple times to hash more data, before calling
 * sha256_done().
 */
void sha256_update(struct sha256_ctx *ctx, const void *p, size_t size);

/**
 * sha256_done - finish SHA256 and return the hash
 * @ctx: the sha256_ctx to complete
 * @sha: the hash to return.
 *
 * Note that @ctx is *destroyed* by this, and must be reinitialized.
 * To avoid that, pass a copy instead.
 */
void sha256_finalize(struct sha256_ctx *sha256, uint8_t *sha, size_t size);

// finalize and do another sha256
void sha256d_finalize(struct sha256_ctx *sha256, uint8_t *sha, size_t size);

#endif /* SLIP0039_SHA256_H */
