/* sha512.h - interface to SHA512
 *
 * ------
 *
 * SHA512 core code translated from the Bitcoin project's C++:
 *
 * src/crypto/sha512.cpp commit 96ee992ac3535848e2dc717bf284339badd40dcb
 * Copyright (c) 2014-2022 The Bitcoin Core developers
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
#ifndef SLIP0039_SHA512_H
#define SLIP0039_SHA512_H
#include <stdint.h>
#include <stdlib.h>

#define SHA512_LEN              64
#define SHA512_BLOCKSIZE        128


/**
 * struct shar512_ctx - structure to store running context for sha512
 */
struct sha512_ctx {
    uint64_t s[8];
    unsigned char buf[128];
    size_t bytes;
};

void sha512_init(struct sha512_ctx *ctx);

void sha512_update(struct sha512_ctx *ctx, const void *p, size_t size);

void sha512_finalize(struct sha512_ctx *ctx, uint8_t *sha512, size_t size);

#endif // SLIP0039_SHA512_H
