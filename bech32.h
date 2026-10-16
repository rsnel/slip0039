/* bech32.h - checksums of bech32 (BIP-0173) and codex32 (BIP-0093)
 *
 * Copyright 2026 Rik Snel <rik@snel.it>
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
#ifndef SLIP0039_BECH32_H
#define SLIP0039_BECH32_H

#include <stddef.h>
#include <stdint.h>

#define BECH32_CHECKSUM_LEN 6

/* data are 5 bit values, including the checksum */
int bech32_verify(const char*, const uint16_t*, size_t);

/* computes the BECH32_CHECKSUM_LEN values of the checksum of data */
void bech32_checksum(const char*, const uint16_t*, size_t, uint16_t*);

/* the length of the checksum of a codex32 data part of the given
 * length (without checksum), 0 if this length is not allowed */
int ms32_checksum_len(size_t);

/* verifies the data part of a codex32 string with the human readable
 * part "ms", including the checksum, returns the length of the checksum,
 * or 0 if the checksum or the length is not valid */
int ms32_verify(const uint16_t*, size_t);

/* computes the checksum of the data part (without checksum) */
void ms32_checksum(const uint16_t*, size_t, uint16_t*);

#endif /* SLIP0039_BECH32_H */
