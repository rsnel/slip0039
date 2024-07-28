/* config.h - compile time configuration
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
#ifndef SLIP0039_CONFIG_H
#define SLIP0039_CONFIG_H

#define HAVE_LITTLE_ENDIAN 1
// support secrets of at most BLOCKS*2 bytes since
// the spec requires that secrets of 256 bits (32 bytes)
// are supported, BLOCKS must be >= 16
// we set this to 32 to be able to store xpubs and xprvs
#define BLOCKS 32

#define BITS_PER_WORD 10

// the maximum number of supported words
// 4 words for the header, 3 for the checksum
// and enough words to store BLOCKS*16 bits
#define WORDS 	(4 + (BLOCKS*16 + BITS_PER_WORD - 1)/BITS_PER_WORD + 3)

// size of a line with WORDS words of 8 characters (there are no longer words
// than 8 chars in the wordlist) (space between the words and end with newline
// and string terminator)
#define LINE 	(WORDS*9 + 1)


//#define DISPLAYLINE 160
#define DISPLAYLINE 256

#define DIGEST_LEN 4

#define MAX_SHARES 16

// in this implementation, the shares are indexed by an 8 bit
// integer, such that -1 == (int8_t)255 and -2 == (int8_t)254
// (255 and 254 are the x-coordinates of the secret and the digest)
// therefore we only support up to 254 shares, this is sufficient
// because the standard only allows for up to 16 shares
// the shares are numbered from 0, so the 254th share has index 253
#if MAX_SHARES > 254
#error "MAX_SHARES must be < 255"
#endif

// shares are identified with 0 - 9, A - F, the special shares DIGEST,
// EMS and the non-share MS are identified by the following characters
#define DIGEST_IDENTIFIER 	'?'
#define EMS_IDENTIFIER	  	'S'
#define MS_IDENTIFIER		'P'

#endif /* SLIP0039_CONFIG_H */
