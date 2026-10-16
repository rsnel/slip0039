/* codec.h - code to encode/decode data to/from MS
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
#ifndef SLIP0039_CODEC_H
#define SLIP0039_CODEC_H

#include <stddef.h>
#include <stdint.h>
#include "shashtbl.h"
#include "lrcipher.h"
#include "wordlists.h"
#include "base.h"
#include "config.h"
#include "honey.h"

typedef struct {
	shashtbl_elt_t elt;
	const char *info;
	void (*encode)(uint8_t*, size_t*, lrcipher_t*, uint16_t*, size_t,
			const char*, wordlist_t*, const char*, size_t,
			base_scratch_t*);
	void (*decode)(char*, size_t, lrcipher_t*, uint16_t*, size_t,
			const uint8_t*, size_t, wordlist_t*, base_scratch_t*);
	const char *default_language;
	shashtbl_t wordlists;
} codec_t;

void codec_init();

extern codec_t *codec;

/* number of words to decode, set with --words, 0 if not given */
extern int codec_words;

/* the gain of the honey encoding, set with --gain */
extern double gain;

/* static scratch space for the codecs, cleared at exit: room for 3
 * fixnums of the maximum size and the scratch space of the DTE */
#define CODEC_SCRATCH_SIZE (3*(BLOCKS<<1) + HONEY_SCRATCH_SIZE(BLOCKS<<1))
extern uint8_t codec_scratch[CODEC_SCRATCH_SIZE];

codec_t *codec_find(const char*);

#endif /* SLIP0039_CODEC_H */
