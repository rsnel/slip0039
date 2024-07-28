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

typedef struct {
	shashtbl_elt_t elt;
	const char *info;
	void (*encode)(uint8_t *out, size_t *n, lrcipher_t*, uint16_t*, size_t, const char *in, wordlist_t*);
	void (*decode)(char *out, size_t out_size, lrcipher_t*, uint16_t*, size_t, const uint8_t *in, size_t n, wordlist_t *w, base_scratch_t*);
	const char *default_language;
	shashtbl_t wordlists;
} codec_t;

void codec_init();

extern codec_t *codec;

codec_t *codec_find(const char*);

#endif /* SLIP0039_CODEC_H */
