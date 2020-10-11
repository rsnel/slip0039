/* base1024.c - functions encode/decode base1024 data
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
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "slip0039.h"
#include "verbose.h"
#include "base1024.h"
#include "rs1024.h"
#include "utils.h"
#include "wordlists.h"

void base1024_to_string(base1024_t *b, slip0039_mnemonic_t line) {
	sbuf_t s = {
		.buf = line,
		.size = sizeof(slip0039_mnemonic_t),
		.len = 0
	};
	int i = 0;

	goto start;

	while (++i < b->no_words) {
		sbufprintf(&s, " ");
start:
		sbufprintf(&s, "%s", wordlist_slip0039[b->words[i]]);
	}
}

void base1024_empty(base1024_t *b) {
	assert(b);
       	memset(b, 0, sizeof(*b));
}

void base1024_from_string(base1024_t *b, const slip0039_mnemonic_t line,
		int line_number) {
	base1024_empty(b);

	while (*line) {
		if (b->no_words == WORDS)
			FATAL("too many words in mnemomic on line %d, "
					"%d supported at maximum",
					line_number, WORDS);

		int index = search(line);
		if (index < 0) {
			const char *end = line;
			for (int i = 0; i < LINE; i++)
				end += (*end != '\0') &&
					(*end != ' ') && (*end != '\n');
			FATAL("word \"%.*s\" not found in wordlist",
					(int)(end - line), line);
		}

		b->words[b->no_words++] = index;

		/* max length of a valid word is 8 chars, so
		 * we need to skip at most 8 letters to get
		 * to the space or EOS */
		for (int i = 0; i < 8; i++)
			line += (*line != '\0') &&
				(*line != ' ') && (*line != '\n');

		/* skip a space (if any) */
		line += (*line == ' ') || (*line == '\n');
	}
}

void base1024_verify_checksum(base1024_t *b, int line_number) {
	rs1024_state_t ok = RS1024_INIT, s;

        rs1024_init_slip0039(&s);
        rs1024_add_array(&s, b->words, b->no_words);

        if (ok.chk != s.chk) 
		FATAL("checksum of mnemomic on line %d is not valid",
				line_number);
}

void base1024_append_checksum(base1024_t *b) {
	assert(b->no_words + 3 <= WORDS);
	assert(b->bit_idx == 0);
	rs1024_state_t s;
	rs1024_init_slip0039(&s);
	rs1024_add_array(&s, b->words, b->no_words);
	rs1024_checksum(&s, b->words + b->no_words);
	b->no_words += 3;
}

void base1024_print(base1024_t *b) {
	printf("no_words=%d, data:", b->no_words);
	for (int i = 0; i < b->no_words; i++) 
		printf(" %04x (%s)", b->words[i], wordlist_slip0039[b->words[i]]);

	printf("\n");
}

void base1024_rewind_and_truncate(base1024_t *b, unsigned int index) {
	/* index in bits */
	int target_word_idx = index/BITS_PER_WORD;
	int target_bit_idx = index%BITS_PER_WORD;

	assert(b->word_idx > target_word_idx ||
			(b->word_idx == target_word_idx &&
				b->bit_idx >= target_bit_idx));

	while (b->word_idx > target_word_idx) {
		if (b->bit_idx > 0) {
			b->words[b->word_idx] = 0;
		}
		b->word_idx--;
		b->bit_idx = 10;
	}
	
	b->words[b->word_idx] &= 0xFFFF<<(BITS_PER_WORD-target_bit_idx);
	b->bit_idx = target_bit_idx;
}

void base1024_write_bits(base1024_t *b, unsigned int data, unsigned int bits) {
	assert(b && bits <= 32);

	while (bits--) {
		assert(b->word_idx < WORDS);
		assert(!(b->words[b->word_idx]&(0x200>>b->bit_idx)));
		if (data&(1<<bits)) 
			b->words[b->word_idx] |= 0x200>>b->bit_idx;

		b->bit_idx++;
		if (b->bit_idx == BITS_PER_WORD) {
			b->bit_idx = 0;
			b->word_idx++;
		}
	}

	b->no_words = b->word_idx + (b->bit_idx != 0);
}

unsigned int base1024_read_bits(base1024_t *b, unsigned int bits) {
	assert(b && bits <= 32);
	unsigned int out = 0;

	while (bits--) {
		out <<= 1;
		assert(b->word_idx < WORDS);
		out |= (b->words[b->word_idx]&(0x200>>b->bit_idx)) != 0;
		b->bit_idx++;
		if (b->bit_idx == BITS_PER_WORD) {
			b->bit_idx = 0;
			b->word_idx++;
		}
	}

	return out;
}
