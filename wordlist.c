/* wordlist.c - looking up words in wordlists
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
#include <string.h>
#include <stdlib.h>

#include "wordlists.h"
#include "utils.h"
#include "verbose.h"
#include "cthelp.h"
#include "normalize.h"

int wordlist_dereference(wordlist_t *w, char *buf, int buf_size, uint16_t idx) {
	assert(w && idx < w->m.value && buf_size > w->max_word_length);
	int ret = 0;

	for (int i = 0; i < w->max_word_length + 1; i++)
		assert(*(buf + i) == '\0');

	for (int i = 0; i < w->m.value; i++) {
		char *cur = w->words[i];
		int eq = cthelp_eq(i, idx);
		while (*cur) {
			*(buf + (cur - w->words[i])) |= *cur&(-eq);
			ret += 1&(-eq);
			cur++;
		}
	}

	return ret;
}

uint16_t wordlist_search(wordlist_t *w, const char *word, const char **end) {
	char **words = w->match_words?w->match_words:w->words;
	int req_terminator = w->spaced ||
		w->max_word_length != w->min_word_length;
	int match = 0, found = 0;
	*end = NULL;

	/* some wordlists (diceware dutch) have a word more than once,
	 * the first match is taken, the words are the same, so the
	 * secret is the same */
	for (int i = 0; i < w->m.value; i++) {
		int eq = 1 - (w->min_prefix?
				wordpfxeq(word, words[i], end, w->min_prefix):
				wordeq(word, words[i], end, req_terminator));
		int first = eq&(1 - found);
		match |= i&(-first);
		found |= eq;
	}

	if (!found) {
		sbuf_t sbuf = { .buf = dl, .size = sizeof(dl) };
		/* the words of an alphabet are single characters */
		int alphabet = !w->spaced && w->max_word_length == 1;

		sbuf_printf(&sbuf, alphabet?"character '":"word '");

		if (alphabet) sbuf_putchar(&sbuf, *word);
		else while (*word != '\0' && *word != ' ' && *word != '\n')
			sbuf_putchar(&sbuf, *word++);

		if (*w->elt.key == '\0') {
			sbuf_printf(&sbuf, "' not found in the %s %s",
					w->family,
					alphabet?"alphabet":"wordlist");
		} else if (alphabet) {
			sbuf_printf(&sbuf, "' not found in the %s alphabet "
					"of %s", w->elt.key, w->family);
		} else {
			sbuf_printf(&sbuf, "' not found in the %s wordlist "
					"of language %s", w->family,
					w->elt.key);
		}
		if (w->min_prefix) sbuf_printf(&sbuf, " (a word can be "
				"given by its first %d letters)",
				w->min_prefix);
		FATAL("%s", dl);
	}

	return match;
}

/* the input is converted to NFKD (see nfkd()), so the words must be in
 * that form too; the words are not changed, since they are used in the
 * output, normalized copies are made of the words that need it */
void wordlist_prepare(wordlist_t *w) {
	char buf[256];

	assert(w);
	if (!w->spaced || w->match_words) return;

	for (int i = 0; i < w->m.value; i++) {
		assert(strlen(w->words[i]) < sizeof(buf));
		strcpy(buf, w->words[i]);
		nfkd(buf, sizeof(buf), "word of wordlist");
		if (!strcmp(buf, w->words[i])) continue;

		if (!w->match_words) {
			if (!(w->match_words = calloc(w->m.value,
							sizeof(char*))))
				FATAL_errno("allocating normalized wordlist");
			for (int j = 0; j < w->m.value; j++)
				w->match_words[j] = w->words[j];
		}

		if (!(w->match_words[i] = strdup(buf)))
			FATAL_errno("allocating normalized word");
	}
}
