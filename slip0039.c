/* slip0039.c - simple SLIP-0039 implementation in C without dependencies
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
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/random.h>
#if defined(__linux__)
#include <sys/prctl.h>
#endif

#include "slip0039.h"
#include "verbose.h"
#include "codec.h"
#include "utils.h"
#include "rs1024.h"
#include "digest.h"
#include "lagrange.h"
#include "lrcipher.h"
#include "wordlists.h"
#include "fixnum.h"
#include "base.h"
#include "shashtbl.h"
#include "normalize.h"
#include "version.h"

slip0039_mode_t mode = SLIP0039_MODE_NULL;
slip0039_t s;                 // the main struct with all the info
slip0039_mnemonic_t mnemonic; // buffer to contain one mnemonic
pbkdf2_t prng;                // PRNG for shares and part of digests
char plaintext_line[PLAINTEXT_LINE]; // the master secret as given
char plaintext_again[PLAINTEXT_LINE]; // ... typed again on a terminal
char passphrase[LINE];        // the passphrase, as it is read
uint16_t input[BLOCKS<<3];    // space for input
base_scratch_t bs;	      // scratch space for base encoding
uint8_t base_scratch_space[(BLOCKS<<1)<<2]; // actual scratch space
uint8_t slip0039_header[5];

/* use the share format of SLIP-0039 as it was before May 2024, without
 * the extendable backup flag and with a 5 bit iteration exponent */
int pre_may_2024 = 0;

/* generate the SEED instead of reading it */
int random_seed = 0;

// seed for PRNG
char seed[512];
size_t seed_len = 0;

// buffers for stdin and stdout, so that the passphrase, seed, secret
// and mnemonics that pass through stdio end up in static storage that
// we can wipe, instead of in buffers that libc allocates on the heap
char stdin_buffer[BUFSIZ];
char stdout_buffer[BUFSIZ];

#define STACK_CLEAR_SIZE 256 * 1024
#if defined(__APPLE__) && defined(__MACH__)
const void *stackbase = NULL;
#endif

#define SEED_LEN 64

static void usage(FILE *fp) {
	fprintf(fp,
"usage: %s [OPTION]... [recover]\n"
"       %s [OPTION]... check\n"
"       %s [OPTION]... split EXP GT XofY...\n"
"\n"
"recover  read the passphrase and the shares (one per line) on standard\n"
"         input and print the master secret\n"
"check    read the shares (without passphrase) and report which groups\n"
"         are complete and whether the shares belong together\n"
"split    read the passphrase, the SEED and the master secret (one per\n"
"         line) and print the shares; EXP is the iteration exponent, GT\n"
"         the number of groups that is needed, XofY the threshold and\n"
"         the number of shares of each group, as in 2of3\n"
"\n"
"If standard input is a terminal, the input is asked for and the\n"
"passphrase, SEED and master secret are not echoed.\n"
"\n"
"options:\n"
"  -c CODEC[:[WORDLIST][:ARG]]  format of the master secret, see below\n"
"  --gain GAIN      bound on the gain of a guesser by the honey encoding\n"
"                   of structured secrets (default 0.01)\n"
"  --random-seed    split: generate the SEED, it is not read from input\n"
"  --pre-may-2024   split: make shares without the extendable backup flag\n"
"  -d               show the internal data at exit\n"
"  -q               no warnings and notes\n"
"  -h, --help       show this help\n"
"  -V, --version    show the version\n"
"\n"
"codecs (the default is base16):\n"
"  base16                     16 to 64 bytes in hexadecimal\n"
"  bip39[:LANGUAGE]           a BIP39 mnemonic of 12 to 24 words, LANGUAGE\n"
"                             is english (default), spanish, french,\n"
"                             italian, portuguese, czech, japanese, korean,\n"
"                             chinese_simplified or chinese_traditional\n"
"  diceware:[LANGUAGE]:WORDS  a diceware passphrase, english (default),\n"
"                             dutch or german\n"
"  password:[ALPHABET]:LEN    a random password, alnum (default), alpha,\n"
"                             lower or ascii\n"
"  numeric::DIGITS            a random number, a PIN for example\n"
"  totp::CHARS                a base32 TOTP/HOTP secret\n"
"  bip32::VERSION             a root extended private key, xprv, yprv,\n"
"                             zprv, Yprv, Zprv, tprv, uprv, vprv, Uprv, Vprv\n"
"  wif::TYPE                  a private key in WIF, compressed,\n"
"                             uncompressed, testnet-compressed or\n"
"                             testnet-uncompressed\n"
"  nostr                      a nostr private key (nsec1...)\n"
"  codex32::HEADER            a codex32 secret, HEADER is the threshold\n"
"                             and identifier, as in 0test\n"
"\n"
"The argument of a codec is not stored in the shares, keep it with them.\n"
"See the README for details.\n", exec_name, exec_name, exec_name);
}

static void write_stderr(const char *str) {
	if (write(STDERR_FILENO, str, strlen(str)) < 0) return;
}

/* wipe all sensitive data, this is also called from the signal
 * handler, so it must not use stdio or other functions that are
 * not async-signal-safe */
static void wipe_secrets() {
	/* we may have been called from FATAL(), deep in the call stack,
	 * clear the part of the stack that functions that have already
	 * returned have used */
	wipestackmemory(STACK_CLEAR_SIZE);

	wipememory(stdin_buffer, sizeof(stdin_buffer));
	wipememory(stdout_buffer, sizeof(stdout_buffer));
	wipememory(&s, sizeof(s));
	wipememory(mnemonic, sizeof(mnemonic));
	wipememory(dl, sizeof(dl));
	wipememory(seed, sizeof(seed));
	wipememory(plaintext_line, sizeof(plaintext_line));
	wipememory(plaintext_again, sizeof(plaintext_again));
	wipememory(passphrase, sizeof(passphrase));
	wipememory(input, sizeof(input));
	wipememory(&bs, sizeof(bs));
	wipememory(&slip0039_header, sizeof(slip0039_header));
	wipememory(base_scratch_space, sizeof(base_scratch_space));
	wipememory(codec_scratch, sizeof(codec_scratch));
	wipememory(nfkd_scratch, sizeof(nfkd_scratch));
	wipememory(&prng, sizeof(prng));
}

// wipe the secrets on receiving fatal signals, after that the signal is
// raised again, with the default action, so that the exit status shows
// the signal; only async-signal-safe functions are used
void sig_handler(int signum) {
	char num[4] = { '0' + signum/10%10, '0' + signum%10, '\n', '\0' };
	sigset_t set;

	tty_restore();
	wipe_secrets();

	write_stderr(exec_name);
	write_stderr(":fatal:caught signal ");
	write_stderr(signum < 10?num + 1:num);

	/* the action is reset to the default by SA_RESETHAND */
	sigemptyset(&set);
	sigaddset(&set, signum);
	sigprocmask(SIG_UNBLOCK, &set, NULL);
	raise(signum);
	_exit(EXIT_FAILURE);
}

int slip0039_quorum(slip0039_set_t *s) {
	assert(s);
	return (s->available >= s->threshold && s->threshold != 0)?1:0;
}

void slip0039_debug_share(const char *path, int index, int space,
		const uint8_t *buf, size_t n, const char *title) {
	char character;
	sbuf_t sbuf = { .buf = dl, .size = sizeof(dl) };
	memset(dl, 0, sizeof(dl));

	if (index == -3) character = MS_IDENTIFIER;
	else if (index == -2) character = DIGEST_IDENTIFIER;
	else if (index == -1) character = EMS_IDENTIFIER;
	else if (index >= 0 && index < 10) character = '0' + index;
	else if (index >= 10 && index < 16) character = 'A' + index - 10;
	else BUG("invalid share index %d", index);

	sbuf_printf(&sbuf, "%s%c   ", path, character);

	while (space--) sbuf_printf(&sbuf, " ");

	sbuf_printf_base16(&sbuf, buf, n);

	sbuf_printf(&sbuf, " %s", title);
	DEBUG("%s", dl);
}

void slip0039_debug_set(slip0039_set_t *m, slip0039_t *s,
		const char *path, const char *title) {
	assert(m);
	if (m->threshold) {
		char count[6];
		if (m->count) snprintf_strict(count, sizeof(count), "%2d",
				m->count);
		else strncpy(count, " ?", 6);
		DEBUG("%s%s  count=%s available=%2d threshold=% 2d %s",
				path, m->parent?"":"  ", count, m->available,
				m->threshold,  title);

		for (int i = 0; i < ((m->count != 0)?m->count:MAX_SHARES);
				i++) {
			if (m->children[i]) {
				char newpath[16];
				snprintf_strict(newpath, sizeof(newpath),
						"%s%1x/", path, i);
				slip0039_debug_set(m->children[i], s,
						newpath, m->names[i]);
			} else if (m->shares[i])
				slip0039_debug_share(path, i, 0, m->shares[i],
						s->n, m->names[i]);
		}
	}

	for (int i = -2; i < 0; i++)
		if (m->slots[SLIP0039_SLOT(i)])
			slip0039_debug_share(path, i, m->parent?0:2,
					m->slots[SLIP0039_SLOT(i)], s->n, "");
}

void slip0039_debug(slip0039_t *s) {
	assert(s);
	DEBUG("---START---internal slip0039 data----");
	if (s->n) DEBUG("size of master secret=%ld bytes", s->n);
	if (s->id != -1) DEBUG("Identifier=0x%04x", s->id);
	if (s->ext != -1) DEBUG("Extendable backup flag=%d", s->ext);
	if (s->e != -1)
		DEBUG("Iteration exponent=%d (%ld iterations per round)",
				s->e, 2500L<<s->e);

	slip0039_debug_set(&s->root, s, "/", s->title);
	if (s->plaintext)
		slip0039_debug_share("/", -3, 2, s->plaintext, s->n, "");
	DEBUG("---END-----internal slip0039 data----");
}

#if defined(__APPLE__) && defined(__MACH__)
static void mlock_var(const void *const p, const char *const var,
		const size_t len) {
	if (p && len && mlock(p, len) < 0) {
		FATAL("failed locking %s(%u) in RAM: %s", var,
				(unsigned int)len, strerror(errno));
	}
}
static void munlock_var(const void *const p, const char *const var,
		const size_t len) {
	if (p && len && munlock(p, len) < 0) {
		WARNING("failed unlocking %s(%u) in RAM: %s", var,
				(unsigned int)len, strerror(errno));
	}
}
#define mlock_obj(p) do { \
	void *_p = &p; \
	mlock_var(_p, #p, sizeof(p)); \
} while (0)
#define munlock_obj(p) do { \
	void *_p = &p; \
	munlock_var(_p, #p, sizeof(p)); \
} while (0)
#define mlock_ptr(p, len) do { \
	void *_p = &p; \
	mlock_var(_p, "&" #p, sizeof(p)); \
	mlock_var((p), #p, (len)); \
} while (0)
#define munlock_ptr(p, len) do { \
	void *_p = &p; \
	munlock_var(p, #p, (len)); \
	wipememory(_p, sizeof(p)); \
	munlock_var(_p, "&" #p, sizeof(p)); \
} while (0)
#endif

// function that gets called atexit(), so that
// sensitive contents are removed from memory
void wipe() {
	tty_restore();

	slip0039_debug(&s);

	/* exit() flushes the streams after the atexit() handlers have
	 * run, so we flush stdout now, before we wipe its buffer */
	fflush(stdout);

	wipe_secrets();

#if defined(__APPLE__) && defined(__MACH__)
	munlock_ptr(stackbase, STACK_CLEAR_SIZE);
	munlock_obj(s);
	munlock_obj(mnemonic);
	munlock_obj(dl);
	munlock_obj(seed);
	wipememory(&seed_len, sizeof(seed_len));
	munlock_obj(seed_len);
	munlock_obj(prng);
	munlock_obj(plaintext_line);
	munlock_obj(plaintext_again);
	munlock_obj(passphrase);
	munlock_obj(input);
	munlock_obj(bs);
	munlock_obj(slip0039_header);
	munlock_obj(base_scratch_space);
	munlock_obj(stdin_buffer);
	munlock_obj(stdout_buffer);
	munlock_obj(codec_scratch);
	munlock_obj(nfkd_scratch);
#else
	wipememory(&seed_len, sizeof(seed_len));
	if (munlockall() < 0)
		WARNING("failed unlocking process in from RAM: %s",
				strerror(errno));
#endif
}

void slip0039_init(slip0039_t *s) {
	memset(s, 0, sizeof(*s));
	s->id = -1;
	s->ext = -1;
	s->e = -1;
	for (int i = 0; i < MAX_SHARES; i++) {
		s->root.line_numbers[i] = -1;
		s->members[i].parent = &s->root;
		s->root.children[i] = &s->members[i];
	}
}

void slip0039_set_increment_available(slip0039_set_t *m) {
	assert(m);
	m->available++;

	// if this addition made this group make the threshold,
	// then the number of available groups must be incremented
	if (m->available == m->threshold && m->parent)
		slip0039_set_increment_available(m->parent);
}

void slip0039_write_title(slip0039_t *s, uint16_t *title) {
	sbuf_t sb;
	sb.buf = s->title;
	sb.size = sizeof(s->title);
	sb.len = 0;
	sbuf_printf(&sb, " (");
	sbuf_wordlist_dereference(&wordlist_slip0039, &sb, title[0]);
	sbuf_printf(&sb, " ");
	sbuf_wordlist_dereference(&wordlist_slip0039, &sb, title[1]);
	sbuf_printf(&sb, ")");
}

void slip0039_write_group_title(slip0039_t *s, uint8_t i, uint16_t group) {
	sbuf_t sb;
	sb.buf = s->root.names[i];
	sb.size = sizeof(*s->root.names);
	sb.len = 0;
	sbuf_printf(&sb, " (");
	sbuf_wordlist_dereference(&wordlist_slip0039, &sb, group);
	sbuf_printf(&sb, ")");
}

void slip0039_write_member_title(slip0039_t *s, uint8_t i, uint8_t j,
		uint16_t member) {
	sbuf_t sb;
	sb.buf = s->members[i].names[j];
	sb.size = sizeof(*s->members[i].names);
	sb.len = 0;
	sbuf_printf(&sb, "  (");
	sbuf_wordlist_dereference(&wordlist_slip0039, &sb, member);
	sbuf_printf(&sb, ")");
}

void slip0039_print_mnemonics(slip0039_t *s) {
	// these conditions are (?) enfored elsewhere
	assert(s->n >= 16 && s->n%2 == 0 && s->n <= BLOCKS<<1);
	fixnum_t h;

	fixnum_init(&h, slip0039_header, 5);

	fixnum_poke(&h, 25, 15, s->id);
	if (pre_may_2024) {
		assert(s->ext == 0);
		fixnum_poke(&h, 20, 5, s->e);
	} else {
		fixnum_poke(&h, 24, 1, s->ext);
		fixnum_poke(&h, 20, 4, s->e);
	}

	for (uint8_t i = 0; i < s->root.count; i++) {
		fixnum_poke(&h, 16, 4, i);
		fixnum_poke(&h, 12, 4, s->root.threshold - 1);
		fixnum_poke(&h, 8, 4, s->root.count - 1);

		for (uint8_t j = 0; j < s->members[i].count; j++) {
			fixnum_poke(&h, 4, 4, j);
			fixnum_poke(&h, 0, 4, s->members[i].threshold - 1);

			base_encode_buffer(input, 4, &wordlist_slip0039.m,
					slip0039_header, 5, &bs, 0);

			if (j == 0) {
				if (i == 0) slip0039_write_title(s, input);
				slip0039_write_group_title(s, i, input[2]);
			}
			slip0039_write_member_title(s, i, j, input[3]);

			base_encode_buffer(&input[4], (8*s->n + 9)/10,
					&wordlist_slip0039.m,
					s->members[i].shares[j],
					s->n, &bs, 0);

			rs1024_add(input, 4 + (8*s->n + 9)/10, s->ext);

			wipememory(mnemonic, sizeof(mnemonic));

			sbuf_t sb = {
				.buf = mnemonic,
				.size = sizeof(slip0039_mnemonic_t),
				.len = 0
			};

			size_t k = 0;
			goto start;
			while (++k < 4 + (8*s->n + 9)/10 + 3) {
				sbuf_printf(&sb, " ");
start:
				sbuf_wordlist_dereference(&wordlist_slip0039,
						&sb, input[k]);
			}
			printf("%s\n", mnemonic);

		}
	}
}

void slip0039_print_plaintext(slip0039_t *s, codec_t *c) {
	(*c->decode)(dl, sizeof(dl), &s->l, input, sizeof(input)/sizeof(*input),
			s->plaintext, s->n, wordlist, &bs);

	printf("%s\n", dl);
}

void slip0039_add_mnemonic(slip0039_t *s, const char *line, int line_number) {
	size_t no_input = 0;
	fixnum_t h;

	assert(sizeof(input)/sizeof(*input) >= WORDS);

	snprintf_strict(wordlist_context, sizeof(wordlist_context),
			"mnemonic on line %d", line_number);
	while (*line) {
		if (no_input == WORDS) FATAL("too many words in mnemonic on "
					"line %d, "
					"%d supported at maximum",
					line_number, WORDS);

		input[no_input++] = wordlist_search(&wordlist_slip0039,
				line, &line);
	}
	*wordlist_context = '\0';

	/* the customization string of the checksum depends on the
	 * extendable backup flag, which is bit 4 of the second word */
	uint8_t ext = pre_may_2024?0:(input[1]>>4)&1;

	if (no_input < 2 || !rs1024_verify(input, no_input, ext))
		FATAL("checksum of mnemonic on line %d is not valid%s",
				line_number, pre_may_2024?" (if these are "
				"shares from after May 2024, try without "
				"--pre-may-2024)":"");

	if (no_input < 20)
		FATAL("not enough words in mnemonic on line %d, "
				"minimum 20 words", line_number);

	fixnum_init_pattern(&h, slip0039_header, 5, FIXNUM_PATTERN_ZERO);
	base_decode_fixnum(&h, &wordlist_slip0039.m, input, 4, 0);

	size_t n = 2*(10*(no_input - 7)/16);
	size_t surplus = 10*(no_input - 7)%16;
	if (surplus >= 10)
		FATAL("invalid master secret length in mnemonic "
				"on line %d, padding >= 10", line_number);

	uint16_t id;
	uint8_t e, GI, GT, G, I, T;

	/* read header */
	id = fixnum_peek(&h, 25, 15);
	if (pre_may_2024) e = fixnum_peek(&h, 20, 5);
	else {
		assert(fixnum_peek(&h, 24, 1) == ext);
		e = fixnum_peek(&h, 20, 4);
	}

	GI = fixnum_peek(&h, 16, 4);
	GT = fixnum_peek(&h, 12, 4) + 1;
	G =  fixnum_peek(&h, 8, 4)+ 1;
	I = fixnum_peek(&h, 4, 4);
	T = fixnum_peek(&h, 0, 4) + 1;

	if (s->n == 0) { // s is uninitialized
		slip0039_write_title(s, input);
		s->id = id;
		s->ext = ext;
		s->e = e;
		if (pre_may_2024 && e >= 16) WARNING("the most significant "
				"bit of the 5 bit iteration exponent is set, "
				"this is unlikely in shares created before May "
				"2024; if recovery fails, try without "
				"--pre-may-2024");
		if (GT > G) FATAL("invalid mnemonic on line %d, the group "
				"threshold %d is larger than the number of "
				"groups %d", line_number, GT, G);
		s->root.threshold = GT;
		s->root.count = G;
		s->n = n;
	} else {
		if (s->id != id) FATAL("Identifier mismatch in "
				"mnemonic on line %d", line_number);
		if (s->ext != ext) FATAL("Extendable backup flag mismatch "
				"in mnemonic on line %d", line_number);
		if (s->e != e) FATAL("Iteration exponent mismatch "
				"in mnemonic on line %d", line_number);
		if (s->root.threshold != GT) FATAL("Group threshold mismatch "
				"in mnemonic on line %d", line_number);
		if (s->root.count != G) FATAL("Group count mismatch in "
				"mnemonic on line %d", line_number);
		if (s->n != n) FATAL("share size mismatch in mnemonic "
				"on line %d", line_number);
	}

	if (GI >= s->root.count)
		 FATAL("group index too large in mnemonic on line %d, "
				 "number of groups is %d, group index is %d",
			line_number, s->root.count, GI);

	slip0039_set_t *m = &s->members[GI];
	if (!m->threshold) { // new group
		slip0039_write_group_title(s, GI, input[2]);
		m->threshold = T;
		m->count = 0; // undefined
	} else if (m->threshold != T)
		FATAL("Member threshold mismatch in mnemonic on line %d",
				line_number);

	if (m->shares[I])
		FATAL("the mnemonic on line %d is the same share as the "
				"one on line %d", line_number,
				m->line_numbers[I]);

	slip0039_write_member_title(s, GI, I, input[3]);
	m->line_numbers[I] = line_number;

	m->shares[I] = m->storage_shares[I];

	if (base_decode_buffer(m->shares[I], n, &wordlist_slip0039.m,
				&input[4], no_input - 7, 0))
		FATAL("invalid (nonzero) padding in mnemonic on line %d",
				line_number);

	slip0039_set_increment_available(m);
}

/* the codec as it must be given to recover, as in diceware:dutch:10 */
static void codec_spec(sbuf_t *sb) {
	const char *list = (wordlist && *wordlist->elt.key)?
		wordlist->elt.key:"";

	sbuf_printf(sb, "%s", codec->elt.key);
	if (codec_arg) sbuf_printf(sb, ":%s:%s", list, codec_arg);
	else if (*list) sbuf_printf(sb, ":%s", list);
}

/* convert a master secret in words to the form of the wordlist */
static void normalize_plaintext(char *buf, size_t size) {
	if (!wordlist || !wordlist->spaced) return;

	nfkd(buf, size, "master secret");
	normalize_words(buf, !wordlist->has_upper);
}

void slip0039_add_plaintext(slip0039_t *s, codec_t *c) {
	char spec[64];
	sbuf_t sb = { .buf = spec, .size = sizeof(spec) };

	assert(s && !s->plaintext && !s->n);

	codec_spec(&sb);
	prompt("master secret (%s): ", spec);
	read_string_lf(plaintext_line, sizeof(plaintext_line), stdin,
			"master secret", READ_SECRET, NULL);
	normalize_plaintext(plaintext_line, sizeof(plaintext_line));

	if (interactive) {
		prompt("master secret (again): ");
		read_string_lf(plaintext_again, sizeof(plaintext_again), stdin,
				"master secret", READ_SECRET, NULL);
		normalize_plaintext(plaintext_again, sizeof(plaintext_again));
		if (strcmp(plaintext_line, plaintext_again))
			FATAL("the master secrets do not match");
	}

	(c->encode)(s->storage_plaintext, &s->n, &s->l,
			input, sizeof(input)/sizeof(*input),
			plaintext_line, wordlist, seed, seed_len, &bs);

	s->plaintext = s->storage_plaintext;

	// try to read one more character, it should set feof since
	// we don't expect anymore characters
	if (!interactive && fgetc(stdin) != EOF)
		WARNING("data detected after the master secret on input");
}

/* a random SEED of SEED_LEN alphanumeric characters */
static void generate_seed(void) {
	static const char alnum[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz";
	uint8_t r[64];

	assert(sizeof(seed) > SEED_LEN && sizeof(alnum) == 63);

	seed_len = 0;
	while (seed_len < SEED_LEN) {
		if (getentropy(r, sizeof(r)) < 0)
			FATAL_errno("getting random bytes for the seed");
		/* 248 = 4*62, the bytes from 248 are rejected, so that
		 * every character is equally likely */
		for (size_t i = 0; i < sizeof(r) && seed_len < SEED_LEN; i++)
			if (r[i] < 248) seed[seed_len++] = alnum[r[i]%62];
	}
	seed[seed_len] = '\0';
	wipememory(r, sizeof(r));

	if (!quiet) {
		WHINE("seed:%s", seed);
		WHINE("info:the seed is needed only to check the shares "
				"with verify.py, keep it as secret as the "
				"master secret or destroy it");
	}
}

void slip0039_add_seed(slip0039_t *s) {
	uint8_t sha[SHA256_LEN];

	if (random_seed) generate_seed();
	else {
		// now read the seed for the prng
		prompt("seed (empty for a random seed): ");
		read_string_lf(seed, sizeof(seed), stdin, "seed",
				READ_SECRET, &seed_len);
		if (interactive && !seed_len) generate_seed();
	}
#if defined(__APPLE__) && defined(__MACH__)
	mlock_ptr(seed, seed_len);
#endif
	if (seed_len < 64) WARNING("specified value for SEED is very "
				"short, consider using a longer value of at "
				"least 64 alphanumeric bytes or --random-seed");
	hash(sha, SHA256_LEN, seed, seed_len, HASH_SHA256);
	// drop MSB to get 15 bits
	s->id = 0x7fff&((sha[0]<<8) + sha[1]);
}

void slip0039_add_mnemonics(slip0039_t *s, FILE *fp) {
	int count = 0;

	while (1) {
		/* on a terminal, stop asking when there are enough */
		if (interactive && slip0039_quorum(&s->root)) break;

		prompt("share %d (empty line when done): ", count + 1);
		if (!read_string_lf(mnemonic, sizeof(mnemonic), fp, "mnemonic",
					READ_EOF_OK, NULL)) break;

		/* empty lines are skipped, on a terminal they end
		 * the input */
		if (!normalize_words(mnemonic, 1)) {
			if (interactive) break;
			continue;
		}

		slip0039_add_mnemonic(s, mnemonic, input_line);
		count++;
	}

	if (!count) FATAL("no mnemonics given");
}

/* tell which groups are complete */
void slip0039_report(FILE *fp, slip0039_t *s) {
	fprintf(fp, "identifier %d, %s, iteration exponent %d, "
			"master secret of %zu bits\n", s->id,
			s->ext?"extendable":"not extendable", s->e, s->n<<3);
	fprintf(fp, "%d of %d groups needed, %d complete\n",
			s->root.threshold, s->root.count, s->root.available);

	for (int i = 0; i < s->root.count; i++) {
		slip0039_set_t *m = &s->members[i];
		if (!m->threshold) {
			fprintf(fp, "group %d: no shares\n", i + 1);
			continue;
		}
		if (m->available <= m->threshold)
			fprintf(fp, "group %d%s: %d of %d shares", i + 1,
					s->root.names[i], m->available,
					m->threshold);
		else fprintf(fp, "group %d%s: %d shares, %d needed", i + 1,
				s->root.names[i], m->available, m->threshold);
		if (m->available >= m->threshold) fprintf(fp, ", complete");
		else fprintf(fp, ", %d more needed",
				m->threshold - m->available);
		fprintf(fp, " (line%s", m->available == 1?"":"s");
		for (int j = 0, first = 1; j < MAX_SHARES; j++) {
			if (!m->shares[j]) continue;
			fprintf(fp, "%s %d", first?"":",", m->line_numbers[j]);
			first = 0;
		}
		fprintf(fp, ")\n");
	}
}

void slip0039_passphrase(slip0039_t *s, int confirm) {
	size_t len;

	prompt("passphrase (empty for none): ");
	read_string_lf(passphrase, sizeof(passphrase), stdin, "passphrase",
			READ_SECRET, &len);

	if (confirm && interactive) {
		prompt("passphrase (again): ");
		read_string_lf(mnemonic, sizeof(mnemonic), stdin, "passphrase",
				READ_SECRET, NULL);
		if (strcmp(passphrase, mnemonic))
			FATAL("the passphrases do not match");
		wipememory(mnemonic, sizeof(mnemonic));
	}

	for (size_t i = 0; i < len; i++)
		if (passphrase[i] < 32 || passphrase[i] > 126)
			FATAL("character in passphrase is not a printable "
					"ASCII character");

	lrcipher_init(&s->l);
	lrcipher_add_passphrase(&s->l, passphrase, len);
	wipememory(passphrase, sizeof(passphrase));
}

/* must be called after EMS is computed */
void init_prng_pbkdf2(pbkdf2_t *p, slip0039_t *s, const char *seed,
		size_t seed_len) {
	/* initialize PRNG based on PBKDF2 with EMS and SEED
	 * as password and a description of the way the secret
	 * must be split as the first salt
	 *
	 * Password = ( EMS || SEED )
	 * Salt = ( e || GT || G || T_i || count_i  ... )
	 *                       \_______________/  1 <= i <= G
	 *
	 * all numbers are encoded as 8 bit integers */
	assert(s->root.secret);
	pbkdf2_init(p, HASH_SHA256);
	pbkdf2_update_password(p, s->root.secret, s->n);
	pbkdf2_update_password(p, seed, seed_len);
	pbkdf2_update_salt_uint8(p, s->e);
	pbkdf2_update_salt_uint8(p, s->root.threshold);
	pbkdf2_update_salt_uint8(p, s->root.count);
	for (uint8_t i = 0; i < s->root.count; i++) {
		slip0039_set_t *set = &s->members[i];
		pbkdf2_update_salt_uint8(p, set->threshold);
		pbkdf2_update_salt_uint8(p, set->count);
	}
	pbkdf2_finalize_salt(p, 1);
}

void slip0039_split(slip0039_set_t *s, size_t n, pbkdf2_t *p) {
	assert(s->secret && !s->digest);
	for (uint8_t i = 0; i < MAX_SHARES; i++) assert(!s->shares[i]);

	if (s->threshold == 1) {
		for (uint8_t i = 0; i < s->count; i++) {
			assert(!s->shares[i]);
			s->shares[i] = s->storage_shares[i];
			memcpy(s->shares[i], s->secret, n);
		}
	} else {
		/* the secret and digest will be known, once we start
		 * to compute the other shares using lagrange */
		uint8_t idx[MAX_SHARES] = { -1, -2 };
		int no_idx = 2;

		/* compute digest */
		assert(!s->digest);
		s->digest = s->storage_digest;
		pbkdf2_generate(p, s->digest + DIGEST_LEN, n - DIGEST_LEN);
		digest_compute(s->digest, s->secret, n);

		/* generate the other required shares randomly */
		for (uint8_t i = 0; i < s->threshold - 2; i++) {
			assert(!s->shares[i]);
			s->shares[i] = s->storage_shares[i];
			pbkdf2_generate(p, s->shares[i], n);
			idx[no_idx++] = i; // share[i] is set
		}

		/* compute the remaining shares */
		for (uint8_t i = s->threshold - 2; i < s->count; i++) {
			assert(!s->shares[i]);
			s->shares[i] = s->storage_shares[i];
			lagrange(s, n, no_idx, idx, i, s->shares[i]);
		}
	}

	s->available = s->count;

	for (uint8_t i = 0; i < s->count; i++) {
		slip0039_set_t *child = s->children[i];
		if (!child) continue;

		child->secret = s->shares[i];
		slip0039_split(child, n, p);
	}
}

/* share x of s (a group, or the root if group is -1) does not lie on the
 * polynomial of the other shares */
static void slip0039_inconsistent(slip0039_set_t *s, int group, uint8_t x) {
	if (group < 0) FATAL("group %d does not belong to the same master "
			"secret as the other groups", x + 1);
	else FATAL("the mnemonic on line %d does not belong to the same "
			"secret as the other mnemonics of group %d",
			s->line_numbers[x], group + 1);
}

/* recover the secret of s (a group, or the root if group is -1) from
 * the first threshold shares; the other shares, if there are more, must
 * give the same secret, they are checked */
void slip0039_recover(slip0039_set_t *s, int group, uint8_t *secret,
		size_t n) {
	uint8_t idx[MAX_SHARES], check[BLOCKS<<1];
	int no_idx = 0;

	assert(s->available >= s->threshold && s->threshold);

	for (int i = 0; i < MAX_SHARES; i++) {
		slip0039_set_t *child = s->children[i];
		if (!s->shares[i] && child && slip0039_quorum(child)) {
			slip0039_recover(child, i, s->storage_shares[i], n);
			s->shares[i] = s->storage_shares[i];
		}
		if (s->shares[i]) idx[no_idx++] = i;
	}

	assert(no_idx >= s->threshold);

	if (s->threshold == 1) {
		// if threshold is 1, just copy the first
		// available share to the secret, since
		// all shares contain the same data
		// (and there SHOULD only be one share)
		// furthermore, there is no digest to verify
		s->secret = secret;
		memcpy(s->secret, s->shares[idx[0]], n);
	} else {
		// compute digest share (uint8_t)-2 = 254
		// and secret share (uint8_t)-1 = 255

		for (int i = -2; i < 0; i++) {
			assert(!s->slots[SLIP0039_SLOT(i)]);
			s->slots[SLIP0039_SLOT(i)] =
				(i == -2)?s->storage_digest:secret;
			lagrange(s, n, s->threshold, idx, (uint8_t)i,
					s->slots[SLIP0039_SLOT(i)]);
		}

		if (!digest_verify(s->digest, s->secret, n)) {
			if (group < 0) FATAL("the digest of the master secret "
					"does not match, the groups do not "
					"belong to the same master secret");
			else FATAL("the digest of group %d does not match, "
					"its mnemonics do not belong to the "
					"same secret", group + 1);
		}
	}

	/* the shares that were not needed must lie on the same polynomial,
	 * this detects a share of another split with the same identifier */
	for (int k = s->threshold; k < no_idx; k++) {
		if (s->threshold == 1) memcpy(check, s->secret, n);
		else lagrange(s, n, s->threshold, idx, idx[k], check);
		if (!memeq(check, s->shares[idx[k]], n))
			slip0039_inconsistent(s, group, idx[k]);
	}

	wipememory(check, sizeof(check));
}

void slip0039_decrypt(slip0039_t *s) {
	assert(s && !s->plaintext && s->root.secret);
	s->plaintext = s->storage_plaintext;
	lrcipher_execute(&s->l, s->plaintext, s->root.secret,
			s->n, 2500L<<s->e, LRCIPHER_DECRYPT);
}

void slip0039_encrypt(slip0039_t *s) {
	assert(s && !s->root.secret && s->plaintext);
	s->root.secret = s->storage_secret;
	lrcipher_execute(&s->l, s->root.secret, s->plaintext,
			s->n, 2500L<<s->e, LRCIPHER_ENCRYPT);
}

void boring_stuff() {
	/* let stdio use our static buffers, this must be done
	 * before any input or output takes place on these streams */
	if (setvbuf(stdin, stdin_buffer, _IOFBF, sizeof(stdin_buffer)) ||
			setvbuf(stdout, stdout_buffer, _IOFBF,
				sizeof(stdout_buffer)))
		FATAL("failed to set buffers for stdin and stdout");

	/* a core dump would contain all secrets, mlock() does not
	 * prevent that, so we disable core dumps */
	struct rlimit no_core = { .rlim_cur = 0, .rlim_max = 0 };
	if (setrlimit(RLIMIT_CORE, &no_core) < 0)
		FATAL("failed to disable core dumps: %s", strerror(errno));
#if defined(__linux__)
	/* this also prevents core dumps if RLIMIT_CORE is ignored,
	 * because the kernel pipes them to a helper program */
	if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) < 0)
		FATAL("failed to make process non-dumpable: %s",
				strerror(errno));
#endif

#if defined(__APPLE__) && defined(__MACH__)
	mlock_ptr(stackbase, STACK_CLEAR_SIZE);
	mlock_obj(s);
	mlock_obj(mnemonic);
	mlock_obj(dl);
	mlock_obj(seed);
	mlock_obj(seed_len);
	mlock_obj(prng);
	mlock_obj(plaintext_line);
	mlock_obj(plaintext_again);
	mlock_obj(passphrase);
	mlock_obj(input);
	mlock_obj(bs);
	mlock_obj(base_scratch_space);
	mlock_obj(slip0039_header);
	mlock_obj(stdin_buffer);
	mlock_obj(stdout_buffer);
	mlock_obj(codec_scratch);
	mlock_obj(nfkd_scratch);
#else
	/* lock me into memory; don't leak info to swap */
	if (mlockall(MCL_CURRENT|MCL_FUTURE)<0)
		FATAL("failed locking process in RAM: %s",
				strerror(errno));
#endif

	if (atexit(wipe))
		FATAL("error setting atexit() handler");

	/* make the program cleanup our data on receiving common
	 * signals and on crashes */
	static const int signals[] = { SIGINT, SIGTERM, SIGHUP, SIGQUIT,
		SIGABRT, SIGALRM, SIGPIPE, SIGUSR1, SIGUSR2, SIGSEGV, SIGBUS,
		SIGFPE, SIGILL, SIGTRAP };
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sig_handler;
	sa.sa_flags = SA_RESETHAND;
	sigfillset(&sa.sa_mask);
	for (size_t i = 0; i < sizeof_array(signals); i++)
		if (sigaction(signals[i], &sa, NULL) < 0)
			FATAL_errno("installing signal handler");
}

void parse_options_split(slip0039_t *s, char *arg,
		slip0039_parse_state_t *state, int *max_T) {
	char *end;

	if (*state == SLIP0039_PARSE_STATE_EXP) {
		/* the range depends on --pre-may-2024, which may come
		 * later on the commandline, it is checked afterwards */
		s->e = parse_number(arg, "iteration exponent", 0, 31, &end, 1);
		*state = SLIP0039_PARSE_STATE_GT;
	} else if (*state == SLIP0039_PARSE_STATE_GT) {
		s->root.threshold = parse_number(arg, "group threshold", 1,
				MAX_SHARES, &end, 1);
		*state = SLIP0039_PARSE_STATE_XOFY;
	} else if (*state == SLIP0039_PARSE_STATE_XOFY) {
		if (s->root.count == MAX_SHARES)
			FATAL("at most %d groups supported", MAX_SHARES);
		unsigned long int x = parse_number(arg, "X in group spec XofY",
				1, MAX_SHARES, &end, 0);
		arg = end;
		if (arg[0] != 'o' || arg[1] != 'f')
			FATAL("X and Y must be separated by 'of', as in 4of6");
		arg += 2;
		unsigned long int y = parse_number(arg, "Y in group spec XofY",
				x, MAX_SHARES, &end, 1);
		if (x == 1 && y > 1)
			WARNING("X == 1, according to the spec, "
					"Y SHOULD also be 1");
		if ((int)x > *max_T) *max_T = x;
		s->members[s->root.count].count = y;
		s->members[s->root.count].threshold = x;
		s->root.count++;
	} else BUG("invalid parse state %d", *state);
}

/* parse CODEC[:[WORDLIST][:ARG]], an empty WORDLIST selects the
 * default wordlist of the codec */
void parse_codec(char *arg) {
	char *name = arg, *list = NULL, *a = NULL;

	if ((list = strchr(name, ':'))) {
		*list++ = '\0';
		if ((a = strchr(list, ':'))) *a++ = '\0';
	}

	codec_arg = a;

	codec = codec_find(name);
	if (!codec) FATAL("codec %s not available, see %s --help", name,
			exec_name);
	if (!codec->encode || !codec->decode)
		FATAL("codec %s is not implemented", name);

	if (!codec->default_language) {
		if (list && *list) FATAL("codec %s does not take a wordlist",
				name);
		wordlist = NULL;
	} else if (!list || !*list) {
		wordlist = shashtbl_search_elt_bykey(&codec->wordlists,
				codec->default_language);
		// the default should be available
		assert(wordlist);
	} else {
		wordlist = shashtbl_search_elt_bykey(&codec->wordlists, list);
		if (!wordlist) FATAL("wordlist \"%s\" not found for codec "
				"%s", list, name);
	}

	if (codec_arg) {
		if (!codec->parse_arg) FATAL("codec %s does not take an "
				"argument", name);
		(*codec->parse_arg)(codec_arg);
	}
}

void parse_options(slip0039_t *s, int argc, char *argv[]) {
	slip0039_parse_state_t state = SLIP0039_PARSE_STATE_EXP;
	int max_T = 0;
	int optind = 1;

	while (argc > optind) {
		char *arg = argv[optind++];
		if (!strcmp(arg, "-d")) debug = 1;
		else if (!strcmp(arg, "-q")) quiet = 1;
		else if (!strcmp(arg, "-h") || !strcmp(arg, "--help")) {
			usage(stdout);
			exit(EXIT_SUCCESS);
		} else if (!strcmp(arg, "-V") || !strcmp(arg, "--version")) {
			printf("slip0039 %s\n", SLIP0039_VERSION);
			exit(EXIT_SUCCESS);
		} else if (!strcmp(arg, "-c")) {
			if (argc > optind) {
				parse_codec(argv[optind++]);
			} else FATAL("option -c given, but no argument "
					"supplied");
		} else if (!strcmp(arg, "--pre-may-2024")) {
			pre_may_2024 = 1;
		} else if (!strcmp(arg, "--random-seed")) {
			random_seed = 1;
		} else if (!strcmp(arg, "--gain")) {
			if (argc > optind) {
				char *end;
				gain = strtod(argv[optind], &end);
				// the negation also rejects NaN
				if (*argv[optind] == '\0' || *end != '\0' ||
						!(gain >= 1.0/(1ULL<<62) &&
							gain <= 1))
					FATAL("invalid value \"%s\" for --gain, "
							"it must be a number "
							"between 2^-62 and 1",
							argv[optind]);
				optind++;
			} else FATAL("option --gain given, but no argument "
					"supplied");
		} else if (arg[0] == '-' && arg[1] != '\0')
			FATAL("unknown option %s, see %s --help", arg,
					exec_name);
		else if (mode == SLIP0039_MODE_RECOVER ||
				mode == SLIP0039_MODE_CHECK)
			FATAL("no arguments must be given after \"%s\"",
					mode == SLIP0039_MODE_CHECK?
					"check":"recover");
		else if (mode == SLIP0039_MODE_SPLIT)
			parse_options_split(s, arg, &state, &max_T);
		else {
			assert(mode == SLIP0039_MODE_NULL);
			if (!strcmp(arg, "recover"))
				mode = SLIP0039_MODE_RECOVER;
			else if (!strcmp(arg, "check"))
				mode = SLIP0039_MODE_CHECK;
			else if (!strcmp(arg, "split"))
				mode = SLIP0039_MODE_SPLIT;
			else FATAL("first non-option argument must be "
					"\"recover\", \"check\" or \"split\", "
					"see %s --help", exec_name);
		}
	}

	if (pre_may_2024) WARNING("--pre-may-2024 selects the share format "
			"of SLIP-0039 as it was before the extendable backup "
			"flag was added in May 2024, this is not recommended");

	if (codec->parse_arg && !codec_arg && mode != SLIP0039_MODE_CHECK)
		FATAL("codec %s needs the %s, for example -c %s",
				codec->elt.key, codec->arg_name,
				codec->arg_example);

	if (random_seed && mode != SLIP0039_MODE_SPLIT)
		FATAL("--random-seed can only be used with split");

	// set mode to 'recover' if no mode is specified
	if (mode == SLIP0039_MODE_NULL) mode = SLIP0039_MODE_RECOVER;

	// check if we have all the neccesary information
	// to create the shares if mode is set to 'split'
	else if (mode == SLIP0039_MODE_SPLIT) {
		if (state == SLIP0039_PARSE_STATE_EXP)
			FATAL("iteration exponent needs to be specified "
					"as next argument");
		else if (state == SLIP0039_PARSE_STATE_GT)
			FATAL("GT (group threshold) needs to be specified "
					"as next argument");
		else if (state == SLIP0039_PARSE_STATE_XOFY &&
				s->root.count < s->root.threshold)
			FATAL("not enough groups specified to satisfy "
					"group threshold");
		else {
			assert(max_T > 0);
			if (!pre_may_2024 && s->e > 15)
				FATAL("iteration exponent must be <= 15");
			s->ext = !pre_may_2024;
			if (pre_may_2024) WARNING("the shares will not be "
					"extendable%s", s->e > 15?" and other "
					"SLIP-0039 implementations will not be "
					"able to recover them, because the "
					"iteration exponent is >= 16":"");
			if (max_T == 1 && s->root.count > 1)
				WARNING("a simple split in %d different "
						"shares, SHOULD be made "
						"using a single group "
						"according to the spec",
						s->root.count);
		}
	}

}

/* the salt of the encryption is "shamir" || id, unless the shares are
 * extendable, then it is empty */
void slip0039_finalize_passphrase(slip0039_t *s) {
	assert(s->ext == 0 || s->ext == 1);
	if (!s->ext) lrcipher_finalize_passphrase(&s->l, "shamir", 6, s->id);
}

/* the codec is not stored in the shares, tell how to recover them */
static void print_recover_hint(void) {
	char spec[64];
	sbuf_t sb = { .buf = spec, .size = sizeof(spec) };

	if (quiet || !strcmp(codec->elt.key, "base16")) return;

	codec_spec(&sb);
	WHINE("info:recover with: %s -c %s recover", exec_name, spec);
	WHINE("info:the codec and its argument are not stored in the "
			"shares, keep this with the shares");
}

/* warn about groups that have shares, but not enough */
static void warn_unused_groups(slip0039_t *s) {
	for (int i = 0; i < s->root.count; i++) {
		slip0039_set_t *m = &s->members[i];
		if (m->available && m->available < m->threshold)
			WARNING("group %d%s has %d of %d shares, it is not "
					"used", i + 1, s->root.names[i],
					m->available, m->threshold);
	}
}

int main(int argc, char *argv[]) {
#if defined(__APPLE__) && defined(__MACH__)
	// save stackbase for locking stack memory
	stackbase = (const void*)((uintptr_t)&argc - STACK_CLEAR_SIZE);
#endif

	verbose_init(argv[0]);
	codec_init();
	boring_stuff();
	base_init_scratch(&bs, base_scratch_space, BLOCKS<<1);
	wordlists_init();
	slip0039_init(&s);
	parse_options(&s, argc,argv);
	interactive = isatty(STDIN_FILENO);
	if (wordlist) wordlist_prepare(wordlist);

	if (mode == SLIP0039_MODE_SPLIT) {
		/* read passphrase from first line of stdin */
		slip0039_passphrase(&s, 1);

		/* read seed for encoding on second line of stdin */
		slip0039_add_seed(&s);

		/* we should have the ID and the extendable backup flag,
		 * these are needed to finish initializing lrcipher */
		slip0039_finalize_passphrase(&s);

		/* read Master Secret (MS) and seed */
		slip0039_add_plaintext(&s, codec);

		/* encrypt plaintext to EMS */
		slip0039_encrypt(&s);

		init_prng_pbkdf2(&prng, &s, seed, seed_len);

		/* calculate all shares */
		slip0039_split(&s.root, s.n, &prng);

		slip0039_print_mnemonics(&s);

		print_recover_hint();
	} else if (mode == SLIP0039_MODE_CHECK) {
		/* no passphrase, only the shares */
		slip0039_add_mnemonics(&s, stdin);

		slip0039_report(stdout, &s);
		fflush(stdout);

		if (!slip0039_quorum(&s.root)) {
			printf("not enough shares to recover the master "
					"secret\n");
			exit(EXIT_FAILURE);
		}

		/* this checks the digests and the extra shares */
		slip0039_recover(&s.root, -1, s.storage_secret, s.n);

		printf("the shares belong together, the master secret can "
				"be recovered\n");
	} else {
		/* read passphrase from first line of stdin */
		slip0039_passphrase(&s, 0);

		/* read mnemonics from stdin (one per line) */
		slip0039_add_mnemonics(&s, stdin);

		/* we now have the ID and the extendable backup flag,
		 * these are needed to finish initializing lrcipher */
		slip0039_finalize_passphrase(&s);

		/* check if EMS can be recovered from
		 * these shares */
		if (!slip0039_quorum(&s.root)) {
			slip0039_report(stderr, &s);
			FATAL("not enough shares to recover "
					"the master secret");
		}

		warn_unused_groups(&s);

		slip0039_recover(&s.root, -1, s.storage_secret, s.n);

		/* decrypt EMS to MS */
		slip0039_decrypt(&s);

		slip0039_print_plaintext(&s, codec);
	}

	/* the stack is cleared by wipe(), which is called by exit() */
}
