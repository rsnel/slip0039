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
#include <string.h>
#include <sys/mman.h>

#include "slip0039.h"
#include "verbose.h"
#include "utils.h"
#include "base1024.h"
#include "digest.h"
#include "lagrange.h"
#include "lrcipher.h"
#include "wordlists.h"
#include "charlists.h"
#include "fixnum.h"

slip0039_mode_t mode = SLIP0039_MODE_NULL;
slip0039_t s;                 // the main struct with all the info
base1024_t b;                 // needed to convert wordlist to and from bits
slip0039_mnemonic_t mnemonic; // buffer to contain one mnemonic
pbkdf2_t prng;                // PRNG for shares and part of digests

// seed for PRNG
const char *seed = NULL;
size_t seed_len = 0;

// call exit on receiving fatal signals
void sig_handler(int signum) {
	FATAL("%s", strsignal(signum));
}

int slip0039_quorum(slip0039_set_t *s) {
	assert(s);
	return (s->available >= s->threshold && s->threshold != 0)?1:0;
}

void slip0039_debug_share(const char *path, int index, int space,
		const uint8_t *buf, size_t n, const char *title) {
	char character;
        sbuf_t sbuf = { .buf = dl, .size = sizeof(dl) };

	if (index == -3) character = MS_IDENTIFIER;
	else if (index == -2) character = DIGEST_IDENTIFIER;
	else if (index == -1) character = EMS_IDENTIFIER;
	else if (index >= 0 && index < 10) character = '0' + index;
	else if (index >= 10 && index < 16) character = 'A' + index - 10;
	else assert(0);

	sbufprintf(&sbuf, "%s%c   ", path, character);

	while (space--) sbufprintf(&sbuf, " ");

	sbufprintf_base16(&sbuf, buf, n);

	sbufprintf(&sbuf, " %s", title);
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
		if (*(m->shares + i))
			slip0039_debug_share(path, i, m->parent?0:2,
					m->shares[i], s->n, "");
}

void slip0039_debug(slip0039_t *s) {
	assert(s);
	DEBUG("---START---internal slip0039 data----");
	if (s->n) DEBUG("size of master secret=%ld bytes", s->n);
	if (s->id != -1) DEBUG("Identifier=0x%04x", s->id);
	if (s->e != -1)
		DEBUG("Iteration exponent=%d (%ld iterations per round)",
				s->e, 2500L<<s->e);

	slip0039_debug_set(&s->root, s, "/", s->title);
	if (s->plaintext)
		slip0039_debug_share("/", -3, 2, s->plaintext, s->n, "");
	DEBUG("---END-----internal slip0039 data----");
}

// function that gets called atexit(), so that
// sensitive contents are removed from memory
void wipe() {
	slip0039_debug(&s);
	wipememory(&s, sizeof(s));
	wipememory(mnemonic, sizeof(mnemonic));
	wipememory(&b, sizeof(b));
	wipememory(dl, sizeof(dl));
	wipememory(seed, seed_len);
	pbkdf2_finished(&prng);
}

void slip0039_init(slip0039_t *s) {
	memset(s, 0, sizeof(*s));
	s->id = -1;
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
	sbufprintf(&sb, " (");
	sbufwordlist_dereference(&wordlist_slip0039, &sb, title[0]);
	sbufprintf(&sb, " ");
	sbufwordlist_dereference(&wordlist_slip0039, &sb, title[1]);
	sbufprintf(&sb, ")");
}

void slip0039_write_group_title(slip0039_t *s, uint8_t i, uint16_t group) {
	sbuf_t sb;
	sb.buf = s->root.names[i];
	sb.size = sizeof(*s->root.names);
	sb.len = 0;
	sbufprintf(&sb, " (");
	sbufwordlist_dereference(&wordlist_slip0039, &sb, group);
	sbufprintf(&sb, ")");
}

void slip0039_write_member_title(slip0039_t *s, uint8_t i, uint8_t j, uint16_t member) {
	sbuf_t sb;
	sb.buf = s->members[i].names[j];
	sb.size = sizeof(*s->members[i].names);
	sb.len = 0;
	sbufprintf(&sb, "  (");
	sbufwordlist_dereference(&wordlist_slip0039, &sb, member);
	sbufprintf(&sb, ")");
}

void slip0039_print_mnemonics(slip0039_t *s) {
	// these conditions are (?) enfored elsewhere
	assert(s->n >= 16 && s->n%2 == 0 && s->n <= BLOCKS<<1);
	base1024_empty(&b);
	unsigned int padding_bits = ((s->n*8 + 9)/10)*10 - s->n*8;

	base1024_write_bits(&b, s->id, 15);
	base1024_write_bits(&b, s->e, 5);

	slip0039_write_title(s, b.words);

	for (uint8_t i = 0; i < s->root.count; i++) {
		base1024_write_bits(&b, i, 4);
		base1024_write_bits(&b, s->root.threshold - 1, 4);
		base1024_write_bits(&b, s->root.count - 1, 4);

		slip0039_write_group_title(s, i, b.words[2]);

		for (uint8_t j = 0; j < s->members[i].count; j++) {
			base1024_write_bits(&b, j, 4);
			base1024_write_bits(&b,
					s->members[i].threshold - 1, 4);

			slip0039_write_member_title(s, i, j, b.words[3]);

			// write padding
			base1024_write_bits(&b, 0, padding_bits);

			for (int k = 0; k < s->n; k++)
				base1024_write_bits(&b, s->members[i].shares[j][k], 8);

			assert(b.bit_idx == 0);


			base1024_append_checksum(&b);
			base1024_to_string(&b, mnemonic);
			printf("%s\n", mnemonic);

			base1024_rewind_and_truncate(&b, 32);
		}
		base1024_rewind_and_truncate(&b, 20);
	}
}

void slip0039_print_plaintext(slip0039_t *s) {
        sbuf_t sbuf = { .buf = dl, .size = sizeof(dl) };
	sbufprintf_base16(&sbuf, s->plaintext, s->n);

	printf("%s\n", dl);
}

void slip0039_add_mnemonic(slip0039_t *s, const char *line, int line_number) {
	base1024_from_string(&b, line, line_number);
	base1024_verify_checksum(&b, line_number);

        if (b.no_words < 20)
		FATAL("not enough words in mnemonic on line %d, "
				"minimum 20 words", line_number);

	size_t n = 2*(10*(b.no_words - 7)/16);
	size_t surplus = 10*(b.no_words - 7)%16;
        if (surplus >= 10) 
                FATAL("invalid master secret length in mnemonic "
				"on line %d, padding >= 10", line_number);

	/* read header */
	uint16_t id = base1024_read_bits(&b, 15);
	uint8_t e = base1024_read_bits(&b, 5);

	uint8_t GI = base1024_read_bits(&b, 4);
	uint8_t GT = base1024_read_bits(&b, 4) + 1;
	uint8_t G = base1024_read_bits(&b, 4) + 1;
	uint8_t I = base1024_read_bits(&b, 4);
	uint8_t T = base1024_read_bits(&b, 4) + 1;

	if (s->n == 0) { // s is uninitialized
		slip0039_write_title(s, b.words);
		s->id = id;
		s->e = e;
		s->root.threshold = GT;
		s->root.count = G;
		s->n = n;
	} else {
		if (s->id != id) FATAL("Identifier mismatch in "
				"mnemonic on line %d", line_number);
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
		slip0039_write_group_title(s, GI, b.words[2]);
		m->threshold = T;
		m->count = 0; // undefined
	} else if (m->threshold != T)
		FATAL("Member threshold mismatch in mnemonic on line %d",
				line_number);

	if (m->shares[I])
		FATAL("share is already loaded in mnemonic on line %d",
				line_number);

	slip0039_write_member_title(s, GI, I, b.words[3]);
	m->line_numbers[I] = line_number;

	if (base1024_read_bits(&b, surplus))
		FATAL("invalid (nonzero) padding in mnemonic on line %d",
				line_number);

	m->shares[I] = m->storage_shares[I];

	for (int i = 0; i < n; i++)
		m->shares[I][i] = base1024_read_bits(&b, 8);

	slip0039_set_increment_available(m);
}

/* this function reads a hexadecimal string and interpretes it
 * as binary data (it MUST have an even number of characters */
void slip0039_add_plaintext(slip0039_t *s, FILE *fp) {
	assert(s && !s->plaintext && !s->n);

	size_t nibbles = 0;
	fixnum_t f;
	int character;
	fixnum_init(&f, s->storage_plaintext, BLOCKS<<1);
	do {
		character = fgetc(fp);
		if (character == EOF) {
			if (feof(fp))
				FATAL("end of file while reading passphrase");
			else FATAL("error %d reading passphrase: %s",
					errno, strerror(errno));
		} else if (character == '\n') break;
		else fixnum_poke(&f, (f.no_limbs<<3) - (nibbles++<<2) - 4, 4,
					charlist_search(&charlist_base16, character));
	} while (1);

	if (nibbles%2) FATAL("odd number of hexadecimal digits given");
	if (nibbles%4) FATAL("size of plaintext must be a multiple of 16 bits");
	if (nibbles>>1 < 16) FATAL("size of plaintext must be at least 16 bytes");

	s->plaintext = s->storage_plaintext;
	s->n = nibbles>>1;

	character = fgetc(fp);
	if (!feof(fp)) WARNING("data detected after plaintext on input");
}

void slip0039_add_mnemonics(slip0039_t *s, FILE *fp) {
	char *out;
	int line_number = 0;

	while ((out = fgets(mnemonic, sizeof(mnemonic), fp))) {
		slip0039_add_mnemonic(s, mnemonic, ++line_number);
	}

	if (!out && !feof(fp))
		FATAL("error %d reading from stream: %s",
				errno, strerror(errno));
}

void slip0039_add_passphrase(slip0039_t *s, FILE *fp) {
	int character;
	lrcipher_init(&s->l);
	do {
		character = fgetc(fp);
		if (character == EOF) {
			if (feof(fp))
			       	FATAL("end of file while reading passphrase");
			else FATAL("error %d reading passphrase: %s",
					errno, strerror(errno));
		} else if (character == '\n') break;
		else if (character < 32 || character > 126)
			FATAL("character in passphrase is not a "
					"printable character");

		char tmp = (char)character;
		lrcipher_add_passphrase(&s->l, &tmp, 1);
	} while (1);
}

/* must be called after EMS is computed */
void init_prng_pbkdf2(pbkdf2_t *p) {
	/* initialize PRNG based on PBKDF2 with EMS and SEED
	 * as password and a description of the way the secret
	 * must be split as the first salt
	 *
	 * Password = ( EMS || SEED )
	 * Salt = ( e || GT || G || T_i || count_i  ... )
	 *                       \_______________/  1 <= i <= G
	 *
	 * all numbers are encoded as 8 bit integers */
	assert(s.root.secret);
	pbkdf2_init(p);
	pbkdf2_update_password(p, s.root.secret, s.n);
	pbkdf2_update_password(p, seed, seed_len);
	pbkdf2_update_salt_uint8(p, s.e);
	pbkdf2_update_salt_uint8(p, s.root.threshold);
	pbkdf2_update_salt_uint8(p, s.root.count);
	for (uint8_t i = 0; i < s.root.count; i++) {
		slip0039_set_t *set = &s.members[i];
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
		assert(!*(s->shares - 2));
		*(s->shares - 2) = s->storage_digest;
		pbkdf2_generate(p, *(s->shares - 2) + DIGEST_LEN, n - DIGEST_LEN);
		digest_compute(*(s->shares - 2), *(s->shares - 1), n);

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
			lagrange(s, n, no_idx, idx, i);
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

void slip0039_recover(slip0039_set_t *s, uint8_t *secret, size_t n) {
        uint8_t idx[MAX_SHARES];
        int no_idx = 0;

	assert(s->available >= s->threshold && s->threshold);

	for (int i = 0; i < MAX_SHARES; i++) {
		slip0039_set_t *child = s->children[i];
		if (!s->shares[i] && child && slip0039_quorum(child)) {
			slip0039_recover(child, s->storage_shares[i], n);
			s->shares[i] = s->storage_shares[i];
		}
		if (s->shares[i]) idx[no_idx++] = i;

                if (no_idx == s->threshold) break;
        }

        assert(no_idx == s->threshold);

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
			assert(!s->shares[i]);
			*(s->shares + i) = (i == -2)?s->storage_digest:secret;
			lagrange(s, n, no_idx, idx, (uint8_t)i);
		}

		digest_verify(s->digest, s->secret, n);
	}
}

void slip0039_decrypt(slip0039_t *s) {
	assert(s && !s->plaintext && s->root.secret);
	s->plaintext = s->storage_plaintext;
	lrcipher_finalize_passphrase(&s->l, s->id);
	lrcipher_execute(&s->l, s->plaintext, s->root.secret,
			s->n, 2500L<<s->e, LRCIPHER_DECRYPT);
}

void slip0039_encrypt(slip0039_t *s) {
	assert(s && !s->root.secret && s->plaintext);
	s->root.secret = s->storage_secret;
	lrcipher_finalize_passphrase(&s->l, s->id);
	lrcipher_execute(&s->l, s->root.secret, s->plaintext,
			s->n, 2500L<<s->e, LRCIPHER_ENCRYPT);
}

void boring_stuff() {
#if defined(__APPLE__) && defined(__MACH__)
	WARNING("MACOS does not implement mlockall() api, your secret would be write to swap disk!");
#else
        /* lock me into memory; don't leak info to swap */
        if (mlockall(MCL_CURRENT|MCL_FUTURE)<0)
                FATAL("failed locking process in RAM: %s",
                                strerror(errno));
#endif

	if (atexit(wipe))
		FATAL("error setting atexit() handler");

	/* make the program cleanup our data
	 * on receiving common signals */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
	signal(SIGHUP, sig_handler);
	signal(SIGQUIT, sig_handler);
	signal(SIGABRT, sig_handler);
	signal(SIGALRM, sig_handler);
	signal(SIGPIPE, sig_handler);
	signal(SIGUSR1, sig_handler);
	signal(SIGUSR2, sig_handler);
}

unsigned long int parse_number(const char *arg, const char *name, 
		unsigned long int min, unsigned long int max,
		char **end, int empty) {
	unsigned long int ret = strtoul(arg, end, 0);

	if (*end == arg) FATAL("expected %s, found \"%s\" instead", name, arg);
	if (ret > max) FATAL("%s must be <= %lu", name, max);
	if (ret < min) FATAL("%s must be >= %lu", name, min);
	if (empty && **end != '\0') FATAL("junk found while parsing %s", name);

	return ret;
}

void parse_options_split(slip0039_t *s, char *arg,
		slip0039_parse_state_t *state, int *max_T) {
	char *end;

	if (*state == SLIP0039_PARSE_STATE_SEED) {
		uint8_t sha[SHA256_LEN];
		assert(!seed && seed_len == 0);
		seed = arg;
		seed_len = strlen(seed);
		if (seed_len < 4) WARNING("specified value for SEED is very "
				"short, consider using a longer value");
		sha256(sha, seed, seed_len);
	       	// drop MSB to get 15 bits
		s->id = 0x7fff&((sha[0]<<8) + sha[1]);
		*state = SLIP0039_PARSE_STATE_EXP;
	} else if (*state == SLIP0039_PARSE_STATE_EXP) {
		s->e = parse_number(arg, "iteration exponent", 0, 32, &end, 1);
		*state = SLIP0039_PARSE_STATE_GT;
	} else if (*state == SLIP0039_PARSE_STATE_GT) {
		s->root.threshold = parse_number(arg, "group threshold", 0,
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
		if (x > *max_T) *max_T = x;
		s->members[s->root.count].count = y;
		s->members[s->root.count].threshold = x;
		s->root.count++;
	} else assert(0);
}

void parse_options(slip0039_t *s, int argc, char *argv[]) {
	slip0039_parse_state_t state = SLIP0039_PARSE_STATE_SEED;
	int max_T = 0;
	int optind = 1;

	while (argc > optind) {
		char *arg = argv[optind];
		if (!strcmp(arg, "-d")) debug = 1;
		else if (!strcmp(arg, "-q")) quiet = 1;
		else if (mode == SLIP0039_MODE_RECOVER) FATAL("no arguments "
				"must be given after \"recover\"");
		else if (mode == SLIP0039_MODE_SPLIT)
			parse_options_split(s, arg, &state, &max_T);
		else {
		       	assert(mode == SLIP0039_MODE_NULL);
			if (!strcmp(arg, "recover"))
				mode = SLIP0039_MODE_RECOVER;
			else if (!strcmp(arg, "split"))
				mode = SLIP0039_MODE_SPLIT;
			else FATAL("first non-option argument must be "
					"\"recover\" or \"split\"");
		}

		optind++;
	}

	// set mode to 'recover' if no mode is specified
	if (mode == SLIP0039_MODE_NULL) mode = SLIP0039_MODE_RECOVER;

	// check if we have all the neccesary information
	// to create the shares if mode is set to 'split'
	else if (mode == SLIP0039_MODE_SPLIT) {
		if (state == SLIP0039_PARSE_STATE_SEED)
			FATAL("SEED needs to be specified as next argument");
		else if (state == SLIP0039_PARSE_STATE_EXP)
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
			if (max_T == 1 && s->root.count > 1)
				WARNING("a simple split in %d different "
						"shares, SHOULD be made "
						"using a single group "
						"according to the spec",
						s->root.count);
		}
	}

}

int main(int argc, char *argv[]) {
	verbose_init(argv[0]);
	boring_stuff();

       	slip0039_init(&s);
	parse_options(&s, argc,argv);

	/* read passphrase from first line of stdin */
	slip0039_add_passphrase(&s, stdin);

	if (mode == SLIP0039_MODE_SPLIT) {
		/* read Master Secret (MS) */
		slip0039_add_plaintext(&s, stdin);

		/* encrypt plaintext to EMS */
		slip0039_encrypt(&s);

		init_prng_pbkdf2(&prng);

		/* calculate all shares */
		slip0039_split(&s.root, s.n, &prng);

		slip0039_print_mnemonics(&s);
	} else {
		/* read mnemonics from stdin (one per line) */
		slip0039_add_mnemonics(&s, stdin);

		/* check if EMS can be recovered from
		 * these shares */
		if (!slip0039_quorum(&s.root))
			FATAL("not enough shares to recover "
					"the master secret");

		slip0039_recover(&s.root, s.storage_secret, s.n);

		/* decrypt EMS to MS */
		slip0039_decrypt(&s);

		slip0039_print_plaintext(&s);
	}
}
