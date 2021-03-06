/* utils.h - some utilties
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
#ifndef SLIP0039_UTILS_H
#define SLIP0039_UTILS_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "config.h"
#include "charlists.h"
#include "wordlists.h"

#define sizeof_array(a)	(sizeof(a)/sizeof(*a))

/* To avoid that a compiler optimizes certain memset calls away, these
 * macros may be used instead. */
#define wipememory2(_ptr,_set,_len) do { \
        volatile char *_vptr=(volatile char *)(_ptr); \
        size_t _vlen=(size_t)(_len); /*, ctr = 0;*/ \
        while(_vlen) { \
                *_vptr=(_set); _vptr++; _vlen--; \
        } \
} while(0)
#define wipememory(_ptr,_len) wipememory2(_ptr,0,_len)

typedef struct sbuf_s {
	char *buf;
	size_t size;
	size_t len;
} sbuf_t;

typedef char displayline_t[DISPLAYLINE];

displayline_t dl;

int wordlist_dereference(wordlist_t*, char *, int, uint16_t);

void sbufwordlist_dereference(wordlist_t*, sbuf_t*, uint16_t);

uint16_t wordlist_search(wordlist_t*, const char*, const char**);

char charlist_dereference(charlist_t*, uint8_t);

uint8_t charlist_search(charlist_t*, char);

int vsnprintf_strict(char*, size_t, const char*, va_list ap);

int snprintf_strict(char*, size_t, const char*, ...);

int sbufprintf(sbuf_t*, const char* format, ...);

int sbufprintf_base16(sbuf_t*, const uint8_t*, size_t);

int memeq(const uint8_t*, const uint8_t*, size_t);

#endif /* SLIP0039_UTILS_H */
