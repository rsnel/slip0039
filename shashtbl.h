/* shashtbl.h - simple hash table
 *
 * Copyright (C) 2010  Rik Snel <rik@snel.it>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef SLIP0039_SHASHTBL_H
#define SLIP0039_SHASHTBL_H 1

#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include "llist.h"

typedef struct shashtbl_elt_s {
	struct shashtbl_elt_s *next;
	const char *key;
} shashtbl_elt_t;

typedef struct shashtbl_s {
	llist_info_t li;
	llist_t *buckets;
	uint8_t key_bits;    /* number of key bits that are
				 used for bucket selection,
				 1<<key_bits is number of buckets */
	uint8_t unique;
} shashtbl_t;

void *shashtbl_init_default(shashtbl_t*, uint8_t, uint8_t, size_t, void (*)(void*));

void *shashtbl_init_simple(shashtbl_t*, uint8_t, uint8_t);

void shashtbl_free(shashtbl_t*);

void shashtbl_empty(shashtbl_t*);

shashtbl_elt_t **shashtbl_search_eltp(shashtbl_t*, void*);

void *shashtbl_search_elt_bykey(shashtbl_t*, const char*);

shashtbl_elt_t **shashtbl_search_eltp_bykey(shashtbl_t*, const char*);

void *shashtbl_add_elt(shashtbl_t*, void*);

void *shashtbl_alloc_and_add_elt(shashtbl_t*, const char*);

void shashtbl_del_eltp(shashtbl_t*, shashtbl_elt_t**);

void shashtbl_del_elt(shashtbl_t*, void*);

void shashtbl_del_elt_bykey(shashtbl_t*, const char*);

void *shashtbl_iteratorp(shashtbl_t*, void *(*)(shashtbl_elt_t**, void*), void*);

void *shashtbl_iterator(shashtbl_t*, void *(*)(void*, void*), void*);

size_t shashtbl_get_count(shashtbl_t*);

#endif /* SLIP0039_SHASHTBL_H */
