/* llist.h - linked list
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
#ifndef INCLUDE_TAGMEISTER_LLIST_H
#define INCLUDE_TAGMEISTER_LLIST_H 1

#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>

typedef struct llist_info_s {
	size_t size;
	void (*freer)(void*);
} llist_info_t;

llist_info_t *llist_info_init_default(llist_info_t*, size_t, void (*)(void*));

void llist_info_free(llist_info_t*);

typedef struct llist_s {
	void *head;
	llist_info_t *info;
	size_t count;
} llist_t;

llist_t *llist_init_default(llist_t*, llist_info_t*);

llist_t *llist_init_info(llist_t*, llist_info_t*, size_t, void (*)(void*));

void llist_free(llist_t*);

void llist_empty(llist_t*);

void *llist_add_elt(llist_t*, void*);

void *llist_alloc_and_add_elt(llist_t*);

// O(1)
void llist_del_eltp(llist_t*, void**);

void *llist_search_eltp(llist_t*, void*);

// O(n)
void llist_del_elt(llist_t*, void*);

void *llist_iterator(llist_t*, void *(*)(void*, void*), void*);

void *llist_iteratorp(llist_t*, void *(*)(void**, void*), void*);

size_t llist_get_count(llist_t*);

#endif /* INCLUDE_TAGMEISTER_LLIST_H */
