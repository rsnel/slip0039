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

#include <assert.h>
#include <errno.h>
#include <string.h>
#include "verbose.h"
#include "utils.h"
#include "llist.h"

#define ASSERT_SANE_LLIST_INFO() assert(li && li->freer && li->size > sizeof(void*))
#define ASSERT_SANE_LLIST() assert(l && (!l->info || (l->info->freer && l->info->size > sizeof(void*))) && ((l->count == 0 && !l->head) || (l->count > 0 && l->head)))

llist_info_t *llist_info_init_default(llist_info_t *li, size_t size, void(*freer)(void*)) {
	assert(li);
	li->size = size;
	li->freer = freer;

	ASSERT_SANE_LLIST_INFO();

	return li;
}

void llist_info_free(llist_info_t *li) {
	ASSERT_SANE_LLIST_INFO();
}

llist_t *llist_init_default(llist_t *l, llist_info_t *li) {
	assert(l);

	l->head = NULL;
	l->info = li;
	l->count = 0;

	ASSERT_SANE_LLIST();

	return l;
}

llist_t *llist_init_info(llist_t *l, llist_info_t *li, size_t size, void (*freer)(void*)) {
	init_error(llist_info, default, li, size, freer);
	init_error(llist, default, l, li);
	return l;
}

void llist_free(llist_t *l) {
	ASSERT_SANE_LLIST();
	void *elt, *next = l->head;

	if (!l->info) return;

	while ((elt = next)) {
		next = *(void**)elt;
		l->info->freer(elt);
	}
}

void llist_empty(llist_t *l) {
	ASSERT_SANE_LLIST();

	llist_free(l);

	l->head = NULL;
	l->count = 0;
}

void *llist_add_elt(llist_t *l, void *elt) {
	ASSERT_SANE_LLIST();
	assert(elt && !*(void**)elt);

	*(void**)elt = l->head;
	l->head = elt;

	l->count++;

	return elt;
}

void *llist_alloc_and_add_elt(llist_t *l) {
	ASSERT_SANE_LLIST();
	void *elt;

	assert(l->info);

	initp_error_errno(malloc, elt, l->info->size);
#ifndef NDEBUG // keep assert() happy if active
	*(void**)elt = NULL;
#endif

	return llist_add_elt(l, elt);
}

void llist_del_eltp(llist_t *l, void **eltp) {
	void *next;
	ASSERT_SANE_LLIST();
	l->count--;
	next = *(void**)*eltp;
#ifndef NDEBUG // keep assert() happy if active
	*(void**)*eltp = NULL;
#endif
	if (l->info) l->info->freer(*eltp);

	*eltp = next;
}

static void *search_eltp(void **eltp, void *target) {
	assert(eltp && *eltp && target);
	if (target == *eltp) return eltp;

	return NULL;
}

void *llist_search_eltp(llist_t *l, void *elt) {
	void **eltp;
	ASSERT_SANE_LLIST();

	if (!(eltp = llist_iteratorp(l, search_eltp, elt)))
		BUG("didn't find something that should have been in the list");

	return eltp;
}

void llist_del_elt(llist_t *l, void *elt) {
	ASSERT_SANE_LLIST();

	llist_del_eltp(l, llist_search_eltp(l, elt));
}

void *llist_iterator(llist_t *l, void *(*func)(void*, void*), void *arg) {
	ASSERT_SANE_LLIST();
	assert(func);

	void *next = l->head, *elt, *ret;

	while ((elt = next)) {
		next = *(void**)elt;
		if ((ret = func(elt, arg))) return ret;
	}

	return NULL;
}

void *llist_iteratorp(llist_t *l, void *(*func)(void**, void*), void *arg) {
	ASSERT_SANE_LLIST();
	assert(func);

	void **eltp = &l->head, *ret, *prev;

	while (*eltp) {
		prev = *eltp;
		if ((ret = func(eltp, arg))) return ret;
		if (prev != *eltp) continue;
		eltp = (void**)*eltp;
	}

	return NULL;
}

size_t llist_get_count(llist_t *l) {
	ASSERT_SANE_LLIST();
	return l->count;
}


