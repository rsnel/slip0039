/* shashtbl.c - hashtable implementation
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
#include <stdint.h>
#include <assert.h>
#include "verbose.h"
#include "utils.h"
#include "shashtbl.h"

#define NO_BUCKETS (1<<s->key_bits)

//typedef int (*compare_t)(shashtbl_t*, const void*, shashtbl_elt_t*);

void *shashtbl_init_default(shashtbl_t *s, uint8_t key_bits, uint8_t unique, size_t size, void (*freer)(void*)) {
	int i;
	assert(s && key_bits >= 0 && key_bits <= 16 && size > sizeof(void*) && freer);
	assert(unique == 0 || unique == 1);

	s->key_bits = key_bits;

	if (!(s->buckets = calloc(sizeof(llist_t), NO_BUCKETS))) ERROR_errno("allocating buckets");

	init_error(llist_info, default, &s->li, size, freer);
	for (i = 0; i < NO_BUCKETS; i++) init_error(llist, default, &s->buckets[i], &s->li);

	s->unique = unique;

	return s;
}

void *shashtbl_init_simple(shashtbl_t *s, uint8_t key_bits, uint8_t unique) {
	int i;
	assert(s && key_bits >= 0 && key_bits <= 16);
	assert(unique == 0 || unique == 1);

	s->key_bits = key_bits;

	if (!(s->buckets = calloc(sizeof(llist_t), NO_BUCKETS))) ERROR_errno("allocating buckets");

	for (i = 0; i < NO_BUCKETS; i++) init_error(llist, default, &s->buckets[i], NULL);

	s->unique = unique;

	return s;
}

void shashtbl_free(shashtbl_t *s) {
	int i;
	int free_info = 0;
	if (s->buckets[0].info) free_info = 1;
	for (i = 0; i < NO_BUCKETS; i++) llist_free(&s->buckets[i]);
	if (free_info) llist_info_free(&s->li);
	free(s->buckets);
}

void shashtbl_empty(shashtbl_t *s) {
	int i;
	for (i = 0; i < NO_BUCKETS; i++) llist_empty(&s->buckets[i]);
}

/* function used for hashtables with strings as key */
static uint32_t hash_sdbm(const unsigned char *str) {
	uint32_t hash = 0;
	int c;

	while ((c = *str++)) hash = c + (hash<<6) + (hash<<16) - hash;

	return hash;
}

/* calculate bucket number belonging to key */
static inline llist_t *get_bucket(shashtbl_t *s, const char *key) {
	return &s->buckets[hash_sdbm((const unsigned char*)key)&(0xFFFFFFFF>>(32-s->key_bits))];
}

shashtbl_elt_t **shashtbl_search_eltp(shashtbl_t *s, void *elt) {
	return llist_search_eltp(get_bucket(s, ((shashtbl_elt_t*)elt)->key), elt);
}

static inline void *search_elt_bykey(void *ptr, void *key) {
	return strcmp(((shashtbl_elt_t*)ptr)->key, key)?NULL:ptr;
}

void *shashtbl_search_elt_bykey(shashtbl_t *s, const char *key) {
	return llist_iterator(get_bucket(s, key), search_elt_bykey, (char*)key);
}

static void *search_eltp_bykey(void **ptr, void *key) {
	return search_elt_bykey(*ptr, key)?ptr:NULL;
}

shashtbl_elt_t **shashtbl_search_eltp_bykey(shashtbl_t *s, const char *key) {
	return llist_iteratorp(get_bucket(s, key), search_eltp_bykey, (char*)key);
}

void *shashtbl_add_elt(shashtbl_t *s, void *ptr) {
	shashtbl_elt_t *elt = ptr;

	// if we only allow unique keys, search for the key of this
	// element and bail out if found
	if (s->unique && shashtbl_search_elt_bykey(s, elt->key)) return NULL;

	llist_add_elt(get_bucket(s, elt->key), elt);

	return elt;
}

void *shashtbl_alloc_and_add_elt(shashtbl_t *s, const char *key) {
	assert(s && key);
	shashtbl_elt_t *elt, *ret;;

	initp_fatal_errno(elt, malloc, s->li.size);
#ifndef NDEBUG
	elt->next = NULL;
#endif
	elt->key = key;

	if (!(ret = shashtbl_add_elt(s, elt))) free(elt);

	return ret;
}

void shashtbl_del_eltp(shashtbl_t *s, shashtbl_elt_t **eltp) {
	llist_del_eltp(get_bucket(s, (*eltp)->key), (void**)eltp);
}

void shashtbl_del_elt_bykey(shashtbl_t *s, const char *key) {
	shashtbl_elt_t **eltp;

	if (!(eltp = shashtbl_search_eltp_bykey(s, key)))
		BUG("element with key %s not found, so it why ask for deletion?", key);

	shashtbl_del_eltp(s, eltp);
}

void shashtbl_del_elt(shashtbl_t *s, void *elt) {
	llist_del_elt(get_bucket(s, ((shashtbl_elt_t*)elt)->key), elt);
}

void *shashtbl_iteratorp(shashtbl_t *s, void *(*func)(shashtbl_elt_t**, void*), void *arg) {
	int i;
	void *ret;

	for (i = 0; i < NO_BUCKETS; i++)
		if ((ret = llist_iteratorp(&s->buckets[i], (void *(*)(void**, void*))func, arg)))
			return ret;

	return NULL;
}

void *shashtbl_iterator(shashtbl_t *s, void *(*func)(void*, void*), void *arg) {
	int i;
	void *ret;

	for (i = 0; i < NO_BUCKETS; i++)
		if ((ret = llist_iterator(&s->buckets[i], (void *(*)(void*, void*))func, arg)))
			return ret;

	return NULL;
}

size_t shashtbl_get_count(shashtbl_t *s) {
	int i;
	size_t count = 0;

	for (i = 0; i < NO_BUCKETS; i++)
		count += llist_get_count(&s->buckets[i]);

	return count;
}
