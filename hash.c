/* RT/NTS -- a lightweight, high performance news transit server. */
/* 
 * Copyright (c) 2011 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */
/* $Header: /cvsroot/nts/hash.c,v 1.5 2012/01/10 17:14:13 river Exp $ */
/* $NetBSD: hcreate.c,v 1.6 2008/07/21 12:05:43 lukem Exp $ */

/*
 * Copyright (c) 2001 Christopher G. Demetriou
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *          This product includes software developed for the
 *          NetBSD Project.  See http://www.NetBSD.org/ for
 *          information about NetBSD.
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 * <<Id: LICENSE,v 1.2 2000/06/14 15:57:33 cgd Exp>>
 */

/*
 * hcreate() / hsearch() / hdestroy()
 *
 * SysV/XPG4 hash table functions.
 *
 * Implementation done based on NetBSD manual page and Solaris manual page,
 * plus my own personal experience about how they're supposed to work.
 *
 * I tried to look at Knuth (as cited by the Solaris manual page), but
 * nobody had a copy in the office, so...
 */

#include	<assert.h>
#include	<errno.h>
#include	<inttypes.h>
#include	<search.h>
#include	<stdlib.h>
#include	<string.h>

#include	"queue.h"
#include	"hash.h"
#include	"nts.h"

#define	MIN_BUCKETS_LG2	4
#define	MIN_BUCKETS	(1 << MIN_BUCKETS_LG2)

/*
 * max * sizeof internal_entry must fit into size_t.
 * assumes internal_entry is <= 32 (2^5) bytes.
 */
#define	MAX_BUCKETS_LG2	(sizeof (size_t) * 8 - 1 - 5)
#define	MAX_BUCKETS	((size_t)1 << MAX_BUCKETS_LG2)

static uint32_t nts_hash4(const void *, size_t);

hash_table_t *
hash_new(nel, hf, cf, df)
	size_t			nel;
	hash_func		hf;
	hash_compare_func	cf;
	hash_free_func		df;
{
unsigned int	 p2;
hash_table_t	*table;

	/* If nel is too small, make it min sized. */
	if (nel < MIN_BUCKETS)
		nel = MIN_BUCKETS;

	/* If it's too large, cap it. */
	if (nel > MAX_BUCKETS)
		nel = MAX_BUCKETS;

	/* If it's is not a power of two in size, round up. */
	if ((nel & (nel - 1)) != 0) {
		for (p2 = 0; nel != 0; p2++)
			nel >>= 1;
		nel = 1 << p2;
	}

	if (hf == NULL)
		hf = nts_hash4;
	if (cf == NULL)
		cf = memcmp;
	table = xcalloc(1, sizeof(*table));
	
	table->ht_data_free = df;
	table->ht_hash = hf;
	table->ht_compare = cf;

	/* Allocate the table. */
	table->ht_nbuckets = nel;
	table->ht_buckets = xcalloc(nel, sizeof(*table->ht_buckets));

	return table;
}

void
hash_free(table)
	hash_table_t	*table;
{
hash_item_t	*ie;
size_t		 idx;

	for (idx = 0; idx < table->ht_nbuckets; idx++) {
		while (!LIST_EMPTY(&table->ht_buckets[idx])) {
			ie = LIST_FIRST(&table->ht_buckets[idx]);
			LIST_REMOVE(ie, hi_link);
			free(ie->hi_key);
			if (table->ht_data_free)
				table->ht_data_free(ie->hi_data);
			free(ie);
		}
	}

	free(table);
}

void *
hash_find(table, key, keylen)
	hash_table_t	*table;
	void const	*key;
	size_t		 keylen;
{
uint32_t	 h;
hash_bucket_t	*head;
hash_item_t	*ie;

	h = table->ht_hash(key, keylen) & (table->ht_nbuckets - 1);
	assert(h < table->ht_nbuckets);
	head = &table->ht_buckets[h];

	LIST_FOREACH(ie, head, hi_link) {
		if (ie->hi_keylen != keylen)
			continue;
		if (table->ht_compare(ie->hi_key, key, keylen) == 0)
			return ie;
	}
	
	return NULL;
}

int
hash_insert(table, key, keylen, value)
	hash_table_t	*table;
	void const	*key;
	size_t		 keylen;
	void		*value;
{
uint32_t	 h;
hash_bucket_t	*head;
hash_item_t	*ie;

	h = table->ht_hash(key, keylen) & (table->ht_nbuckets - 1);
	assert(h < table->ht_nbuckets);
	head = &table->ht_buckets[h];

	LIST_FOREACH(ie, head, hi_link) {
		if (ie->hi_keylen != keylen)
			continue;

		if (table->ht_compare(ie->hi_key, key, keylen) == 0)
			return 0;
	}

	ie = xcalloc(1, sizeof(*ie));
	ie->hi_key = xcalloc(1, keylen);
	bcopy(key, ie->hi_key, keylen);
	ie->hi_keylen = keylen;
	ie->hi_data = value;

	LIST_INSERT_HEAD(head, ie, hi_link);
	return 1;
}

void*
hash_remove(table, key, keylen)
	hash_table_t	*table;
	void const	*key;
	size_t		 keylen;
{
uint32_t	 h;
hash_bucket_t	*head;
hash_item_t	*ie;

	h = nts_hash4(key, keylen) & (table->ht_nbuckets - 1);
	assert(h < table->ht_nbuckets);
	head = &table->ht_buckets[h];

	LIST_FOREACH(ie, head, hi_link) {
		if (keylen != ie->hi_keylen)
			continue;
		if (table->ht_compare(key, ie->hi_key, keylen))
			continue;

		if (table->ht_data_free)
			table->ht_data_free(ie->hi_data);
		LIST_REMOVE(ie, hi_link);
		free(ie->hi_key);
		free(ie);
		return ie->hi_data;
	}

	return NULL;
}

/*	$NetBSD: hash_func.c,v 1.13 2008/09/10 17:52:35 joerg Exp $	*/

/* Hash function from Chris Torek. */
static uint32_t
nts_hash4(keyarg, len)
	const void	*keyarg;
	size_t		 len;
{
const uint8_t	*key;
size_t		 loop;
uint32_t	 h;

#define HASH4a   h = (h << 5) - h + *key++;
#define HASH4b   h = (h << 5) + h + *key++;
#define HASH4 HASH4b

	h = 0;
	key = keyarg;
	if (len > 0) {
		loop = (len + 8 - 1) >> 3;

		switch (len & (8 - 1)) {
		case 0:
			do {	HASH4;
		case 7:		HASH4;
		case 6:		HASH4;
		case 5:		HASH4;
		case 4:		HASH4;
		case 3:		HASH4;
		case 2:		HASH4;
		case 1:		HASH4;
			} while (--loop);
		}
	}
	return (h);
}
