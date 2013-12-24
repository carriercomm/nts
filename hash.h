/* RT/NTS -- a lightweight, high performance news transit server. */
/* 
 * Copyright (c) 2011-2013 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */

#ifndef	NTS_HASH_H
#define NTS_HASH_H

#include	"queue.h"

typedef struct hash_item {
	LIST_ENTRY(hash_item)	 hi_link;
	void			*hi_key;
	size_t			 hi_keylen;
	void			*hi_data;
} hash_item_t;
typedef LIST_HEAD(hash_bucket, hash_item) hash_bucket_t;

typedef	void		(*hash_free_func)	(void *);
typedef uint32_t	(*hash_func)		(void const *, size_t);
typedef int		(*hash_compare_func)	(void const *a, void const *b,
						 size_t len);

typedef struct hash_table {
	hash_bucket_t		*ht_buckets;
	size_t			 ht_nbuckets;
	hash_func		 ht_hash;
	hash_compare_func	 ht_compare;
	hash_free_func		 ht_data_free;
} hash_table_t;

typedef struct hash_entry {
	char	*he_key;
	void	*he_data;
} hash_entry_t;

hash_table_t	*hash_new(size_t, hash_func, hash_compare_func,
			  hash_free_func data_free);
void		 hash_free(hash_table_t *);
void		*hash_find(hash_table_t *, void const *, size_t);
int		 hash_insert(hash_table_t *, void const *, size_t, void *);
void		*hash_remove(hash_table_t *, void const *, size_t);

#endif	/* !NTS_HASH_H */
