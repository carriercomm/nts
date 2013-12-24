/* RT/NTS -- a lightweight, high performance news transit server. */
/* 
 * Copyright (c) 2011-2013 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */

#include	"client.h"
#include	"queue.h"
#include	"hash.h"

static hash_table_t	*pending_list;

void
pending_init(void)
{
	if (!defer_pending)
		return;

	pending_list = hash_new(128, NULL, NULL, NULL);
}

void
pending_add(client, msgid)
	client_t	*client;
	char const	*msgid;
{
	if (!defer_pending)
		return;

	hash_insert(pending_list, msgid, strlen(msgid), client);
}

int
pending_check(msgid)
	char const	*msgid;
{
	if (!defer_pending)
		return 0;

	return hash_find(pending_list, msgid, strlen(msgid)) != NULL;
}

void
pending_remove(msgid)
	char const	*msgid;
{
	if (!defer_pending)
		return;

	hash_remove(pending_list, msgid, strlen(msgid));
}

void
pending_remove_client(client)
	client_t	*client;
{
hash_item_t	*ie, *next;
size_t		 i;

	if (!defer_pending)
		return;

	for (i = 0; i < pending_list->ht_nbuckets; i++) {
		LIST_FOREACH_SAFE(ie, &pending_list->ht_buckets[i], hi_link, next) {
			if (ie->hi_data == client) {
				LIST_REMOVE(ie, hi_link);
				free(ie->hi_key);
				free(ie);
			}
		}
	}
}
