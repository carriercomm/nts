/* RT/NTS -- a lightweight, high performance news transit server. */
/* 
 * Copyright (c) 2011, 2012 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */
/* $Header: /cvsroot/nts/balloc.c,v 1.9 2012/01/09 15:48:53 river Exp $ */

#include	<strings.h>
#include	<stdlib.h>

#include	"balloc.h"
#include	"nts.h"

#ifdef TEST_BALLOC
# define xmalloc(s)		malloc(s)
# define xcalloc(n,s)		calloc(n,s)
# include	<assert.h>
#endif

#if BALLOC_STATS
balloc_slist_t	balloc_list;
#endif

#if BALLOC_STATS
balloc_t *
balloc_new_impl(sz, nalloc, nm)
	size_t		 sz, nalloc;
	char const	*nm;
#else
balloc_t *
balloc_new_impl(sz, nalloc)
	size_t		 sz, nalloc;
#endif
{
balloc_t	*ba = xcalloc(1, sizeof(*ba));
	ba->ba_size = sz < sizeof(balloc_entry_t) ? sizeof(balloc_entry_t) : sz;
	ba->ba_nalloc = nalloc;

#if !BALLOC_ATOMIC || defined(BALLOC_STATS)
	pthread_mutex_init(&ba->ba_mtx, NULL);
#endif

#if BALLOC_STATS
	ba->ba_name = nm;
	SLIST_INSERT_HEAD(&balloc_list, ba, ba_slist);
#endif
	return ba;
}

void *
balloc(ba)
	balloc_t	*ba;
{
#if BALLOC_ATOMIC
balloc_entry_t	*head, *e, *be, *oldhead, *newhead;
# if BALLOC_STATS
	atomic_inc_ulong(&ba->ba_alloc);
#  if 0
	pthread_mutex_lock(&ba->ba_mtx);
	if ((ba->ba_alloc - ba->ba_free) > ba->ba_max)
		++ba->ba_max;
	pthread_mutex_unlock(&ba->ba_mtx);
#  endif
# endif
	while ((head = ba->ba_list.bl_head) != NULL) {
	balloc_entry_t	*next;
		next = head->be_next;
		if (atomic_cas_ptr(&ba->ba_list.bl_head,
				head, next) == head) {
			return head + 1;
		}
	}

	be = xmalloc(ba->ba_nalloc * ba->ba_size);
	for (e = be; e < be + ba->ba_nalloc - 2; e++)
		e->be_next = e + 1;
	e->be_next = NULL;

	do {
		oldhead = ba->ba_list.bl_head;
		e->be_next = oldhead;
		newhead = be;
	} while (atomic_cas_ptr(&ba->ba_list.bl_head, 
				oldhead, newhead) != oldhead);

	return be + (ba->ba_nalloc - 1);
#else
balloc_entry_t	*a;
	pthread_mutex_lock(&ba->ba_mtx);
	if (ba->ba_list.bl_head == NULL) {
	balloc_entry_t	*e, *be = xmalloc(ba->ba_nalloc * ba->ba_size);
		for (e = be; e < be + ba->ba_nalloc - 1; e++)
			e->be_next = e + 1;
		e->be_next = NULL;
		ba->ba_list.bl_head = e;
	}
	a = ba->ba_list.bl_head;
	ba->ba_list.bl_head = a->be_next;
	ba->ba_alloc++;
	if ((ba->ba_alloc - ba->ba_free) > ba->ba_max)
		ba->ba_max++;	
	pthread_mutex_unlock(&ba->ba_mtx);
	return (char *)a;
#endif
}

void *
bzalloc(ba)
	balloc_t	*ba;
{
void	*ret;
	ret = balloc(ba);
	bzero(ret, ba->ba_size);
	return ret;
}

void
bfree(ba, p)
	balloc_t	*ba;
	void		*p;
{
#if BALLOC_ATOMIC
balloc_entry_t	*be = (balloc_entry_t *)p,
		*oldhead;
	do {
		oldhead = ba->ba_list.bl_head;
		be->be_next = oldhead;
	} while (atomic_cas_ptr(&ba->ba_list.bl_head, 
				oldhead, be) != oldhead);
# if BALLOC_STATS
	atomic_inc_ulong(&ba->ba_free);
# endif
#else
balloc_entry_t	*be = (balloc_entry_t *) p;
	pthread_mutex_lock(&ba->ba_mtx);
	be->be_next = ba->ba_list.bl_head;
	ba->ba_list.bl_head = be;
# if BALLOC_STATS
	ba->ba_free++;
# endif
	pthread_mutex_unlock(&ba->ba_mtx);
#endif
}

#ifdef TEST_BALLOC
balloc_t	*ba;
int		 num = 1024;
void *
test_worker(arg)
	void *arg;
{
int	n = (uintptr_t) arg;
	for (;;) {
	uint32_t	**p;
	int		  i;
		p = calloc(sizeof(uint32_t *), num);
		for (i = 0; i < num; ++i) {
			p[i] = balloc(ba);
			*p[i] = 0x7E7E7E7E ^ ((n << 16) + i);
		}
		for (i = 0; i < num; ++i) {
			assert(*p[i] == 0x7E7E7E7E ^ ((n << 16) + i));
			bfree(ba, p[i]);
		}
		free(p);
	}
}


int
main()
{
int		 workers = 10;
	ba = balloc_new(sizeof(uint32_t), num / 2, "test");
	while (workers--) {
	pthread_t	id;
		pthread_create(&id, NULL, test_worker, (void *) (uintptr_t) workers);
	}
	sleep(3600);
}
#endif
