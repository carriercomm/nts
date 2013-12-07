/* RT/NTS -- a lightweight, high performance news transit server. */
/* 
 * Copyright (c) 2011, 2012 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */
/* $Header: /cvsroot/nts/balloc.h,v 1.8 2012/01/05 14:02:30 river Exp $ */

#ifndef	NTS_BALLOC_H
#define	NTS_BALLOC_H

/*
 * balloc -- an efficient block allocator for allocating blocks of a fixed
 * size.
 */

#include	<strings.h>
#include	<stdlib.h>
#include	<pthread.h>

#include	"queue.h"
#include	"nts.h"

/* note: BALLOC_ATOMIC is suspected to be broken. */
#define BALLOC_ATOMIC	0
#define	BALLOC_STATS	1
#define	USE_BALLOC	0

#if !defined(ATOMIC)
# undef BALLOC_ATOMIC
# define BALLOC_ATOMIC 0
#endif

typedef struct balloc_entry {
	struct balloc_entry	*be_next;
} balloc_entry_t;

typedef struct {
	balloc_entry_t	*bl_head;
} balloc_entry_list_t;

typedef struct balloc {
	size_t			 ba_size;
	size_t			 ba_nalloc;
	balloc_entry_list_t	 ba_list;
#if !BALLOC_ATOMIC || defined(BALLOC_STATS)
	pthread_mutex_t		 ba_mtx;
#endif

#if BALLOC_STATS
	char const		*ba_name;
	unsigned long		 ba_alloc,
				 ba_free,
				 ba_max;
	SLIST_ENTRY(balloc)	 ba_slist;
#endif
} balloc_t;

#if BALLOC_STATS
typedef SLIST_HEAD(balloc_slist, balloc) balloc_slist_t;
extern balloc_slist_t balloc_list;
#endif

#if BALLOC_STATS
balloc_t	*balloc_new_impl(size_t sz, size_t nalloc, char const *name);
# define	 balloc_new(s,na,nm)	balloc_new_impl(s,na,nm)
#else
balloc_t	*balloc_new_impl(size_t sz, size_t nalloc);
# define	 balloc_new(s,na,nm)	balloc_new_impl(s,na)
#endif

void		*balloc(balloc_t *);
void		*bzalloc(balloc_t *);
void		 bfree(balloc_t *, void *);

#endif	/* !NTS_BALLOC_H */
