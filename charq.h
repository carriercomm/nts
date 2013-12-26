/* RT/NTS -- a lightweight, high performance news transit server. */
/* 
 * Copyright (c) 2011-2013 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */

#ifndef	NTS_CHARQ_H
#define	NTS_CHARQ_H

#include	<sys/types.h>

#include	"queue.h"

/*
 * A charq is a simple char buffer that allows efficient addition of data at the
 * end and removal of data at the start.  It can be used to implement network
 * buffering.
 *
 * A charq is actually a deque, but only queue operations are provided.
 */

typedef struct charq_ent {
	char	*cqe_data;
	size_t	 cqe_len;

	TAILQ_ENTRY(charq_ent)	 cqe_list;
} charq_ent_t;

typedef TAILQ_HEAD(charq_ent_list, charq_ent) charq_ent_list_t;

typedef struct charq {
	size_t		 cq_len;	/* Amount of data in q */
	size_t		 cq_offs;	/* Unused space in the first ent */
	charq_ent_list_t cq_ents;	/* List of ents */
} charq_t;

#define	cq_len(cq)		((cq)->cq_len)
#define	cq_used(cq)		((cq)->cq_len + (cq)->cq_offs)
#define	cq_first_ent(cq)	(TAILQ_FIRST(&(cq)->cq_ents))
#define	cq_last_ent(cq)		(TAILQ_LAST(&(cq)->cq_ents, charq_ent_list))

void	 cq_init(void);

charq_t	*cq_new(void);
void	 cq_free(charq_t *);

void	 cq_append(charq_t *, char *, size_t);
void	 cq_remove_start(charq_t *, size_t);
void	 cq_extract_start(charq_t *, void *buf, size_t);

char	 *cq_read_line(charq_t *);

#endif	/* !NTS_CHARQ_H */
