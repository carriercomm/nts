/* RT/NTS -- a lightweight, high performance news transit server. */
/* 
 * Copyright (c) 2011 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */
/* $Header: /cvsroot/nts/spool.h,v 1.8 2012/01/10 00:22:32 river Exp $ */

#ifndef	SPOOL_H
#define	SPOOL_H

#include	<inttypes.h>

struct article;

typedef uint32_t spool_id_t;
typedef uint64_t spool_offset_t;

typedef struct spool_pos {
	spool_id_t	sp_id;
	spool_offset_t	sp_offset;
} spool_pos_t;

int	spool_init(void);
int	spool_run(void);

/*
 * Open the spool in the specified path.  Returns 0 on success or -1 on 
 * failure.
 */
int	spool_open(char const *path);

/*
 * Close the spool.
 */
void	spool_close(void);

/*
 * Store the given article in the spool.  Returns 0 on success or -1 on 
 * failure.
 */
int	spool_store(struct article *);

/*
 * Fetch an article from the spool.
 */
struct article	*spool_fetch(spool_id_t, spool_offset_t);
void		 spool_get_cur_pos(spool_pos_t *);

void	spool_shutdown(void);

#endif	/* !SPOOL_H */
