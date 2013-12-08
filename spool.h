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

#include	"str.h"

struct article;

typedef uint32_t spool_id_t;
typedef uint64_t spool_offset_t;

typedef struct spool_pos {
	spool_id_t	sp_id;
	spool_offset_t	sp_offset;
} spool_pos_t;

typedef struct spool_header {
	uint32_t	sa_magic;
	uint32_t	sa_len;
	uint8_t		sa_hdr_len;
	uint32_t	sa_flags;
	double		sa_emp_score;
	double		sa_phl_score;
	uint64_t	sa_crc;
	uint32_t	sa_text_len;
} spool_header_t;

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
 * Check the spool files for consistency.
 */
int	spool_check(void);

/*
 * Fetch an article from the spool.
 */
struct article	*spool_fetch(spool_id_t, spool_offset_t);
int		 spool_fetch_text(spool_id_t, spool_offset_t, spool_header_t *hdr, str_t*);
void		 spool_get_cur_pos(spool_pos_t *);

void	spool_shutdown(void);

extern int spool_do_sync;

#endif	/* !SPOOL_H */
