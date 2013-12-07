/* RT/NTS -- a lightweight, high performance news transit server. */
/* 
 * Copyright (c) 2011-2013 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */

#ifndef	NTS_ARTICLE_H
#define	NTS_ARTICLE_H

#include	<inttypes.h>

#include	"str.h"
#include	"queue.h"
#include	"spool.h"
#include	"bitset.h"

/*
 * An article.
 */

#define	ART_SPAM		0x00000001
#define	ART_CONTROL		0x00000002	/* Has a Control: header */
#define	ART_REPLY		0x00000004	/* Has a References: header */
#define ART_MIME		0x00000008	/* Has a MIME-Version: header */
#define ART_MIME_MULTIPART	0x00000010	/* MIME type is multipart/mixed */
#define	ART_CRC			0x00000020	/* Calculated CRC */

#define ART_FILTERED		0x00010000

#define	ART_TYPE_MIME_BINARY	0x00100000
#define ART_TYPE_YENC		0x00200000
#define	ART_TYPE_UUE		0x00400000
#define	ART_TYPE_BINARY		0x00F00000

#define	ART_TYPE_MIME_TEXT	0x01000000
#define ART_TYPE_HTML		0x02000000
#define ART_TYPE_ODD_TEXT	0x0F000000

#define	ART_COMPRESSED		0x10000000	/* (spool) Article is compressed */

typedef struct article {
	str_t		 art_path;
	str_t		 art_msgid;
	str_t		 art_content;
	str_t		 art_body;
	str_t		 art_posting_host;
	str_t		 art_newsgroups;
	strlist_t	 art_groups;
	int		 art_ngroups;
	int		 art_nfollowups;
	double		 art_emp_score;
	double		 art_phl_score;
	uint16_t	 art_lines;
	uint32_t	 art_flags;
	time_t		 art_date;
	spool_pos_t	 art_spool_pos;
	uint16_t	 art_hdr_len;
	int		 art_refs;
	bs_word_t	*art_filters;
} article_t;

void		article_init(void);
void		article_run(void);

/*
 * Parse an article in wire form and return a parsed version.
 */
article_t	*article_parse(str_t);

/*
 * Add our name to an article's Path: header
 */
void		 article_munge_path(article_t *);

/*
 * Free an article.
 */
void		 article_free(article_t *art);

int		 article_path_contains(article_t *, str_t);
int		 valid_msgid(str_t);

#define	art_deref(art)				\
	do {					\
		if (--art->art_refs == 0)	\
		article_free(art);		\
	} while (0) 

#endif	/* !NTS_ARTICLE_H */
