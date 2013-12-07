/* RT/NTS -- a lightweight, high performance news transit server. */
/* 
 * Copyright (c) 2011 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */
/* $Header: /cvsroot/nts/filter.h,v 1.9 2012/01/04 20:59:07 river Exp $ */

#ifndef	NTS_FILTER_H
#define	NTS_FILTER_H

#include	"article.h"
#include	"wildmat.h"
#include	"queue.h"

#define	FILTER_ACT_DENY		0x0001
#define	FILTER_ACT_PERMIT	0x0002
#define	FILTER_ACT_DUNNO	0x0003
#define	FILTER_ACT_MASK		0x000F

#define	FILTER_LOG_REJECTED	0x0010
#define FILTER_USED		0x0020

typedef struct filter {
	str_t		 fi_name;
	wildmat_t	*fi_groups;
	strlist_t	 fi_paths;
	uint8_t		 fi_flags;
	uint32_t	 fi_art_types;
	short		 fi_emp_limit;
	short		 fi_emp_decay;
	short		 fi_phl_limit;
	short		 fi_phl_decay;
	short		 fi_max_crosspost;
	uint64_t	 fi_num_permit,
			 fi_num_deny,
			 fi_num_dunno;
	short		 fi_bit;
} filter_t;

typedef struct filter_list_entry {
	filter_t				*fle_filter;
	SIMPLEQ_ENTRY(filter_list_entry)	 fle_list;
} filter_list_entry_t;
typedef SIMPLEQ_HEAD(filter_list, filter_list_entry) filter_list_t;
extern filter_list_t filter_list;

typedef struct filter_group {
	str_t				 fg_name;
	filter_list_t			 fg_filters;
	SIMPLEQ_ENTRY(filter_group)	 fg_list;
} filter_group_t;
typedef SIMPLEQ_HEAD(filter_group_list, filter_group) filter_group_list_t;

extern int	 nfilters;

int		 filter_init(void);
int		 filter_run(void);
filter_t	*filter_find_by_name(char const *);
filter_group_t	*filter_group_find_by_name(char const *);

typedef enum {
	FILTER_RESULT_PERMIT = 0,
	FILTER_RESULT_DENY,
	FILTER_RESULT_DUNNO
} filter_result_t;

filter_result_t	 filter_article(article_t *, char const *, filter_list_t *, str_t *);
filter_result_t	 filter_article_one(article_t *, filter_t *);

void		 filter_shutdown(void);

#endif	/* !NTS_FILTER_H */
