/* RT/NTS -- a lightweight, high performance news transit server. */
/* 
 * Copyright (c) 2011 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */
/* $Header: /cvsroot/nts/wildmat.h,v 1.2 2011/12/28 23:03:19 river Exp $ */

#ifndef	NTS_WILDMAT_H
#define	NTS_WILDMAT_H

#include	"config.h"
#include	"str.h"
#include	"queue.h"

#define	WM_POISON	0x1
#define WM_NEGATE	0x2

typedef struct wildmat_entry {
	str_t				 wm_pattern;
	int				 wm_flags;
	struct wildmat			*wm_next;
	SIMPLEQ_ENTRY(wildmat_entry)	 wm_list;
} wildmat_entry_t;

typedef SIMPLEQ_HEAD(wildmat, wildmat_entry) wildmat_t;

wildmat_t	*wildmat_from_value(conf_val_t *);
int		 wildmat_match(wildmat_t *, str_t);

#endif	/* !NTS_WILDMAT_H */
