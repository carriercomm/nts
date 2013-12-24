/* RT/NTS -- a lightweight, high performance news transit server. */
/* 
 * Copyright (c) 2011-2013 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */

#ifndef	NTS_WILDMAT_H
#define	NTS_WILDMAT_H

#include	"config.h"
#include	"queue.h"

#define	WM_POISON	0x1
#define WM_NEGATE	0x2

typedef struct wildmat_entry {
	char	*wm_pattern;
	int	 wm_flags;

	SIMPLEQ_ENTRY(wildmat_entry)	 wm_list;
} wildmat_entry_t;

typedef SIMPLEQ_HEAD(wildmat, wildmat_entry) wildmat_t;

wildmat_t	*wildmat_from_value(conf_val_t *);
int		 wildmat_match(wildmat_t *, char const *);

#endif	/* !NTS_WILDMAT_H */
