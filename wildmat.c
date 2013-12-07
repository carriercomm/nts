/* RT/NTS -- a lightweight, high performance news transit server. */
/* 
 * Copyright (c) 2011 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */
/* $Header: /cvsroot/nts/wildmat.c,v 1.2 2011/12/28 23:03:19 river Exp $ */

#include	<stdlib.h>
#include	<stdio.h>

#include	"wildmat.h"
#include	"nts.h"

wildmat_t *
wildmat_from_value(value)
	conf_val_t	*value;
{
wildmat_t	*list = xcalloc(1, sizeof(*list));

	SIMPLEQ_INIT(list);

	for (; value; value = value->cv_next) {
	wildmat_entry_t	*m = xcalloc(1, sizeof(*m));
	char		*v = value->cv_string;

		if (*v == '!') {
			m->wm_flags |= WM_NEGATE;
			v++;
		} else if (*v == '@') {
			m->wm_flags |= WM_POISON;
			v++;
		}

		m->wm_pattern = str_new_c(v);
		SIMPLEQ_INSERT_TAIL(list, m, wm_list);
	}

	return list;
}

int
wildmat_match(wm, str)
	wildmat_t	*wm;
	str_t		 str;
{
wildmat_entry_t	*wme;
int		 match = 0;

	SIMPLEQ_FOREACH(wme, wm, wm_list) {
		if (!str_match(str, wme->wm_pattern))
			continue;
		if (wme->wm_flags & WM_POISON)
			return 0;
		else if (wme->wm_flags & WM_NEGATE)
			match = 0;
		else
			match = 1;
	}

	return match;
}
