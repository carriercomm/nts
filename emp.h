/* RT/NTS -- a lightweight, high performance news transit server. */
/* 
 * Copyright (c) 2011, 2012 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */
/* $Header: /cvsroot/nts/emp.h,v 1.1 2012/01/04 20:59:07 river Exp $ */

#ifndef	NTS_EMP_H
#define	NTS_EMP_H

#include	"article.h"

int	emp_init(void);
int	emp_run(void);
void	emp_shutdown(void);

void	emp_track(article_t *);

extern int	do_emp_tracking;
extern int	do_phl_tracking;

#endif	/* !NTS_EMP_H */
