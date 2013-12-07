/* RT/NTS -- a lightweight, high performance news transit server. */
/* 
 * Copyright (c) 2011, 2012 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */
/* $Header: /cvsroot/nts/rfile.h,v 1.1 2012/01/02 01:33:49 river Exp $ */

#ifndef	NTS_RFILE_H
#define	NTS_RFILE_H

#include	<sys/types.h>
#include	<sys/stat.h>

#include	<time.h>
#include	<stdio.h>
#include	<stdarg.h>

/*
 * rfile -- a file that automatically rotates itself when the file is moved
 * or deleted.  Use it for log files.
 */

typedef struct rfile {
	FILE		*rf_file;
	char		*rf_name;
	time_t		 rf_last_stat;
	struct stat	 rf_stat;
} rfile_t;

rfile_t	*rfopen(char const *path, char const *mode);
void	 rfcheck(rfile_t *);
int	 rfprintf(rfile_t *, char const *, ...);
int	 rfputs(char const *, rfile_t *);
int	 vrfprintf(rfile_t *, char const *, va_list);
int	 rfclose(rfile_t *);

#define	rfflush(rf)	fflush((rf)->rf_file)

#endif	/* !NTS_RFILE_H */
