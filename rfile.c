/* RT/NTS -- a lightweight, high performance news transit server. */
/* 
 * Copyright (c) 2011, 2012 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */
/* $Header: /cvsroot/nts/rfile.c,v 1.2 2012/01/02 02:33:04 river Exp $ */

#include	<errno.h>
#include	<string.h>

#include	"rfile.h"
#include	"log.h"

void
rfcheck(rf)
	rfile_t	*rf;
{
	/* Check if we need to re-open the logfile. */
	if (time(NULL) - rf->rf_last_stat > 10) {
	dev_t	odev = rf->rf_stat.st_dev;
	ino_t	oino = rf->rf_stat.st_ino;
	off_t	osize = rf->rf_stat.st_size;

		if (stat(rf->rf_name, &rf->rf_stat) == -1 || (
		    (odev != rf->rf_stat.st_dev ||
		     oino != rf->rf_stat.st_ino ||
		     osize > rf->rf_stat.st_size))) {
		FILE	*nfile;
			if ((nfile = fopen(rf->rf_name, "a")) == NULL) {
				nts_log("%s: cannot re-open: %s",
					rf->rf_name, strerror(errno));
			} else {
				fclose(rf->rf_file);
				rf->rf_file = nfile;
				nts_log("\"%s\": rotated",
					rf->rf_name);
			}

			stat(rf->rf_name, &rf->rf_stat);
		}

		rf->rf_last_stat = time(NULL);
	}
}

int
rfprintf(rfile_t *rf, char const *fmt, ...)
{
va_list	ap;
int	ret;
	va_start(ap, fmt);
	ret = vrfprintf(rf, fmt, ap);
	va_end(ap);
	return ret;
}

int
vrfprintf(rf, fmt, ap)
	rfile_t		*rf;
	char const	*fmt;
	va_list		 ap;
{
	return vfprintf(rf->rf_file, fmt, ap);
}

rfile_t *
rfopen(path, mode)
	char const	*path, *mode;
{
FILE	*f;
rfile_t	*rf;

	if ((f = fopen(path, mode)) == NULL)
		return NULL;

	rf = xcalloc(1, sizeof(*rf));
	rf->rf_name = xstrdup(path);
	rf->rf_file = f;

	if (fstat(fileno(f), &rf->rf_stat) == -1) {
		nts_log("\"%s\": cannot fstat: %s",
			path, strerror(errno));
		free(rf);
		fclose(f);
		return NULL;
	}

	rf->rf_last_stat = time(NULL);
	return rf;
}

int
rfputs(str, rf)
	char const	*str;
	rfile_t		*rf;
{
	return fputs(str, rf->rf_file);
}

int
rfclose(rf)
	rfile_t	*rf;
{
int	ret;
	ret = fclose(rf->rf_file);
	free(rf);
	return ret;
}
