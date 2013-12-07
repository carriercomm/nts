/* RT/NTS -- a lightweight, high performance news transit server. */
/* 
 * Copyright (c) 2011, 2012 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */
/* $Header: /cvsroot/nts/crypt.h,v 1.1 2012/01/04 06:04:34 river Exp $ */

#ifndef	NTS_CRYPT_H
#define	NTS_CRYPT_H

#include	<stdlib.h>

char	*nts_crypt(char const *, char const *);
char	*nts_crypt_blowfish(char const *, char const *);
char	*nts_crypt_sha1(char const *, char const *);
char	*nts_crypt_md5(char const *, char const *);
int	 nts_gensalt(char *salt, size_t saltlen, const char *type, const char *option);

#define	PASSWORD_NONDES	'$'
#define	PASSWORD_EFMT1	'_'
#define	PASSWORD_LEN	128

#endif	/* !NTS_CRYPT_H */
