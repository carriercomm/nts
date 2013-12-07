/* RT/NTS -- a lightweight, high performance news transit server. */
/* 
 * Copyright (c) 2012 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */
/* $Header: /cvsroot/nts/base64.h,v 1.2 2012/01/08 18:32:20 river Exp $ */

#ifndef	NTS_BASE64_H
#define	NTS_BASE64_H

#include	<stdlib.h>
#define	base64_encode_len(n)	(4 * ((n + 2) / 3))
#define	base64_decode_len(n)	(3 * ((n + 3) / 4))

void	base64_encode(unsigned char const *inbuf, size_t inlen, char *outbuf);
ssize_t	base64_decode(char const *inbuf, size_t inlen, unsigned char *outbuf);

#endif	/* !NTS_BASE64_H */
