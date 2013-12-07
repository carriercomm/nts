/* RT/NTS -- a lightweight, high performance news transit server. */
/* 
 * Copyright (c) 2011 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */
/* $Header: /cvsroot/nts/crc.h,v 1.2 2011/12/28 23:03:19 river Exp $ */

#ifndef	NTS_CRC64_H
#define	NTS_CRC64_H

#include	<stdlib.h>

uint64_t	crc64(void const *, size_t);

#endif	/* !NTS_CRC64_H */
