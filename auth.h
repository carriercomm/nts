/* RT/NTS -- a lightweight, high performance news transit server. */
/* 
 * Copyright (c) 2011, 2012 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */
/* $Header: /cvsroot/nts/auth.h,v 1.3 2012/01/07 16:47:17 river Exp $ */

#ifndef	NTS_AUTH_H
#define	NTS_AUTH_H

#include	"str.h"

extern int	auth_enabled;
extern int	allow_unauthed;
extern int	insecure_auth;

int	auth_init(void);
int	auth_run(void);

int	auth_check(str_t username, str_t password);
str_t	auth_hash_password(str_t pw);

#endif	/* !NTS_AUTH_H */
