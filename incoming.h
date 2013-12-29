/* RT/NTS -- a lightweight, high performance news transit server. */
/* 
 * Copyright (c) 2011-2013 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */

#ifndef NTS_INCOMING_H
#define NTS_INCOMING_H

#include	"client.h"

#define	IN_OK			0
#define	IN_ERR_TOO_OLD		1
#define	IN_ERR_FILTER		2
#define	IN_ERR_DUPLICATE	3
#define	IN_ERR_CANNOT_PARSE	4

struct artbuf;
void	process_article(client_t *, artbuf_t *);

int	incoming_init(void);
void	incoming_run(void);

#endif	/* !NTS_INCOMING_H */
