/* RT/NTS -- a lightweight, high performance news transit server. */
/* 
 * Copyright (c) 2011 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */
/* $Header: /cvsroot/nts/history.h,v 1.3 2011/12/30 15:57:52 river Exp $ */

#ifndef NTS_HISTORY_H
#define NTS_HISTORY_H

#include	"client.h"
#include	"str.h"

int	history_init(void);
int	history_run(void);
void	history_shutdown(void);

/*
 * Look for a message in the history.  Return 1 if present or 0 if not.
 */
int	history_check(str_t mid);

/*
 * Add a message to the history.
 */
int	history_add(str_t mid);

/*
 * Mark this article as pending.
 */
void	history_add_pending(str_t mid, void *);
void	history_clear_pending_for_client(void *);

#endif	/* !NTS_HISTORY_H */
