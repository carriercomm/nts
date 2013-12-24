/* RT/NTS -- a lightweight, high performance news transit server. */
/* 
 * Copyright (c) 2011-2013 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */

#ifndef NTS_HISTORY_H
#define NTS_HISTORY_H

#include	"client.h"

int	history_init(void);
int	history_run(void);
void	history_shutdown(void);

/*
 * Look for a message in the history.  Return 1 if present or 0 if not.
 */
int	history_check(char const *mid);

/*
 * Add a message to the history.
 */
int	history_add(char const *mid);
int	history_add_multiple(char const **mids);

/*
 * Mark this article as pending.
 */
void	history_add_pending(char const *mid, void *);
void	history_clear_pending_for_client(void *);

#endif	/* !NTS_HISTORY_H */
