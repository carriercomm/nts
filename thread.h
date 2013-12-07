/* RT/NTS -- a lightweight, high performance news transit server. */
/* 
 * Copyright (c) 2011, 2012 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */
/* $Header: /cvsroot/nts/thread.h,v 1.2 2012/01/04 20:57:06 river Exp $ */

#ifndef	NTS_THREAD_H
#define	NTS_THREAD_H

typedef void *(*thr_work_fn) (void *);
typedef void  (*thr_done_fn) (void *);

int	thr_init(void);
int	thr_run(void);

/*
 * Call ret = wfn(wdata) in a worker thread, wait until it's finished, then call
 * dfn(ret) in the main thread.
 */
void	thr_do_work(thr_work_fn wfn, void *wdata, thr_done_fn dfn);

#endif	/* !NTS_THREAD_H */
