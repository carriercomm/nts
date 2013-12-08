/* RT/NTS -- a lightweight, high performance news transit server. */
/* 
 * Copyright (c) 2012 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */
/* $Header: /cvsroot/nts/thread.c,v 1.3 2012/01/05 14:02:30 river Exp $ */

#include	<pthread.h>
#include	<errno.h>
#include	<ev.h>

#include	"thread.h"
#include	"log.h"
#include	"nts.h"
#include	"net.h"
#include	"balloc.h"

static pthread_t	*threads;
static balloc_t		*ba_wu;

static void	*worker_run(void *);
static void	 work_done(struct ev_loop *, ev_async *, int);

typedef struct workunit {
	thr_work_fn		 wu_wfn;
	void			*wu_wdata;
	thr_done_fn		 wu_dfn;
	void			*wu_ddata;
	TAILQ_ENTRY(workunit)	 wu_list;
} workunit_t;

typedef TAILQ_HEAD(workunit_list, workunit) worklist_t;
static worklist_t	 workunits, donework;
static pthread_mutex_t   done_mtx;
static pthread_cond_t	 work_cond;
static pthread_mutex_t	 work_mtx;
static struct ev_loop	*loop;

static ev_async	wakeup;

int
thr_init()
{
	ba_wu = balloc_new(sizeof(workunit_t), 128, "workunit_t");
	pthread_mutex_init(&done_mtx, NULL);
	pthread_mutex_init(&work_mtx, NULL);
	pthread_cond_init(&work_cond, NULL);
	TAILQ_INIT(&workunits);
	TAILQ_INIT(&donework);
	loop = EV_DEFAULT;
	ev_async_init(&wakeup, work_done);
	return 0;
}

int
thr_run()
{
int		i;
pthread_attr_t	attr;

	if (worker_threads == 0)
		return 0;

	pthread_attr_init(&attr);
	pthread_attr_setstacksize(&attr, 65535);

	threads = xcalloc(worker_threads, sizeof(*threads));
	for (i = 0; i < worker_threads; ++i) {
		if (pthread_create(&threads[i], &attr,
				worker_run, NULL) == -1) {
			nts_log(LOG_ERR, "cannot create worker thread: %s",
					strerror(errno));
			return -1;
		}
	}

	ev_async_start(loop, &wakeup);
	return 0;
}

typedef struct thr_dispatch_data {
	thr_work_fn	 wfn;
	thr_done_fn	 dfn;
	void		*wdata;
} thr_dispatch_data_t;

void
thr_dispatch_work(udata)
	void	*udata;
{
thr_dispatch_data_t	*d = udata;
void			*r;

	r = d->wfn(d->wdata);
	if (d->dfn)
		d->dfn(r);
}

void
thr_do_work(wfn, wdata, dfn)
	thr_work_fn	 wfn;
	thr_done_fn	 dfn;
	void		*wdata;
{
workunit_t	*work;

	if (worker_threads == 0) {
		thr_dispatch_data_t	*d = xcalloc(1, sizeof(*d));
		d->wfn = wfn;
		d->dfn = dfn;
		d->wdata = wdata;
		net_soon(thr_dispatch_work, d);
		return;
	}

	work = bzalloc(ba_wu);
	work->wu_wfn = wfn;
	work->wu_wdata = wdata;
	work->wu_dfn = dfn;

	pthread_mutex_lock(&work_mtx);
	TAILQ_INSERT_TAIL(&workunits, work, wu_list);
	pthread_cond_signal(&work_cond);
	pthread_mutex_unlock(&work_mtx);
}

static void *
worker_run(udata)
	void	*udata;
{
	for (;;) {
	workunit_t	*work;

		pthread_mutex_lock(&work_mtx);
		while (TAILQ_EMPTY(&workunits))
			pthread_cond_wait(&work_cond, &work_mtx);

		work = TAILQ_FIRST(&workunits);
		TAILQ_REMOVE(&workunits, work, wu_list);
		pthread_mutex_unlock(&work_mtx);

		work->wu_ddata = work->wu_wfn(work->wu_wdata);

		pthread_mutex_lock(&done_mtx);
		TAILQ_INSERT_TAIL(&donework, work, wu_list);
		pthread_mutex_unlock(&done_mtx);

		ev_async_send(loop, &wakeup);
	}

	return NULL;
}

static void
work_done(loop, w, events)
	struct ev_loop	*loop;
	ev_async	*w;
{
workunit_t	*work;
worklist_t	 l;

	TAILQ_INIT(&l);
	pthread_mutex_lock(&done_mtx);
	TAILQ_CONCAT(&l, &donework, wu_list);
	pthread_mutex_unlock(&done_mtx);
	while (work = TAILQ_FIRST(&l)) {
		if (work->wu_dfn)
			work->wu_dfn(work->wu_ddata);
		TAILQ_REMOVE(&l, work, wu_list);
		bfree(ba_wu, work);
	}
}
