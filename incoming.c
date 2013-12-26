/* RT/NTS -- a lightweight, high performance news transit server. */
/* 
 * Copyright (c) 2011-2013 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */

#include	<pthread.h>
#include	<uv.h>

#include	"incoming.h"
#include	"client.h"
#include	"log.h"
#include	"history.h"
#include	"emp.h"

static	pthread_t	incoming_thread;

static uv_loop_t	*incoming_loop;
uv_async_t		 incoming_ev;

typedef struct pending {
	client_t	*pe_client;
	char		*pe_text;
	char		*pe_msgid;
	struct pending	*pe_next;
} pending_t;

static pending_t	*pending_list;
pthread_mutex_t		 pending_mtx;
int			 npending;

static void	*do_incoming(void *);
static void	 incoming_wakeup(uv_async_t *, status);
static int	 handle_one_article(pending_t *);
static void	 incoming_reply(pending_t *, int);

int
incoming_init()
{
	incoming_loop = uv_loop_new();
	pthread_mutex_init(&pending_mtx, NULL);
	return 0;
}

void
incoming_run()
{
	pthread_create(&incoming_thread, NULL, do_incoming, NULL);
}

static void *
do_incoming(p)
	void	*p;
{
	uv_async_init(incoming_loop, &incoming_ev, incoming_wakeup);
	uv_run(incoming_loop, UV_RUN_DEFAULT);
	return NULL;
}

static void
incoming_wakeup(async, status)
	uv_async_t	*async;
{
pending_t	*list, *e, *next;
const char	**mids, **p;

	pthread_mutex_lock(&pending_mtx);
	list = pending_list;
	pending_list = NULL;
	mids = xcalloc(sizeof(char *), npending + 1);
	npending = 0;
	pthread_mutex_unlock(&pending_mtx);

	p = mids;

	for (e = list, next = NULL; e; e = next) {
		if (handle_one_article(e)) {
			*p = e->pe_msgid;
			p++;
		}

		next = e->pe_next;
	}

	history_add_multiple(mids);

	for (e = list, next = NULL; e; e = next) {
		free(e->pe_msgid);
		free(e->pe_text);
		free(e);
	}

	free(mids);
}

static int
handle_one_article(pe)
	pending_t	*pe;
{
time_t		 age, oldest;
article_t	*article;
int		 filter_result;
char		*filter_name;

	if ((article = article_parse(pe->pe_text)) == NULL) {
		client_log(LOG_NOTICE, pe->pe_client,
			   "%s: cannot parse article",
			   pe->pe_msgid);
		log_article(pe->pe_msgid, NULL,
			    pe->pe_client->cl_server,
			    '-', "cannot-parse");
		incoming_reply(pe, IN_ERR_CANNOT_PARSE);
		return 1;
	}

	age = (time(NULL) - article->art_date);
	oldest = history_remember - 60 * 60 * 24;
	if (age > oldest) {
		client_log(LOG_NOTICE, pe->pe_client,
			   "%s: too old (%d days)",
			   article->art_msgid,
			   (int) age / 60 / 60 / 24);
		log_article(article->art_msgid, NULL,
			    pe->pe_client->cl_server,
			    '-', "too-old");
		incoming_reply(pe, IN_ERR_TOO_OLD);
		return 0;
	}

	if (strcasecmp(article->art_msgid, pe->pe_msgid))
		client_log(LOG_WARNING, pe->pe_client,
			   "message-id mismatch: %s vs %s",
			   pe->pe_client->cl_msgid,
			   article->art_msgid);

	if (history_check(article->art_msgid)) {
		log_article(article->art_msgid, NULL,
			    pe->pe_client->cl_server,
			    '-', "duplicate");
		incoming_reply(pe, IN_ERR_DUPLICATE);
		return 0;
	}

	emp_track(article);

	filter_result = filter_article(article, pe->pe_client->cl_strname,
				&pe->pe_client->cl_server->se_filters_in,
				&filter_name);

	if (filter_result == FILTER_RESULT_DENY) {
		log_article(article->art_msgid, NULL,
			    pe->pe_client->cl_server, '-',
			    "filter/%s",
			    filter_name);
		incoming_reply(pe, IN_ERR_FILTER);
		return 1;
	}

	log_article(article->art_msgid, article->art_path,
		    pe->pe_client->cl_server, '+', NULL);
	article_munge_path(article);
	pe->pe_client->cl_server->se_in_accepted++;
	spool_store(article);
#if 0
	server_notify_article(article);
	if (article->art_refs == 0)
#endif
	article_free(article);
	incoming_reply(pe, IN_OK);
	return 1;
}

void
process_article(text, msgid, cl)
	char const	*text, *msgid;
	client_t	*cl;
{
pending_t	*pe = xcalloc(1, sizeof(*pe));

	pe->pe_text = xstrdup(text);
	pe->pe_msgid = xstrdup(msgid);
	pe->pe_client = cl;

	pthread_mutex_lock(&pending_mtx);

	pe->pe_next = pending_list;
	pending_list = pe;
	++npending;
	uv_async_send(&incoming_ev);

	pthread_mutex_unlock(&pending_mtx);
}

static void
incoming_reply(pe, reason)
	pending_t	*pe;
{
	client_incoming_reply(pe->pe_client, reason);
}
