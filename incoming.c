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
#include	<ev.h>

#include	"incoming.h"
#include	"client.h"
#include	"log.h"
#include	"history.h"
#include	"emp.h"

static	pthread_t	incoming_thread;

static struct ev_loop	*incoming_loop;
ev_async		 incoming_ev;

typedef struct pending {
	client_t	*pe_client;
	char		*pe_text;
	char		*pe_msgid;
	struct pending	*pe_next;
} pending_t;

static pending_t	*pending_list;
pthread_mutex_t		 pending_mtx;

static void	*do_incoming(void *);
static void	 incoming_wakeup(struct ev_loop *, ev_async *, int);
static void	 handle_one_article(pending_t *);
static void	 incoming_reply(pending_t *, int);

int
incoming_init()
{
	incoming_loop = ev_loop_new(ev_supported_backends());
	ev_async_init(&incoming_ev, incoming_wakeup);
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
	ev_async_start(incoming_loop, &incoming_ev);
	ev_run(incoming_loop, 0);
	return NULL;
}

static void
incoming_wakeup(loop, w, revents)
	struct ev_loop	*loop;
	ev_async	*w;
{
pending_t	*list, *e, *next;

	pthread_mutex_lock(&pending_mtx);
	list = pending_list;
	pending_list = NULL;
	pthread_mutex_unlock(&pending_mtx);

	for (e = list, next = NULL; e; e = next) {
		handle_one_article(e);
		next = e->pe_next;
		free(e->pe_msgid);
		free(e->pe_text);
		free(e);
	}
}

static void
handle_one_article(pe)
	pending_t	*pe;
{
time_t		 age, oldest;
article_t	*article;
int		 filter_result;
char		*filter_name;

	if ((article = article_parse(pe->pe_text)) == NULL) {
		history_add(pe->pe_msgid);
		client_log(LOG_NOTICE, pe->pe_client,
			   "%s: cannot parse article",
			   pe->pe_msgid);
		log_article(pe->pe_msgid, NULL,
			    pe->pe_client->cl_server,
			    '-', "cannot-parse");
		incoming_reply(pe, IN_ERR_CANNOT_PARSE);
		return;
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
		return;
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
		return;
	}

	history_add(article->art_msgid);
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
		return;
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
	ev_async_send(incoming_loop, &incoming_ev);

	pthread_mutex_unlock(&pending_mtx);
}

static void
incoming_reply(pe, reason)
	pending_t	*pe;
{
	client_incoming_reply(pe->pe_client, reason);
}
