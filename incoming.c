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

typedef struct incoming_work {
	artbuf_t	*iw_artbuf;
	int		 iw_status;
} incoming_work_t;

static int	 handle_one_article(incoming_work_t *);

static void	 on_new_work(uv_work_t *);
static void	 on_work_done(uv_work_t *, status);

int
incoming_init()
{
	return 0;
}

void
incoming_run()
{
}

static void
on_new_work(req)
	uv_work_t	*req;
{
incoming_work_t	*iw = req->data;

	iw->iw_status = handle_one_article(iw);
}

static int
handle_one_article(iw)
	incoming_work_t	*iw;
{
time_t		 age, oldest;
article_t	*article;
int		 filter_result;
char		*filter_name;
artbuf_t	*buf = iw->iw_artbuf;

	if ((article = article_parse(buf->ab_text)) == NULL) {
		client_log(LOG_NOTICE, buf->ab_client,
			   "%s: cannot parse article",
			   buf->ab_msgid);
		log_article(buf->ab_msgid, NULL,
			    buf->ab_client->cl_server,
			    '-', "cannot-parse");
		history_add(buf->ab_msgid);
		return IN_ERR_CANNOT_PARSE;
	}

	age = (time(NULL) - article->art_date);
	oldest = history_remember - 60 * 60 * 24;
	if (age > oldest) {
		client_log(LOG_NOTICE, buf->ab_client,
			   "%s: too old (%d days)",
			   article->art_msgid,
			   (int) age / 60 / 60 / 24);
		log_article(article->art_msgid, NULL,
			    buf->ab_client->cl_server,
			    '-', "too-old");
		return IN_ERR_TOO_OLD;
	}

	if (strcasecmp(article->art_msgid, buf->ab_msgid))
		client_log(LOG_WARNING, buf->ab_client,
			   "message-id mismatch: %s vs %s",
			   buf->ab_msgid,
			   article->art_msgid);

	if (history_check(article->art_msgid)) {
		log_article(article->art_msgid, NULL,
			    buf->ab_client->cl_server,
			    '-', "duplicate");
		return IN_ERR_DUPLICATE;
	}

	emp_track(article);

	filter_result = filter_article(article, buf->ab_client->cl_strname,
				&buf->ab_client->cl_server->se_filters_in,
				&filter_name);

	if (filter_result == FILTER_RESULT_DENY) {
		log_article(article->art_msgid, NULL,
			    buf->ab_client->cl_server, '-',
			    "filter/%s",
			    filter_name);
		history_add(buf->ab_msgid);
		return IN_ERR_FILTER;
	}

	log_article(article->art_msgid, article->art_path,
		    buf->ab_client->cl_server, '+', NULL);
	article_munge_path(article);
	buf->ab_client->cl_server->se_in_accepted++;
	spool_store(article);
#if 0
	server_notify_article(article);
	if (article->art_refs == 0)
#endif
	article_free(article);
	history_add(buf->ab_msgid);
	return IN_OK;
}

void
process_article(artbuf)
	artbuf_t	*artbuf;
{
incoming_work_t	*iw = xcalloc(1, sizeof(*iw));
uv_work_t	*req = xcalloc(1, sizeof(*req));

	iw->iw_artbuf = artbuf;
	req->data = iw;

	uv_queue_work(loop, req, on_new_work, on_work_done);
}

static void
on_work_done(req, status)
	uv_work_t	*req;
{
incoming_work_t	*iw = req->data;

	client_incoming_reply(iw->iw_artbuf->ab_client, iw->iw_artbuf, iw->iw_status);
	free(iw);
	free(req);
}
