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

#include	"client.h"
#include	"log.h"
#include	"history.h"
#include	"emp.h"
#include	"incoming.h"

typedef struct reply {
	client_t	*re_client;
	int		 re_reason;
	struct reply	*re_next;
} reply_t;

static pthread_mutex_t	 reply_mtx = PTHREAD_MUTEX_INITIALIZER;
static reply_t		*reply_list;

ev_async		 reply_ev;

static void	client_handle_reply(client_t *, int);

void
c_takethis(client, cmd, line)
	client_t	*client;
	char		*cmd, *line;
{
char	*msgid = NULL;
	if ((msgid = next_word(&line)) == NULL || next_word(&line)) {
		/*
		 * We have to close the connection here because the
		 * client will be expecting to send a message after
		 * the command.
		 */
		client_printf(client, "501 Syntax: TAKETHIS <message-id>\r\n");
		client_log(LOG_INFO, client, "disconnected (missing message-id in TAKETHIS)");
		client->cl_state = CS_DEAD;
		return;
	}

	client->cl_state = CS_TAKETHIS;
	client->cl_msgid = xstrdup(msgid);

	client->cl_artsize = 0;
	client->cl_article[0] = 0;
}

void
client_takethis_done(client)
	client_t	*client;
{
int	 rejected = (client->cl_state == CS_TAKETHIS) ? 439 : 437;

#if 0
	pending_remove(client->cl_msgid);
#endif

	if (client->cl_artsize > max_article_size) {
		client->cl_server->se_in_rejected++;
		history_add(client->cl_msgid);
		client_log(LOG_INFO, client, "%s: too large (%d > %d)",
				client->cl_msgid,
				(int) client->cl_artsize,
				(int) max_article_size);
		client_printf(client, "%d %s\r\n", rejected, client->cl_msgid);
		log_article(client->cl_msgid, NULL, client->cl_server, '-', "too-large");
		goto err;
	}

	if (!valid_msgid(client->cl_msgid)) {
		client_printf(client, "%d %s\r\n", rejected, client->cl_msgid);
		goto err;
	}

	if (DEBUG(CIO))
		client_log(LOG_DEBUG, client,
			   "client %d takethis_done; process_article\n",
			   client->cl_fd);

	process_article(client->cl_article, client->cl_msgid, client);
	client->cl_flags |= CL_PENDING;
	ev_io_stop(client_loop, &client->cl_readable);
	return;

err:
	client->cl_state = CS_WAIT_COMMAND;
	free(client->cl_msgid);
	client->cl_msgid = NULL;
}

void	client_incoming_reply(client_t *, int);

void
client_incoming_reply(cl, reason)
	client_t	*cl;
{
reply_t	*reply = xcalloc(1, sizeof(*reply));
	reply->re_client = cl;
	reply->re_reason = reason;

	pthread_mutex_lock(&reply_mtx);
	reply->re_next = reply_list;
	reply_list = reply;
	ev_async_send(client_loop, &reply_ev);
	pthread_mutex_unlock(&reply_mtx);

}

void
client_do_replies(loop, w, revents)
	struct ev_loop	*loop;
	ev_async	*w;
{
reply_t	*list, *e, *next;

	pthread_mutex_lock(&reply_mtx);
	list = reply_list;
	reply_list = NULL;
	pthread_mutex_unlock(&reply_mtx);

	for (e = list, next = NULL; e; e = next) {
		next = e->re_next;
		client_handle_reply(e->re_client, e->re_reason);
		free(e);
		e = NULL;
	}
}

static void
client_handle_reply(cl, reason)
	client_t	*cl;
{
int	 rejected = (cl->cl_state == CS_TAKETHIS) ? 439 : 437;
int	 accepted = (cl->cl_state == CS_TAKETHIS) ? 239 : 235;

	if (DEBUG(CIO))
		client_log(LOG_DEBUG, cl, "client %d got process reply\n", cl->cl_fd);

	if (cl->cl_flags & (CL_DEAD | CL_DRAIN)) {
		client_destroy(cl);
		return;
	}

	cl->cl_flags &= ~CL_PENDING;
	ev_io_start(client_loop, &cl->cl_readable);

	if (reason == IN_OK)
		client_printf(cl, "%d %s\r\n",
			      accepted, cl->cl_msgid);
	else
		client_printf(cl, "%d %s\r\n",
			      rejected, cl->cl_msgid);

	cl->cl_state = CS_WAIT_COMMAND;
	free(cl->cl_msgid);
	cl->cl_msgid = NULL;

	cl->cl_flags &= ~CL_PAUSED;
	ev_io_start(client_loop, &cl->cl_readable);
}
