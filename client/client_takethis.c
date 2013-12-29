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

void
c_takethis(client, cmd, line)
	client_t	*client;
	char		*cmd, *line;
{
char		*msgid = NULL;
artbuf_t	*buf;

	if ((msgid = next_word(&line)) == NULL || next_word(&line)) {
		/*
		 * We have to close the connection here because the
		 * client will be expecting to send a message after
		 * the command.
		 */
		client_printf(client, "501 Syntax: TAKETHIS <message-id>\r\n");
		client_log(LOG_INFO, client, "disconnected (missing message-id in TAKETHIS)");
		client_close(client, 1);
		return;
	}

	buf = xcalloc(1, sizeof(*buf));
	buf->ab_msgid = xstrdup(msgid);
	buf->ab_alloc = ARTBUF_START_SIZE;
	buf->ab_text = xmalloc(buf->ab_alloc);
	buf->ab_text[0] = 0;
	buf->ab_client = client;
	buf->ab_type = AB_TAKETHIS;

	client->cl_buffer = buf;
	client->cl_state = CS_TAKETHIS;
}

void
client_takethis_done(client)
	client_t	*client;
{
int		 rejected = (client->cl_state == CS_TAKETHIS) ? 439 : 437;
artbuf_t	*buf = client->cl_buffer;
msglist_t	*msg;

#if 0
	pending_remove(client->cl_msgid);
#endif

	if (buf->ab_len > max_article_size) {
		client->cl_server->se_in_rejected++;
		history_add(buf->ab_msgid);
		client_log(LOG_INFO, client, "%s: too large (%d > %d)",
				buf->ab_msgid,
				(int) buf->ab_len,
				(int) max_article_size);
		client_printf(client, "%d %s\r\n", rejected, buf->ab_msgid);
		log_article(buf->ab_msgid, NULL, client->cl_server, '-', "too-large");
		goto err;
	}

	if (!valid_msgid(buf->ab_msgid)) {
		client_log(LOG_INFO, client, "%s: invalid message-id",
			   buf->ab_msgid);
		log_article(buf->ab_msgid, NULL, client->cl_server, '-', "invalid-msgid");
		client_printf(client, "%d %s\r\n", rejected, buf->ab_msgid);
		goto err;
	}

	if (DEBUG(CIO))
		client_log(LOG_DEBUG, client, "takethis_done; process_article");

	client_pause(client);
	process_article(client, buf);

	return;

err:
	free(buf->ab_text);
	free(buf->ab_msgid);
	free(buf);
	client->cl_state = CS_WAIT_COMMAND;
	return;
}

void
client_incoming_reply(cl, bufs)
	client_t	*cl;
	artbuf_t	*bufs;
{
artbuf_t	*buf = cl->cl_buffer;

	if (DEBUG(CIO))
		client_log(LOG_DEBUG, cl, "got process reply");

	if (cl->cl_flags & CL_DESTROY) {
		client_destroy(cl);
		return;
	}

	if (buf->ab_status == IN_OK)
		client_printf(cl, "%d %s\r\n",
			      (buf->ab_type == AB_TAKETHIS) ? 239 : 235,
			      buf->ab_msgid);
	else
		client_printf(cl, "%d %s\r\n",
			      (buf->ab_type == AB_TAKETHIS) ? 439 : 437,
			      buf->ab_msgid);

	free(cl->cl_buffer->ab_msgid);
	free(cl->cl_buffer->ab_text);
	free(cl->cl_buffer);
	cl->cl_buffer = NULL;

	cl->cl_state = CS_WAIT_COMMAND;
	client_unpause(cl);
}
