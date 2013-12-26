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
char	*msgid = NULL;
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
		client_log(LOG_DEBUG, client, "takethis_done; process_article");

	process_article(client->cl_article, client->cl_msgid, client);
	client->cl_flags |= CL_PENDING;
	client_pause(client);
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
int	 rejected = (cl->cl_state == CS_TAKETHIS) ? 439 : 437;
int	 accepted = (cl->cl_state == CS_TAKETHIS) ? 239 : 235;

	if (DEBUG(CIO))
		client_log(LOG_DEBUG, cl, "got process reply");

	if (cl->cl_flags & (CL_DEAD | CL_DRAIN)) {
		client_destroy(cl);
		return;
	}

	cl->cl_flags &= ~CL_PENDING;
	client_unpause(cl);

	if (reason == IN_OK)
		client_printf(cl, "%d %s\r\n",
			      accepted, cl->cl_msgid);
	else
		client_printf(cl, "%d %s\r\n",
			      rejected, cl->cl_msgid);

	cl->cl_state = CS_WAIT_COMMAND;
	free(cl->cl_msgid);
	cl->cl_msgid = NULL;

}
