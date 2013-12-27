/* RT/NTS -- a lightweight, high performance news transit server. */
/* 
 * Copyright (c) 2011-2013 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */

#include	"client.h"
#include	"server.h"
#include	"log.h"
#include	"history.h"

void
c_ihave(client, cmd, line)
	client_t	*client;
	char		*cmd, *line;
{
char		*msgid = NULL;
artbuf_t	*buf;

	if ((msgid = next_word(&line)) == NULL || next_word(&line)) {
		client_printf(client, "501 Syntax: IHAVE <message-id>\r\n");
		return;
	}

	if (!valid_msgid(msgid)) {
		client_printf(client, "435 Invalid message-id.\r\n");
		log_article(msgid, NULL, client->cl_server, '-', "invalid-msgid");
		return;
	}

	if (pending_check(msgid)) {
		client->cl_server->se_in_deferred++;
		client_printf(client, "436 %s Try again later.\r\n", msgid);
		return;
	}

	if (!server_accept_offer(client->cl_server, msgid)) {
		client->cl_server->se_in_rejected++;
		client_printf(client, "435 %s Don't want it.\r\n", msgid);
		log_article(msgid, NULL, client->cl_server, '-', "offer-filter");
		return;
	}

	if (history_check(msgid)) {
		client->cl_server->se_in_refused++;
		client_printf(client, "435 %s Already got it.\r\n", msgid);
		log_article(msgid, NULL, client->cl_server, '-', "duplicate");
	} else {
		pending_add(client, msgid);

		buf = xcalloc(1, sizeof(*buf));
		buf->ab_msgid = xstrdup(msgid);
		buf->ab_alloc = ARTBUF_START_SIZE;
		buf->ab_text = xmalloc(buf->ab_alloc);
		buf->ab_text[0] = 0;
		buf->ab_client = client;

		TAILQ_INSERT_TAIL(&client->cl_buffer, buf, ab_list);
		client->cl_state = CS_IHAVE;

		client_printf(client, "335 %s OK, send it.\r\n", msgid);
	}
}
