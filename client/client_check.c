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
#include	"history.h"
#include	"server.h"

void
c_check(client, cmd, line)
	client_t	*client;
	char		*cmd, *line;
{
char	*msgid;

	if ((msgid = next_word(&line)) == NULL || next_word(&line)) {
		client_printf(client, "501 Syntax: CHECK <message-id>\r\n");
		return;
	}

	if (!valid_msgid(msgid)) {
		client_printf(client, "438 %s\r\n", msgid);
		return;
	}

	if (!server_accept_offer(client->cl_server, msgid)) {
		++client->cl_server->se_in_refused;
		client_printf(client, "438 %s\r\n", msgid);
		return;
	}

	if (pending_check(msgid)) {
		++client->cl_server->se_in_deferred;
		client_printf(client, "431 %s\r\n", msgid);
		return;
	}

	if (history_check(msgid)) {
		++client->cl_server->se_in_refused;
		client_printf(client, "438 %s\r\n", msgid);
	} else {
		client_printf(client, "238 %s\r\n", msgid);
		pending_add(client, msgid);
	}
}
