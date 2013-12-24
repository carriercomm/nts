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
#include	"log.h"

void
c_quit(client, cmd, line)
	client_t	*client;
	char		*cmd, *line;
{
	if (next_word(&line)) {
		client_printf(client, "501 Syntax: QUIT\r\n");
		return;
	}

	if (log_incoming_connections)
		client_log(LOG_INFO, client, "disconnected (QUIT)");

	client_printf(client, "205 Closing connection.\r\n");
	client->cl_state = CS_DEAD;

	client_close(client, 1);
}

