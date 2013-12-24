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

void
c_mode(client, cmd, line)
	client_t	*client;
	char		*cmd, *line;
{
char	*mode = NULL;
	if ((mode = next_word(&line)) == NULL || next_word(&line)) {
		client_printf(client, "501 Syntax: MODE STREAM\r\n");
		return;
	}

	if (strcasecmp(mode, "STREAM") == 0) {
		client_printf(client, "203 Streaming permitted.\r\n");
	} else if (strcasecmp(mode, "READER") == 0) {
		if (reader_handler)
			client_reader(client);
		else
			client_printf(client, "502 Transit service only.\r\n");
		client->cl_state = CS_DEAD;
	} else 
		client_printf(client, "501 Unknown MODE variant.\r\n");
}
