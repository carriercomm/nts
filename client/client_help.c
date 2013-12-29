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
c_help(client, cmd, line)
	client_t	*client;
	char		*cmd, *line;
{
	if (next_word(&line)) {
		client_printf(client, "501 Syntax: HELP\r\n");
		return;
	}

	client_printf(client,
		"100 Command list:\r\n"
		"  CAPABILITIES\r\n"
		"  CHECK <msg-id>\r\n"
		"  HELP\r\n"
		"  IHAVE <msg-id>\r\n"
		"  MODE STREAM\r\n"
		"  MODE READER\r\n"
		"  QUIT\r\n"
		"  TAKETHIS <msg-id>\r\n"
#ifdef	HAVE_OPENSSL
		"  STARTTLS\r\n"
#endif
		".\r\n"
		);
}
