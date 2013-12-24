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
#include	"auth.h"

void
c_capabilities(client, cmd, line)
	client_t	*client;
	char		*cmd, *line;
{
	client_printf(client,
		"101 Capability list:\r\n"
		"VERSION 2\r\n"
		"IMPLEMENTATION RT/NTS %s\r\n",
		PACKAGE_VERSION);

	if (!auth_enabled || client->cl_authenticated)
		client_printf(client, "IHAVE\r\nSTREAMING\r\n");

	if (reader_handler && !client->cl_authenticated && !client->cl_ssl)
		client_printf(client, "MODE-READER\r\n");

	if (auth_enabled && !client->cl_authenticated &&
	    (insecure_auth || (client->cl_flags & CL_SSL)))
		client_printf(client, "AUTHINFO USER\r\n");

	if (client->cl_listener->li_ssl && !client->cl_ssl)
		client_printf(client, "STARTTLS\r\n");

	client_printf(client, ".\r\n");
}


