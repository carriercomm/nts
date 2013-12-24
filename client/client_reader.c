/* RT/NTS -- a lightweight, high performance news transit server. */
/* 
 * Copyright (c) 2011-2013 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */

#include	<errno.h>

#include	"client.h"
#include	"nts.h"
#include	"log.h"

void
client_reader(client)
	client_t	*client;
{
	if (reader_handoff(client->cl_fd) == -1)
		client_log(LOG_ERR, client, "cannot complete reader handoff: %s",
				strerror(errno));
}
