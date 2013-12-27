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

static void	 client_tls_done(int fd, SSL *ssl, void *udata);

void
c_starttls(client, cmd, line)
	client_t	*client;
	char		*cmd, *line;
{
#if 0
#ifndef HAVE_OPENSSL
	client_printf(client, "580 TLS not available.\r\n");
	return;
#else
	if (!client->cl_listener->li_ssl) {
		client_printf(client, "580 TLS not available.\r\n");
		return;
	}

	if (client->cl_ssl) {
		client_printf(client, "502 TLS already in use.\r\n");
		return;
	}

	client_printf(client, "382 OK, start negotiation.\r\n");
	net_starttls(client->cl_fd, client->cl_listener->li_ssl, client_tls_done);
#endif
#endif
}

static void
client_tls_done(fd, ssl, udata)
	SSL	*ssl;
	void	*udata;
{
#if 0
client_t	*client = udata;
	client->cl_ssl = ssl;
#endif
}
