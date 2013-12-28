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
c_starttls(cl, cmd, line)
	client_t	*cl;
	char		*cmd, *line;
{
#ifndef HAVE_OPENSSL
	client_printf(cl, "580 TLS not available.\r\n");
	return;
#else
	if (!cl->cl_listener->li_ssl) {
		client_printf(cl, "580 TLS not available.\r\n");
		return;
	}

	if (cl->cl_ssl) {
		client_printf(cl, "502 TLS already in use.\r\n");
		return;
	}

	cq_free(cl->cl_rdbuf);
	cl->cl_rdbuf = cq_new();

	client_printf(cl, "382 OK, start negotiation.\r\n");

	cl->cl_flags |= (CL_SSL | CL_SSL_ACPTING);
	cl->cl_ssl = SSL_new(cl->cl_listener->li_ssl);
	cl->cl_bio_in = BIO_new(BIO_s_mem());
	cl->cl_bio_out = BIO_new(BIO_s_mem());
	SSL_set_bio(cl->cl_ssl, cl->cl_bio_in, cl->cl_bio_out);

	client_tls_accept(cl);
#endif
}
