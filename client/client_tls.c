/* RT/NTS -- a lightweight, high performance news transit server. */
/* 
 * Copyright (c) 2011-2013 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */

#include	"setup.h"

#ifdef	HAVE_OPENSSL
#include	<openssl/ssl.h>
#include	<openssl/err.h>
#endif

#include	"client.h"
#include	"clientmsg.h"
#include	"log.h"

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

#ifdef	HAVE_OPENSSL
void
client_tls_write_pending(cl)
	client_t	*cl;
{
client_write_req_t	*req;
uv_write_t		*wr;
uv_buf_t		 ubuf;
BUF_MEM			*bptr;

	client_tls_flush(cl);

	if (DEBUG(CIO))
		client_log(LOG_DEBUG, cl, "client_tls_write_pending cq_len=%d bio_out=%d",
			   (int) cq_len(cl->cl_wrbuf),
			   (int) BIO_ctrl_pending(cl->cl_bio_out));

	if (!BIO_ctrl_pending(cl->cl_bio_out))
		return;

	req = xcalloc(1, sizeof(*req));
	wr = xcalloc(1, sizeof(*wr));

	BIO_get_mem_ptr(cl->cl_bio_out, &bptr);

	ubuf = uv_buf_init(bptr->data, bptr->length);

	req->client = cl;
	req->buf = bptr->data;

	bptr->data = NULL;
	bptr->length = bptr->max = 0;

	wr->data = req;
	uv_write(wr, (uv_stream_t *) cl->cl_stream, &ubuf, 1, on_client_write_done);
}

void
client_tls_accept(cl)
	client_t	*cl;
{
int	ret, err;

	ret = SSL_accept(cl->cl_ssl);
	if (DEBUG(CIO))
		client_log(LOG_DEBUG, cl,
			   "client_tls_accept: ret=%d",
			   (int) ret);

	if (ret == 1) {
		if (DEBUG(CIO))
			client_log(LOG_DEBUG, cl, "SSL_accept done");
		if (log_incoming_connections) {
			if (cl->cl_listener->li_ssl_type == SSL_ALWAYS)
				client_logm(CLIENT_fac, M_CLIENT_CONNTLS, cl,
					    SSL_get_cipher_version(cl->cl_ssl),
					    SSL_get_cipher_name(cl->cl_ssl));
			else
				client_logm(CLIENT_fac, M_CLIENT_STARTTLS, cl,
					    SSL_get_cipher_version(cl->cl_ssl),
					    SSL_get_cipher_name(cl->cl_ssl));
		}
		cl->cl_flags &= ~CL_SSL_ACPTING;
		client_tls_write_pending(cl);
		return;
	}

	err = SSL_get_error(cl->cl_ssl, ret);

	switch (err) {
	case SSL_ERROR_WANT_READ:
		if (DEBUG(CIO))
			client_log(LOG_DEBUG, cl,
				   "client_tls_accept: SSL_ERROR_WANT_READ "
				   "in pending=%d out pending=%d",
				   (int) BIO_ctrl_pending(cl->cl_bio_in),
				   (int) BIO_ctrl_pending(cl->cl_bio_out));
		client_tls_write_pending(cl);
		return;

	case SSL_ERROR_WANT_WRITE:
		if (DEBUG(CIO))
			client_log(LOG_DEBUG, cl,
				   "client_tls_accept: SSL_ERROR_WANT_WRITE");
		client_tls_write_pending(cl);
		return;

	default:
		client_logm(CLIENT_fac, M_CLIENT_TLSERR, cl,
			    ERR_error_string(ERR_get_error(), NULL));
		client_close(cl, 0);
		return;
	}
}

void
client_tls_flush(cl)
	client_t	*cl;
{
int	ret, err;

	if (DEBUG(CIO))
		client_log(LOG_DEBUG, cl, "client_tls_flush");

	if (cl->cl_flags & CL_SSL_ACPTING)
		return;

	if (!cq_len(cl->cl_wrbuf))
		return;

	while (cq_len(cl->cl_wrbuf)) {
	charq_ent_t	*cqe = cq_first_ent(cl->cl_wrbuf);

		ret = SSL_write(cl->cl_ssl, cqe->cqe_data, cqe->cqe_len);

		if (DEBUG(CIO))
			client_log(LOG_DEBUG, cl, "client_puts: SSL_write wrote %d",
				   ret);

		if (ret <= 0)
			break;

		cq_remove_start(cl->cl_wrbuf, cqe->cqe_len);

		if (cq_len(cl->cl_wrbuf) == 0)
			return;
	}

	if (ret <= 0) {
		err = SSL_get_error(cl->cl_ssl, ret);
		switch (err) {
		case SSL_ERROR_WANT_READ:
			if (DEBUG(CIO))
				client_log(LOG_DEBUG, cl,
					   "client_puts: SSL_ERROR_WANT_READ");
			break;

		case SSL_ERROR_WANT_WRITE:
			if (DEBUG(CIO))
				client_log(LOG_DEBUG, cl,
					   "client_puts: SSL_ERROR_WANT_WRITE");
			break;

		default:
			client_logm(CLIENT_fac, M_CLIENT_TLSERR, cl,
				    ERR_error_string(ERR_get_error(), NULL));
			break;
		}
		return;
	}
}
#endif	/* !HAVE_OPENSSL */
