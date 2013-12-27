/* RT/NTS -- a lightweight, high performance news transit server. */
/* 
 * Copyright (c) 2011-2013 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */

#include	<fcntl.h>

#include	<uv.h>

#include	"setup.h"

#ifdef HAVE_OPENSSL
# include	<openssl/ssl.h>
# include	<openssl/err.h>
#endif

#include	"client.h"
#include	"log.h"
#include	"clientmsg.h"

static listener_t *client_listeners;
static int	   listen_cfgerrs;

static void	 on_connect(uv_stream_t *, int);

static void	*listen_stanza_start(conf_stanza_t *, void *);
static void	 listen_stanza_end(conf_stanza_t *, void *);
static void	 listen_set_ssl(conf_stanza_t *, conf_option_t *, void *, void *);
static void	 listen_set_ssl_key(conf_stanza_t *, conf_option_t *, void *, void *);
static void	 listen_set_ssl_certificate(conf_stanza_t *, conf_option_t *, void *, void *);
static void	 listen_set_ssl_cyphers(conf_stanza_t *, conf_option_t *, void *, void *);

static config_schema_opt_t listen_opts[] = {
	{ "ssl",		OPT_TYPE_STRING,	listen_set_ssl	},
	{ "ssl-certificate",	OPT_TYPE_STRING,	listen_set_ssl_certificate },
	{ "ssl-key",		OPT_TYPE_STRING,	listen_set_ssl_key },
	{ "ssl-cyphers",	OPT_TYPE_STRING,	listen_set_ssl_cyphers },
	{ "ssl-ciphers",	OPT_TYPE_STRING,	listen_set_ssl_cyphers }
};

config_schema_stanza_t listen_stanza = {
	"listen", 
	SC_MANY | SC_REQTITLE, 
	listen_opts, 
	listen_stanza_start, 
	listen_stanza_end
};

void *
listen_stanza_start(stz, udata)
	conf_stanza_t	*stz;
	void		*udata;
{
listener_t	*li;
	li = xcalloc(1, sizeof(*li));
	li->li_address = xstrdup(stz->cs_title);
	return li;
}

void
listen_stanza_end(stz, udata)
	conf_stanza_t	*stz;
	void		*udata;
{
listener_t	*li = udata;

	if (li->li_ssl_type) {
#ifdef HAVE_OPENSSL
	int	ret;

		if ((li->li_ssl = SSL_CTX_new(SSLv23_server_method())) == NULL) {
			nts_logm(CLIENT_fac, M_CLIENT_SSLCTXFAIL,
				 stz->cs_title, ERR_error_string(ERR_get_error(), NULL));
			++listen_cfgerrs;
			return;
		}

		if ((ret = SSL_CTX_use_certificate_file(li->li_ssl,
				li->li_ssl_cert, SSL_FILETYPE_PEM)) != 1) {
			nts_logm(CLIENT_fac, M_CLIENT_SSLCERTFAIL,
				 stz->cs_title, ERR_error_string(ERR_get_error(), NULL));
			++listen_cfgerrs;
			return;
		}

		if ((ret = SSL_CTX_use_PrivateKey_file(li->li_ssl,
				li->li_ssl_key, SSL_FILETYPE_PEM)) != 1) {
			nts_logm(CLIENT_fac, M_CLIENT_SSLKEYFAIL,
				 stz->cs_title, ERR_error_string(ERR_get_error(), NULL));
			++listen_cfgerrs;
			return;
		}

		if (li->li_ssl_cyphers) {
			if (SSL_CTX_set_cipher_list(li->li_ssl, li->li_ssl_cyphers) == 0) {
				nts_logm(CLIENT_fac, M_CLIENT_SSLCYFAIL, stz->cs_title);
				++listen_cfgerrs;
				return;
			}
		}

		SSL_CTX_set_options(li->li_ssl, SSL_OP_NO_SSLv2);
#else
		nts_logm(CLIENT_fac, M_CLIENT_NOSSL, stz->cs_title);
		++listen_cfgerrs;
		return;
#endif
	}

	li->li_next = client_listeners;
	client_listeners = li;
}

void
listen_set_ssl(stz, opt, udata, arg)
	conf_stanza_t	*stz;
	conf_option_t	*opt;
	void		*udata, *arg;
{
char const	*v = opt->co_value->cv_string;
listener_t	*li = udata;
	if (strcmp(v, "always") == 0) {
		li->li_ssl_type = SSL_ALWAYS;
	} else if (strcmp(v, "starttls") == 0) {
		li->li_ssl_type = SSL_STARTTLS;
	} else {
		nts_logm(CLIENT_fac, M_CLIENT_SSLBADOPT,
			 opt->co_file, opt->co_lineno, v);
		++listen_cfgerrs;
	}
}

void
listen_set_ssl_key(stz, opt, udata, arg)
	conf_stanza_t	*stz;
	conf_option_t	*opt;
	void		*udata, *arg;
{
char const	*v = opt->co_value->cv_string;
listener_t	*li = udata;
	li->li_ssl_key = xstrdup(v);
}

void
listen_set_ssl_cyphers(stz, opt, udata, arg)
	conf_stanza_t	*stz;
	conf_option_t	*opt;
	void		*udata, *arg;
{
char const	*v = opt->co_value->cv_string;
listener_t	*li = udata;
	li->li_ssl_cyphers = xstrdup(v);
}

void
listen_set_ssl_certificate(stz, opt, udata, arg)
	conf_stanza_t	*stz;
	conf_option_t	*opt;
	void		*udata, *arg;
{
char const	*v = opt->co_value->cv_string;
listener_t	*li = udata;
	li->li_ssl_cert = xstrdup(v);
}

int
client_listen()
{
	/*
	 * Create our listeners - do it here so we can pick up errors.
	 *
	 * NB: We can leak strings/fds on error, but in that case we exit
	 * anyway, so it doesn't matter.
	 */

listener_t	*li;
int		 err;

	if (listen_cfgerrs) {
		nts_logm(CLIENT_fac, M_CLIENT_LSNCFGERRS, listen_cfgerrs);
		return -1;
	}

	for (li = client_listeners; li; li = li->li_next) {
	struct addrinfo	hints, *res, *r;
	int		 i;	
	char		*addr, *port;
	char		*listr;

		listr = strdup(li->li_address);

		if (*listr == '[') {
			/* [host]:port form, used for IPv6 */
			if ((port = index(listr, ']')) == NULL) {
				nts_logm(CLIENT_fac, M_CLIENT_INVADDR, listr);
				return -1;
			}

			addr = listr + 1;
			*port++ = 0;
			if (*port != ':') {
				nts_logm(CLIENT_fac, M_CLIENT_INVADDR, li->li_address);
				return -1;
			}
			port++;
		} else {
			if ((port = index(listr, ':')) != NULL) {
				addr = listr;
				*port++ = 0;
			} else {
				/* just a port, no host */
				port = listr;
				addr = NULL;
			}
		}

		/*
		 * Resolve the host.  There's no need to use non-blocking DNS
		 * here (and we probably haven't initialised DNS yet anyway).
		 */
		bzero(&hints, sizeof(hints));
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_family = AF_UNSPEC;
		hints.ai_flags = AI_PASSIVE;

		if (i = getaddrinfo(addr, port, &hints, &res)) {
			nts_logm(CLIENT_fac, M_CLIENT_INVHOST, li->li_address,
				 gai_strerror(i));
			return -1;
		}

		for (r = res, i = 0; r; r = r->ai_next)
			i++;
		li->li_uv = xcalloc(i, sizeof(uv_tcp_t));

		for (r = res; r; r = r->ai_next) {
		uv_tcp_t	*uv;

			++li->li_nuv;
			uv = &li->li_uv[li->li_nuv - 1];

			if (err = uv_tcp_init(loop, uv)) {
				nts_logm(CLIENT_fac, M_CLIENT_LSNFAIL,
					 li->li_address, "uv_tcp_init",
					 uv_strerror(err));
				return -1;
			}

			if (err = uv_tcp_bind(uv, r->ai_addr)) {
				nts_logm(CLIENT_fac, M_CLIENT_LSNFAIL,
					 li->li_address, "uv_tcp_bind",
					 uv_strerror(err));
				return -1;
			}

			if (err = uv_listen((uv_stream_t *) uv, 128, on_connect)) {
				nts_logm(CLIENT_fac, M_CLIENT_LSNFAIL,
					 li->li_address, "uv_listen",
					 uv_strerror(err));
				return -1;
			}

			uv->data = li;
		}

		freeaddrinfo(res);
	}

	return 0;
}

static void
on_connect(server, status)
	uv_stream_t	*server;
{
listener_t	*li = server->data;
uv_tcp_t	*stream;
int		 err;

	stream = xcalloc(1, sizeof(*stream));
	if (err = uv_tcp_init(loop, stream)) {
		nts_logm(CLIENT_fac, M_CLIENT_ACPTERR,
			 "uv_tcp_init", uv_strerror(err));
		return;
	}

	if (err = uv_accept(server, (uv_stream_t *) stream)) {
		nts_logm(CLIENT_fac, M_CLIENT_ACPTERR,
			 "uv_accept", uv_strerror(err));
		return;
	}

	client_accept(stream, NULL, li);
}
