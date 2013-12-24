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

#include	"setup.h"

#ifdef HAVE_OPENSSL
# include	<openssl/ssl.h>
# include	<openssl/err.h>
#endif

#include	"client.h"
#include	"log.h"

static listener_t *client_listeners;

static void	 listen_accept(struct ev_loop *, ev_io *, int);

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
			nts_log(LOG_ERR, "listener \"%s\": cannot create SSL context: %s",
					stz->cs_title, ERR_error_string(ERR_get_error(), NULL));
			return;
		}

		if ((ret = SSL_CTX_use_certificate_file(li->li_ssl,
				li->li_ssl_cert, SSL_FILETYPE_PEM)) != 1) {
			nts_log(LOG_ERR, "listener \"%s\": cannot load SSL certificate: %s",
					stz->cs_title, ERR_error_string(ERR_get_error(), NULL));
			return;
		}

		if ((ret = SSL_CTX_use_PrivateKey_file(li->li_ssl,
				li->li_ssl_key, SSL_FILETYPE_PEM)) != 1) {
			nts_log(LOG_ERR, "listener \"%s\": cannot load SSL private key: %s",
					stz->cs_title, ERR_error_string(ERR_get_error(), NULL));
			return;
		}

		if (li->li_ssl_cyphers) {
			if (SSL_CTX_set_cipher_list(li->li_ssl, li->li_ssl_cyphers) == 0) {
				nts_log(LOG_ERR, "listener \"%s\": no valid cyphers",
						stz->cs_title);
				return;
			}
		}

		SSL_CTX_set_options(li->li_ssl, SSL_OP_NO_SSLv2);
#else
		nts_log(LOG_ERR, "listener \"%s\": SSL support not enabled", stz->cs_title);
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
	} else
		nts_log(LOG_ERR, "\"%s\", line %d: unknown SSL option \"%s\"",
				opt->co_file, opt->co_lineno, v);
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

	for (li = client_listeners; li; li = li->li_next) {
	struct addrinfo	hints, *res, *r;
	int		 i;	
	char		*addr, *port;
	char		*listr;

		listr = strdup(li->li_address);

		if (*listr == '[') {
			/* [host]:port form, used for IPv6 */
			if ((port = index(listr, ']')) == NULL) {
				nts_log(LOG_ERR, "listen: \"%s\": invalid address",
					listr);
				return -1;
			}

			addr = listr + 1;
			*port++ = 0;
			if (*port != ':') {
				nts_log(LOG_ERR, "listen: \"%s\": invalid address",
					li->li_address);
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
			nts_log(LOG_ERR, "listen: \"%s\": bad address: %s",
				li->li_address, gai_strerror(i));
			return -1;
		}

		for (r = res; r; r = r->ai_next) {
		int	fd;
		int	one = 1;
		int	fl;

			if ((fd = socket(r->ai_family, r->ai_socktype, r->ai_protocol)) == -1) {
				nts_log(LOG_ERR, "listen: \"%s\": socket: %s",
					li->li_address, strerror(errno));
				return -1;
			}

			if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == -1) {
				nts_log(LOG_ERR, "listen: \"%s\": setsockopt(SO_REUSEADDR): %s",
					li->li_address, strerror(errno));
				return -1;
			}

			if ((fl = fcntl(fd, F_GETFL, 0)) == -1) {
				nts_log(LOG_ERR, "listen: \"%s\": fgetfl: %s",
					li->li_address, strerror(errno));
				return -1;
			}

			if (fcntl(fd, F_SETFL, fl | O_NONBLOCK) == -1) {
				nts_log(LOG_ERR, "listen: \"%s\": fsetfl: %s",
					li->li_address, strerror(errno));
				return -1;
			}

			if (bind(fd, r->ai_addr, r->ai_addrlen) == -1) {
				nts_log(LOG_ERR, "listen: \"%s\": bind: %s",
					li->li_address, strerror(errno));
				return -1;
			}

			if (listen(fd, 128) == -1) {
				nts_log(LOG_ERR, "listen: \"%s\": listen: %s",
					li->li_address, strerror(errno));
				return -1;
			}

			li->li_fd = fd;
			ev_io_init(&li->li_event, listen_accept, fd, EV_READ);
			ev_io_start(client_loop, &li->li_event);
			li->li_event.data = li;
		}

		freeaddrinfo(res);
	}

	return 0;
}

static void
listen_accept(loop, w, revents)
	struct ev_loop	*loop;
	ev_io		*w;
{
struct sockaddr_storage	 addr;
socklen_t		 addrlen = sizeof(addr);
int			 fd;
listener_t		*li = w->data;

	while ((fd = accept(li->li_fd, (struct sockaddr *) &addr, &addrlen)) != -1) {
		client_accept(fd, (struct sockaddr *) &addr, addrlen, NULL, li);

		addrlen = sizeof(addr);
	}
}
