/* RT/NTS -- a lightweight, high performance news transit server. */
/* 
 * Copyright (c) 2011-2013 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */

#include	<sys/types.h>
#include	<sys/socket.h>

#include	<netinet/in.h>
#include	<netinet/tcp.h>

#include	<stdio.h>
#include	<string.h>
#include	<stdlib.h>
#include	<stdarg.h>
#include	<time.h>
#include	<errno.h>
#include	<fcntl.h>
#include	<pthread.h>

#include	<uv.h>

#include	"setup.h"

#ifdef HAVE_OPENSSL
# include	<openssl/ssl.h>
# include	<openssl/err.h>
#endif

#include	"client.h"
#include	"net.h"
#include	"config.h"
#include	"server.h"
#include	"log.h"
#include	"article.h"
#include	"history.h"
#include	"nts.h"
#include	"queue.h"
#include	"spool.h"
#include	"hash.h"
#include	"filter.h"
#include	"feeder.h"
#include	"auth.h"
#include	"emp.h"
#include	"incoming.h"

static void	 on_client_read(uv_stream_t *, ssize_t, uv_buf_t const *);
static void	 on_client_write_done(uv_write_t *, int);
static void	 on_client_close_done(uv_handle_t *);
static void	 on_client_shutdown_done(uv_shutdown_t *, int);

static client_t	*client_new(uv_tcp_t *);
static void	 client_vprintf(client_t *, char const *, va_list ap);
static void	 client_vlog(int sev, client_t *, char const *, va_list ap);
static void	 client_handle_line(client_t *, char *);

typedef void (*cmd_handler) (client_t *, char *, char *);

static struct {
	char const	*cmd;
	cmd_handler	 handler;
	int		 need_auth;
} cmds[] = {
	{ "CHECK",		c_check,	1 },
	{ "TAKETHIS",		c_takethis,	1 },
	{ "IHAVE",		c_ihave,	1 },
	{ "MODE",		c_mode,		0 },
	{ "CAPABILITIES",	c_capabilities,	0 },
	{ "AUTHINFO",		c_authinfo,	0 },
	{ "QUIT",		c_quit,		0 },
	{ "STARTTLS",		c_starttls,	0 },
	{ "HELP",		c_help,		0 },
};

int
client_init()
{
	if (client_reader_init() == -1)
		return -1;

	pending_init();
	config_add_stanza(&listen_stanza);

#ifdef HAVE_OPENSSL
	SSL_load_error_strings();
	SSL_library_init();
#endif

	if (incoming_init() == -1)
		return -1;

	return 0;
}

int
client_run()
{
	if (client_listen() == -1)
		return -1;

	incoming_run();
	return 0;
}

void
client_accept(stream, ssl, li)
	uv_tcp_t	*stream;
	SSL		*ssl;
	listener_t	*li;
{
client_t	*client;
server_t	*server;
char		 host[NI_MAXHOST], serv[NI_MAXSERV],
		 strname[NI_MAXHOST + NI_MAXSERV + 1024];
int		 err;

struct sockaddr_storage	addr;
int			addrlen = sizeof(addr);

	client = client_new(stream);
	client->cl_listener = li;
	client->cl_ssl = ssl;
	client->cl_rdbuf = cq_new();
	stream->data = client;

	if (ssl)
		client->cl_flags |= CL_SSL;

	if (err = uv_tcp_nodelay(stream, 0)) {
		nts_log(LOG_ERR, "accept: uv_tcp_nodelay: %s",
			uv_strerror(err));
		client_close(client, 0);
		return;
	}

	if (err = uv_tcp_getpeername(stream, (struct sockaddr *) &addr, &addrlen)) {
		nts_log(LOG_ERR, "accept: uv_tcp_getpeername: %s",
			uv_strerror(err));
		client_close(client, 0);
		return;
	}

	if (err = getnameinfo((struct sockaddr *) &addr, addrlen,
		    host, sizeof(host), serv, sizeof(serv),
		    NI_NUMERICHOST | NI_NUMERICSERV)) {
		nts_log(LOG_ERR, "accept: getnameinfo: %s",
			gai_strerror(err));
		client_close(client, 0);
		return;
	}

	bcopy(&addr, &client->cl_addr, addrlen);
	client->cl_addrlen = addrlen;

	if ((server = server_find_by_address(&addr)) == NULL
	    && !allow_unauthed) {
		if (reader_handler) {
			client_reader(client);
			client_destroy(client);
		} else {
			nts_log(LOG_NOTICE, "unknown[%s]:%s: connection rejected: access denied",
				host, serv);
			client_printf(client, "502 Access denied (%s).\r\n", contact_address);
			client_close(client, 1);
		}

		return;
	}

	if (server) {
		if (server->se_nconns == server->se_maxconns_in) {
			nts_log(LOG_NOTICE, "%s[%s]:%s: connection rejected: too many connections",
					server->se_name, host, serv);
			client_printf(client, "400 Too many connection (%s).\r\n", contact_address);
			client_close(client, 1);
			return;
		}
		SIMPLEQ_INSERT_TAIL(&server->se_clients, client, cl_list);
		++server->se_nconns;

		client->cl_server = server;
		snprintf(strname, sizeof(strname), "%s[%s]:%s", server->se_name, host, serv);
		client->cl_strname = xstrdup(strname);
	} else { 
		snprintf(strname, sizeof(strname), "unknown[%s]:%s", host, serv);
		client->cl_strname = xstrdup(strname);
	}

	client_printf(client, "200 RT/NTS %s ready (%s).\r\n",
			PACKAGE_VERSION,  contact_address);

	uv_read_start((uv_stream_t *) stream, uv_alloc, on_client_read);

	if (log_incoming_connections)
		client_log(LOG_INFO, client, "client connected");
}

static void
on_client_read(stream, nread, buf)
	uv_stream_t	*stream;
	ssize_t		 nread;
	uv_buf_t const	*buf;
{
client_t	*cl = stream->data;

	if (DEBUG(CIO))
		client_log(LOG_DEBUG, cl, "on_client_read: nread=%d",
			   (int) nread);

	if (nread == 0 || nread == UV_ECANCELED ||
	    (cl->cl_flags & CL_DEAD)) {
		free(buf->base);
		return;
	}

	if (nread < 0) {
		if (log_incoming_connections)
			if (nread == UV_EOF)
				client_log(LOG_INFO, cl, "disconnected (EOF)");
			else
				client_log(LOG_INFO, cl, "disconnected (read error: %s)",
					   uv_strerror(nread));
		client_close(cl, 0);
		free(buf->base);
		return;
	}

	if (cl->cl_flags & CL_DEAD) {
		if (DEBUG(CIO))
			client_log(LOG_DEBUG, cl, "on_client_read: client is dead");

		free(buf->base);
		return;
	}

	cq_append(cl->cl_rdbuf, buf->base, nread);

	if (cl->cl_flags & CL_PAUSED) {
		if (DEBUG(CIO))
			client_log(LOG_DEBUG, cl, "on_client_read: client is paused");

		return;
	}

	if (cl->cl_flags & CL_PENDING) {
		if (DEBUG(CIO))
			client_log(LOG_DEBUG, cl, "on_client_read: client is pending");

		return;
	}

	for (;;) {
	char	*ln;

		if ((ln = cq_read_line(cl->cl_rdbuf)) == NULL)
			break;

		if (DEBUG(CIO))
			client_log(LOG_DEBUG, cl, "incoming: [%s]", ln);

		client_handle_line(cl, ln);
		free(ln);
		ln = NULL;

		if (cl->cl_flags & (CL_DEAD | CL_PAUSED | CL_PENDING))
			break;
	}
}

static void
client_handle_line(cl, line)
	client_t	*cl;
	char		*line;
{
	if (cl->cl_state == CS_WAIT_COMMAND) {
	char	 *command;
	size_t	  i;

		if ((command = next_word(&line)) == NULL)
			return;

		for (i = 0; i < sizeof(cmds) / sizeof(*cmds); i++) {
			if (strcasecmp(command, cmds[i].cmd))
				continue;

			if (cmds[i].need_auth &&
			    (!cl->cl_server ||
			     (cl->cl_server->se_username_in
			      && !cl->cl_authenticated))) {
				client_printf(cl, "480 Authentication required.\r\n");
			} else {
				cmds[i].handler(cl, command, line);
			}

			return;
		}

		client_printf(cl, "500 Unknown command.\r\n");
	} else if (cl->cl_state == CS_TAKETHIS || cl->cl_state == CS_IHAVE) {
		if (strcmp(line, ".") == 0) {
			client_takethis_done(cl);
		} else {
			if (cl->cl_artsize <= max_article_size) {
			size_t	newsz = (strlen(line) + 3 + cl->cl_artsize);
				if (newsz >= cl->cl_artalloc) {
					cl->cl_artalloc *= 2;
					if (newsz >= cl->cl_artalloc)
						cl->cl_artalloc = newsz + 1;
					    
					cl->cl_article = xrealloc(cl->cl_article,
								  cl->cl_artalloc);
				}

				strlcat(cl->cl_article, line, cl->cl_artalloc);
				strlcat(cl->cl_article, "\r\n", cl->cl_artalloc);
			}

			cl->cl_artsize += strlen(line) + 2;
		}
	}
}

static void
client_vlog(int sev, client_t *client, char const *fmt, va_list ap)
{
char	buf[8192];
char	*r = buf;
int	len;

	len = vsnprintf(buf, sizeof(buf), fmt, ap);
	if ((unsigned int) len >= sizeof (buf)) {
		r = xmalloc(len + 1);
		vsnprintf(r, len + 1, fmt, ap);
	}

	nts_log(sev, "%s: %s", client->cl_strname, r);

	if (r != buf)
		free(r);
}

static void
on_client_write_done(wr, status)
	uv_write_t	*wr;
{
client_t	*cl = wr->data;

	if (wr->bufs)
		free(wr->bufs[0].base);
	free(wr);

	if (status == 0 || status == UV_ECANCELED ||
	    (cl->cl_flags & CL_DEAD))
		return;

	if (log_incoming_connections)
		client_log(LOG_INFO, cl, "write error: %s",
			   uv_strerror(status));

	client_close(cl, 0);
}

static void
client_vprintf(client, fmt, ap)
	client_t	*client;
	char const	*fmt;
	va_list		 ap;
{
char		*buf;
int		 len;
uv_write_t	*wr;
uv_buf_t	 ubuf;

#define PRINTF_BUFSZ	1024

	buf = malloc(PRINTF_BUFSZ);
	len = vsnprintf(buf, PRINTF_BUFSZ, fmt, ap);
	if ((unsigned int) len >= PRINTF_BUFSZ) {
		buf = xrealloc(buf, len + 1);
		vsnprintf(buf, len + 1, fmt, ap);
	}

	wr = xcalloc(1, sizeof(*wr));

	ubuf = uv_buf_init(buf, len);
	wr->data = client;

	uv_write(wr, (uv_stream_t *) client->cl_stream, &ubuf, 1, on_client_write_done);
}

void
client_printf(client_t *client, char const *fmt, ...)
{
va_list	ap;
	va_start(ap, fmt);
	client_vprintf(client, fmt, ap);
	va_end(ap);
}

void
client_log(int sev, client_t *client, char const *fmt, ...)
{
va_list	ap;
	va_start(ap, fmt);
	client_vlog(sev, client, fmt, ap);
	va_end(ap);
}

static client_t *
client_new(stream)
	uv_tcp_t	*stream;
{
client_t	*cl;

	cl = xcalloc(1, sizeof(*cl));
	cl->cl_stream = stream;
	cl->cl_state = CS_WAIT_COMMAND;
	cl->cl_artalloc = 16384;
	cl->cl_article = xmalloc(cl->cl_artalloc);
	cl->cl_article[0] = 0;
	return cl;
}

static void 
on_client_shutdown_done(req, status)
	uv_shutdown_t	*req;
{
uv_tcp_t	*stream = (uv_tcp_t *) req->handle;
client_t	*cl = stream->data;

	free(req);

	if (status) {
		if (log_incoming_connections)
			client_log(LOG_INFO, cl, "write error: %s",
				   uv_strerror(status));
	}

	uv_close((uv_handle_t *) stream, on_client_close_done);
}

static void
on_client_close_done(handle)
	uv_handle_t	*handle;
{
client_t	*cl = handle->data;

	if (cl->cl_flags & CL_PENDING)
		return;

	client_destroy(cl);
}

void
client_close(cl, drain)
	client_t	*cl;
{
	if (cl->cl_flags & CL_DEAD)
		return;

	if (drain) {
	uv_shutdown_t	*req = xcalloc(1, sizeof(*req));

		cl->cl_flags |= CL_DRAIN;
		req->data = cl;

		uv_shutdown(req, (uv_stream_t *) cl->cl_stream, on_client_shutdown_done);
		return;
	}

	cl->cl_flags |= CL_DEAD;
	uv_close((uv_handle_t *) cl->cl_stream, on_client_close_done);
}

void
client_destroy(udata)
	void	*udata;
{
client_t	*client = udata;
	if (client->cl_server) {
		--client->cl_server->se_nconns;
		SIMPLEQ_REMOVE(&client->cl_server->se_clients, client, client, cl_list);
	}

	pending_remove_client(client);
	free(client->cl_stream);
	free(client->cl_msgid);
	free(client->cl_article);
	free(client->cl_username);
	free(client->cl_strname);
	cq_free(client->cl_rdbuf);
	free(client);
}

void
client_pause(cl)
	client_t	*cl;
{
	if (cl->cl_flags & CL_PAUSED)
		return;

	cl->cl_flags |= CL_PAUSED;
	uv_read_stop((uv_stream_t *) cl->cl_stream);
}

void
client_unpause(cl)
	client_t	*cl;
{
	if (!(cl->cl_flags & CL_PAUSED))
		return;

	cl->cl_flags &= ~CL_PAUSED;
	uv_read_start((uv_stream_t *) cl->cl_stream, uv_alloc, on_client_read);
}
