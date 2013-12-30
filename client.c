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

#include	"uv.h"

#include	"setup.h"

#ifdef HAVE_OPENSSL
# include	<openssl/ssl.h>
# include	<openssl/err.h>
# include	<openssl/bio.h>
#endif

#include	"client.h"
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
#include	"clientmsg.h"

static client_t	*client_new(uv_tcp_t *);
static void	 client_vprintf(client_t *, char const *, va_list ap);
static void	 client_vlog(int sev, client_t *, char const *, va_list ap);
static void	 client_puts(client_t *, void *, size_t);
static void	 client_handle_io(client_t *);
static void	 client_handle_line(client_t *, char *);
static void	 client_mark_alive(client_t *);

typedef void (*cmd_handler) (client_t *, char *, char *);

static client_list_t	client_timeout_list;
static uv_timer_t	timeout_timer;
static void	client_handle_timeouts(uv_timer_t *, int);

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

	SIMPLEQ_INIT(&client_timeout_list);

	if (incoming_init() == -1)
		return -1;

	return 0;
}

int
client_run()
{
	if (client_listen() == -1)
		return -1;

	uv_timer_init(loop, &timeout_timer);
	uv_timer_start(&timeout_timer, client_handle_timeouts, 10000, 10000);
	incoming_run();
	return 0;
}

void
#ifdef	HAVE_OPENSSL
client_accept(stream, ssl, li)
	SSL_CTX		*ssl;
#else
client_accept(stream, li)
#endif
	uv_tcp_t	*stream;
	listener_t	*li;
{
client_t	*cl;
server_t	*server;
char		 host[NI_MAXHOST], serv[NI_MAXSERV],
		 strname[NI_MAXHOST + NI_MAXSERV + 1024];
time_t		 now;
struct tm	*tm;
char		 tbuf[64];
int		 err;
#ifdef	HAVE_OPENSSL
int		 is_ssl = ssl && (li->li_ssl_type == SSL_ALWAYS);
#endif

struct sockaddr_storage	 addr;
int			 addrlen = sizeof(addr);

	cl = client_new(stream);
	cl->cl_listener = li;
	cl->cl_rdbuf = cq_new();
	stream->data = cl;

	client_mark_alive(cl);

	if (err = uv_tcp_nodelay(stream, 0)) {
		nts_logm(CLIENT_fac, M_CLIENT_ACPTERR,
			 "uv_tcp_nodelay", uv_strerror(err));
		client_close(cl, 0);
		return;
	}

	if (err = uv_tcp_getpeername(cl->cl_stream, (struct sockaddr *) &addr, &addrlen)) {
		nts_logm(CLIENT_fac, M_CLIENT_ACPTERR,
			 "uv_tcp_getpeername", uv_strerror(err));
		client_close(cl, 0);
		return;
	}

	bcopy(&addr, &cl->cl_addr, addrlen);
	cl->cl_addrlen = addrlen;

	if (err = getnameinfo((struct sockaddr *) &addr, addrlen,
		    host, sizeof(host), serv, sizeof(serv),
		    NI_NUMERICHOST | NI_NUMERICSERV)) {
		nts_logm(CLIENT_fac, M_CLIENT_ACPTERR,
			 "getnameinfo", gai_strerror(err));
		client_close(cl, 0);
		return;
	}

#ifdef	HAVE_OPENSSL
	if (is_ssl) {
		cl->cl_flags |= (CL_SSL | CL_SSL_ACPTING);
		cl->cl_ssl = SSL_new(ssl);
		cl->cl_bio_in = BIO_new(BIO_s_mem());
		cl->cl_bio_out = BIO_new(BIO_s_mem());
		SSL_set_bio(cl->cl_ssl, cl->cl_bio_in, cl->cl_bio_out);
		SSL_set_accept_state(cl->cl_ssl);
	}
#endif

	if ((server = server_find_by_address(&cl->cl_addr)) == NULL
	    && !allow_unauthed) {
		if (reader_handler) {
			client_reader(cl);
			client_destroy(cl);
		} else {
			nts_logm(CLIENT_fac, M_CLIENT_DENIED, host, serv);
			client_printf(cl, "502 Access denied (%s).\r\n", contact_address);
			client_close(cl, 1);
		}

		return;
	}

	if (server) {
		if (server->se_nconns == server->se_maxconns_in) {
			nts_logm(CLIENT_fac, M_CLIENT_TOOMANY, server->se_name,
				 host, serv);
			client_printf(cl, "400 Too many connections (%s).\r\n", contact_address);
			client_close(cl, 1);
			return;
		}
		SIMPLEQ_INSERT_TAIL(&server->se_clients, cl, cl_list);
		++server->se_nconns;

		cl->cl_server = server;
		snprintf(strname, sizeof(strname), "%s[%s]:%s", server->se_name, host, serv);
		cl->cl_strname = xstrdup(strname);
	} else {
		snprintf(strname, sizeof(strname), "unknown[%s]:%s", host, serv);
		cl->cl_strname = xstrdup(strname);
	}

#ifdef	HAVE_OPENSSL
	if (DEBUG(CIO) && is_ssl)
		client_log(LOG_DEBUG, cl, "client is SSL");
#endif

	time(&now);
	tm = localtime(&now);
	strftime(tbuf, sizeof(tbuf), "%d-%b-%Y %H:%M:%S %Z", tm);
	client_printf(cl, "200 %s %s ready at %s (%s).\r\n",
		      pathhost, version_string, tbuf, contact_address);

	uv_read_start((uv_stream_t *) cl->cl_stream, uv_alloc, on_client_read);

	if (log_incoming_connections && !(cl->cl_flags & CL_SSL_ACPTING))
		client_logm(CLIENT_fac, M_CLIENT_CONNECT, cl);
}

void
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
				client_logm(CLIENT_fac, M_CLIENT_DISCEOF, cl);
			else
				client_logm(CLIENT_fac, M_CLIENT_DISCERR, cl,
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

	client_mark_alive(cl);

#ifdef	HAVE_OPENSSL
	if (cl->cl_flags & CL_SSL) {
#define	SSL_RDBUF 1024
	char	*rdbuf = xmalloc(SSL_RDBUF);
	int	 ret, err;

		client_tls_write_pending(cl);

		if (BIO_write(cl->cl_bio_in, buf->base, nread) <= 0) {
			if (log_incoming_connections)
				client_logm(CLIENT_fac, M_CLIENT_TLSERR, cl,
					    "BIO_write failed");
			client_close(cl, 0);
			free(buf->base);
			return;
		}

		free(buf->base);

		if (cl->cl_flags & CL_SSL_ACPTING) {
			client_tls_accept(cl);
			return;
		}

		ret = SSL_read(cl->cl_ssl, rdbuf, SSL_RDBUF);
		if (DEBUG(CIO))
			client_log(LOG_DEBUG, cl,
				   "on_client_read: SSL read=%d",
				   (int) ret);

		if (ret <= 0) {
			free(rdbuf);

			err = SSL_get_error(cl->cl_ssl, ret);
			switch (err) {
			case SSL_ERROR_WANT_READ:
				if (DEBUG(CIO))
					client_log(LOG_DEBUG, cl,
						   "on_client_read: SSL_ERROR_WANT_READ "
						   "in pending=%d out pending=%d",
						   (int) BIO_ctrl_pending(cl->cl_bio_in),
						   (int) BIO_ctrl_pending(cl->cl_bio_out));
				client_tls_write_pending(cl);
				return;

			case SSL_ERROR_WANT_WRITE:
				if (DEBUG(CIO))
					client_log(LOG_DEBUG, cl,
						   "on_client_read: SSL_ERROR_WANT_WRITE");
				client_tls_write_pending(cl);
				return;

			default:
				client_logm(CLIENT_fac, M_CLIENT_TLSERR, cl,
					    ERR_error_string(ERR_get_error(), NULL));
				client_close(cl, 0);
				return;
			}

			return;
		} else {
			cq_append(cl->cl_rdbuf, rdbuf, ret);
		}
		client_tls_write_pending(cl);
	} else
#endif
		cq_append(cl->cl_rdbuf, buf->base, nread);

	if (cl->cl_flags & CL_PAUSED) {
		if (DEBUG(CIO))
			client_log(LOG_DEBUG, cl, "on_client_read: client is paused");

		return;
	}

	client_handle_io(cl);
}

static void
client_handle_io(cl)
	client_t	*cl;
{
	for (;;) {
	char	*ln;

		if ((ln = cq_read_line(cl->cl_rdbuf)) == NULL)
			break;

		if (DEBUG(CIO))
			client_log(LOG_DEBUG, cl, "<- [%s]", ln);

		client_handle_line(cl, ln);

		free(ln);
		ln = NULL;

		if (cl->cl_flags & (CL_DEAD | CL_PAUSED))
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
	artbuf_t	*buf = cl->cl_buffer;

		if (strcmp(line, ".") == 0) {
			client_takethis_done(cl);
		} else {
			if (buf->ab_len <= max_article_size) {
			size_t	newsz = (strlen(line) + 3 + buf->ab_len);

				if (newsz >= buf->ab_alloc) {
					buf->ab_alloc *= 2;
					if (newsz >= buf->ab_alloc)
						buf->ab_alloc = newsz + 1;

					buf->ab_text = xrealloc(buf->ab_text,
								buf->ab_alloc);
				}

				strlcat(buf->ab_text, line, buf->ab_alloc);
				strlcat(buf->ab_text, "\r\n", buf->ab_alloc);
			}

			buf->ab_len += strlen(line) + 2;
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

	nts_log("%s: %s", client->cl_strname, r);

	if (r != buf)
		free(r);
}

void
client_log(int sev, client_t *client, char const *fmt, ...)
{
va_list	ap;
	va_start(ap, fmt);
	client_vlog(sev, client, fmt, ap);
	va_end(ap);
}

static void
client_vlogm(msg_t fac[], int msg, client_t *client, va_list ap)
{
char		 buf[8192];
char		*r = buf;
int		 len;
char const	*fmt = fac[msg].m_text;

	len = vsnprintf(buf, sizeof(buf), fmt, ap);
	if ((unsigned int) len >= sizeof (buf)) {
		r = xmalloc(len + 1);
		vsnprintf(r, len + 1, fmt, ap);
	}

	nts_log("%%%s-%c-%s, %s: %s",
		fac[msg].m_subsys, fac[msg].m_sev,
		fac[msg].m_code, client->cl_strname, r);

	if (r != buf)
		free(r);
}

void
client_logm(msg_t fac[], int msg, client_t *client, ...)
{
va_list	ap;
	va_start(ap, client);
	client_vlogm(fac, msg, client, ap);
	va_end(ap);
}

void
on_client_write_done(wr, status)
	uv_write_t	*wr;
{
client_write_req_t	*cwr = wr->data;
client_t		*cl = cwr->client;

	free(cwr->buf);
	free(cwr);
	free(wr);

#ifdef	HAVE_OPENSSL
	if (status == 0 && (cl->cl_flags & CL_SSL_SHUTDN)) {
		client_close(cl, 1);
		return;
	}
#endif

	if (status == 0) {
		client_mark_alive(cl);
		return;
	}

	if (status == UV_ECANCELED || (cl->cl_flags & CL_DEAD))
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
char			*buf;
int			 len;

#define PRINTF_BUFSZ	1024

	buf = malloc(PRINTF_BUFSZ);
	len = vsnprintf(buf, PRINTF_BUFSZ, fmt, ap);
	if ((unsigned int) len >= PRINTF_BUFSZ) {
		buf = xrealloc(buf, len + 1);
		vsnprintf(buf, len + 1, fmt, ap);
	}

	if (DEBUG(CIO))
		client_log(LOG_DEBUG, client, "-> [%s]", buf);

	client_puts(client, buf, len + 1);
}

static void
client_puts(cl, buf, sz)
	client_t	*cl;
	void		*buf;
	size_t		 sz;
{
uv_write_t		*wr;
uv_buf_t		 ubuf;
client_write_req_t	*cwr;

#ifdef	HAVE_OPENSSL
	if (cl->cl_flags & CL_SSL) {
	int	 ret, err;
	char	*nb;

		nb = xmalloc(sz);
		bcopy(buf, nb, sz);
		cq_append(cl->cl_wrbuf, nb, sz);
		client_tls_write_pending(cl);
		return;
	}
#endif

	wr = xcalloc(1, sizeof(*wr));
	ubuf = uv_buf_init(buf, sz);

	cwr = xcalloc(1, sizeof(*cwr));
	cwr->client = cl;
	cwr->buf = buf;

	wr->data = cwr;

	uv_write(wr, (uv_stream_t *) cl->cl_stream, &ubuf, 1, on_client_write_done);
}

void
client_printf(client_t *client, char const *fmt, ...)
{
va_list	ap;
	va_start(ap, fmt);
	client_vprintf(client, fmt, ap);
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
#ifdef	HAVE_OPENSSL
	cl->cl_wrbuf = cq_new();
#endif
	return cl;
}

void
on_client_shutdown_done(req, status)
	uv_shutdown_t	*req;
{
uv_tcp_t	*stream = (uv_tcp_t *) req->handle;
client_t	*cl = stream->data;

	free(req);

	if (DEBUG(CIO))
		client_log(LOG_DEBUG, cl, "on_client_shutdown_done");

	if (status) {
		if (log_incoming_connections)
			client_log(LOG_INFO, cl, "write error: %s",
				   uv_strerror(status));
	}

	uv_close((uv_handle_t *) stream, on_client_close_done);
}

void
on_client_close_done(handle)
	uv_handle_t	*handle;
{
client_t	*cl = handle->data;

	if (DEBUG(CIO))
		client_log(LOG_DEBUG, cl, "on_client_close_done cl_buffer=%p",
			   cl->cl_buffer);

	if (!cl->cl_buffer)
		client_destroy(cl);
	else
		cl->cl_flags |= CL_DESTROY;
}

void
client_close(cl, drain)
	client_t	*cl;
{
	if (cl->cl_flags & CL_DEAD)
		return;

	if (DEBUG(CIO))
		client_log(LOG_DEBUG, cl, "client_close drain=%d", drain);

	if (drain) {
	uv_shutdown_t	*req;

#ifdef	HAVE_OPENSSL
		if (!(cl->cl_flags & CL_SSL_SHUTDN) && (cl->cl_flags & CL_SSL)) {
			SSL_shutdown(cl->cl_ssl);
			cl->cl_flags |= CL_SSL_SHUTDN;
			client_tls_write_pending(cl);
			return;
		}
#endif

		req = xcalloc(1, sizeof(*req));

		cl->cl_flags |= CL_DRAIN;
		req->data = cl;

		uv_shutdown(req, (uv_stream_t *) cl->cl_stream, on_client_shutdown_done);
		return;
	}

	cl->cl_flags |= CL_DEAD;
	uv_close((uv_handle_t *) cl->cl_stream, on_client_close_done);
}

void
client_destroy(cl)
	client_t	*cl;
{
artbuf_t	*buf;
msglist_t	*msg;

	if (DEBUG(CIO))
		client_log(LOG_DEBUG, cl, "client_destroy");

	if (cl->cl_server) {
		--cl->cl_server->se_nconns;
		SIMPLEQ_REMOVE(&cl->cl_server->se_clients, cl, client, cl_list);
	}

	SIMPLEQ_REMOVE(&client_timeout_list, cl, client, cl_timeout_list);

	if (cl->cl_buffer) {
		free(cl->cl_buffer->ab_msgid);
		free(cl->cl_buffer->ab_text);
		free(cl->cl_buffer);
	}

	pending_remove_client(cl);
	free(cl->cl_stream);
	free(cl->cl_username);
	free(cl->cl_strname);
	cq_free(cl->cl_rdbuf);
#ifdef	HAVE_OPENSSL
	cq_free(cl->cl_wrbuf);
	SSL_free(cl->cl_ssl);
#endif
	free(cl);
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

	if (cq_len(cl->cl_rdbuf))
		client_handle_io(cl);
	uv_read_start((uv_stream_t *) cl->cl_stream, uv_alloc, on_client_read);
}

static void
client_mark_alive(cl)
	client_t	*cl;
{
	if (cl->cl_lastalive)
		SIMPLEQ_REMOVE(&client_timeout_list, cl, client, cl_timeout_list);
	SIMPLEQ_INSERT_TAIL(&client_timeout_list, cl, cl_timeout_list);
	cl->cl_lastalive = uv_now(loop);
}

static void
client_handle_timeouts(ev, status)
	uv_timer_t	*ev;
{
uint64_t	 now = uv_now(loop),
		 oldest = now - (client_timeout * 1000);
client_t	*cl;

	SIMPLEQ_FOREACH(cl, &client_timeout_list, cl_timeout_list) {
		if (DEBUG(CIO))
			client_log(LOG_DEBUG, cl, "check timeout "
				   "now=%d oldest=%d last_alive=%d client_timeout=%d",
				   (int) now, (int) oldest, (int) cl->cl_lastalive,
				   (int) client_timeout);
		if (cl->cl_lastalive >= oldest)
			break;

		if (DEBUG(CIO))
			client_log(LOG_DEBUG, cl, "timeout");

		client_close(cl, 1);
	}
}
