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

#include	<ev.h>

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
#include	"balloc.h"
#include	"auth.h"
#include	"thread.h"
#include	"emp.h"
#include	"incoming.h"

static void	 client_readable(struct ev_loop *, ev_io *, int);
static void	 client_writable(struct ev_loop *, ev_io *, int);

static client_t	*client_new(int fd);
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

static balloc_t	*ba_client;

static pthread_t	 client_thread;
struct ev_loop		*client_loop;

static void	*client_thread_run(void *);

/*
 * When a client becomes readable or writable, we do nothing but add it to the 
 * appropriate list.  Then we process all clients at the end of the I/O loop.
 */
static client_list_t	client_readable_list;
static client_list_t	client_writable_list;
static client_list_t	client_dead_list;
static ev_prepare	client_prepare;

static void		client_do_io(struct ev_loop *, ev_prepare *, int);

int
client_init()
{
	ba_client = balloc_new(sizeof(client_t), 128, "client");
	pending_init();
	config_add_stanza(&listen_stanza);

	SIMPLEQ_INIT(&client_readable_list);
	SIMPLEQ_INIT(&client_writable_list);
	SIMPLEQ_INIT(&client_dead_list);

	ev_prepare_init(&client_prepare, client_do_io);
	ev_async_init(&reply_ev, client_do_replies);

#ifdef HAVE_OPENSSL
	SSL_load_error_strings();
	SSL_library_init();
#endif

	if (incoming_init() == -1)
		return -1;

	client_loop = ev_loop_new(ev_supported_backends());
	return 0;
}

int
client_run()
{
	if (client_listen() == -1)
		return -1;

	incoming_run();
	pthread_create(&client_thread, NULL, client_thread_run, NULL);
	return 0;
}

void *
client_thread_run(p)
	void	*p;
{
	ev_prepare_start(client_loop, &client_prepare);
	ev_async_start(client_loop, &reply_ev);
	ev_run(client_loop, 0);
	return NULL;
}

void
client_accept(fd, addr, addrlen, ssl, li)
	struct sockaddr	*addr;
	socklen_t	 addrlen;
	SSL		*ssl;
	listener_t	*li;
{
client_t	*client;
server_t	*server;
char		 host[NI_MAXHOST], serv[NI_MAXSERV],
		 strname[NI_MAXHOST + NI_MAXSERV + 1024];
int		 one = 1;
int		 fl;

	if ((fl = fcntl(fd, F_GETFL, 0)) == -1) {
		nts_log(LOG_ERR, "fcntl(F_GETFL): %s",
			strerror(errno));
		close(fd);
		return;
	}

	if ((fl = fcntl(fd, F_SETFL, fl | O_NONBLOCK)) == -1) {
		nts_log(LOG_ERR, "fcntl(F_GETFL): %s",
			strerror(errno));
		close(fd);
		return;
	}

	if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) == -1) {
		nts_log(LOG_ERR, "setsockopt(TCP_NODELAY): %s",
			strerror(errno));
		close(fd);
		return;
	}

	client = client_new(fd);
	client->cl_listener = li;
	client->cl_ssl = ssl;
	client->cl_rdbuf = cq_new();
	client->cl_wrbuf = cq_new();

	if (ssl)
		client->cl_flags |= CL_SSL;

	getnameinfo(addr, addrlen, host, sizeof(host), serv, sizeof(serv),
			NI_NUMERICHOST | NI_NUMERICSERV);

	bcopy(addr, &client->cl_addr, addrlen);
	client->cl_addrlen = addrlen;

	ev_io_init(&client->cl_readable, client_readable, fd, EV_READ);
	client->cl_readable.data = client;

	ev_io_init(&client->cl_writable, client_writable, fd, EV_WRITE);
	client->cl_writable.data = client;

	ev_io_start(client_loop, &client->cl_readable);

	if ((server = server_find_by_address((struct sockaddr_storage *) addr)) == NULL
	    && !allow_unauthed) {
		nts_log(LOG_NOTICE, "unknown[%s]:%s: connection rejected: access denied",
				host, serv);
		if (reader_handler) {
			client_reader(client);
		} else {
			client_printf(client, "502 Access denied (%s).\r\n", contact_address);
		}
		client_close(client, 1);
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

	if (log_incoming_connections)
		client_log(LOG_INFO, client, "client connected");
}

void
client_readable(loop, w, revents)
	struct ev_loop	*loop;
	ev_io		*w;
{
client_t	*cl = w->data;

	if (DEBUG(CIO))
		client_log(LOG_DEBUG, cl, "client %d becomes readable CL_READABLE=%d CL_DEAD=%d CL_PAUSED=%d", 
			   cl->cl_fd, cl->cl_flags & CL_READABLE, cl->cl_flags & CL_DEAD,
			   cl->cl_flags & CL_PAUSED);

	if (cl->cl_flags & (CL_DEAD | CL_READABLE))
		return;

	cl->cl_flags |= CL_READABLE;
	SIMPLEQ_INSERT_TAIL(&client_readable_list, cl, cl_read_list);
}

void
client_writable(loop, w, revents)
	struct ev_loop	*loop;
	ev_io		*w;
{
client_t	*cl = w->data;

	if (DEBUG(CIO))
		client_log(LOG_DEBUG, cl, "client %d becomes writable CL_READABLE=%d CL_DEAD=%d CL_PAUSED=%d", 
			cl->cl_fd, cl->cl_flags & CL_READABLE, cl->cl_flags & CL_DEAD,
			cl->cl_flags & CL_PAUSED);

	if (cl->cl_flags & (CL_DEAD | CL_WRITABLE))
		return;

	cl->cl_flags |= CL_WRITABLE;
	SIMPLEQ_INSERT_TAIL(&client_writable_list, cl, cl_write_list);
}

static void
client_do_io(loop, w, revents)
	struct ev_loop	*loop;
	ev_prepare	*w;
{
client_t	*cl;

	if (DEBUG(CIO))
		nts_log(LOG_DEBUG, "client_do_io runs");

	/*
	 * Try to write data to each client.  If we see an error, mark the
	 * client as dead; dead clients are cleaned up later.
	 */
	while (cl = SIMPLEQ_FIRST(&client_writable_list)) {
		SIMPLEQ_REMOVE(&client_writable_list, cl, client, cl_write_list);

		if (DEBUG(CIO))
			client_log(LOG_DEBUG, cl, "client [%d] on writable list cq_len=%d",
				   cl->cl_fd, (int) cq_len(cl->cl_wrbuf));

		if (!(cl->cl_flags & CL_WRITABLE))
			continue;

		cl->cl_flags &= ~CL_WRITABLE;

		if (cq_write(cl->cl_wrbuf, cl->cl_fd) == -1) {
			client_log(LOG_INFO, cl, "write error: %s",
					strerror(errno));
			client_close(cl, 0);
		}

		/*
		 * If we still have outstanding writes for the client,
		 * mark it as paused, so we don't process any input from it.
		 */
		if (cq_len(cl->cl_wrbuf)) {
			if (DEBUG(CIO))
				client_log(LOG_DEBUG, cl, "client [%d] unflushed, pausing reads",
					   cl->cl_fd);
			cl->cl_flags |= CL_PAUSED;
			ev_io_stop(client_loop, &cl->cl_readable);
		} else {
			if (DEBUG(CIO))
				client_log(LOG_DEBUG, cl, "client [%d] flushed", cl->cl_fd);
			ev_io_stop(client_loop, &cl->cl_writable);
			cl->cl_flags &= ~CL_PAUSED;

			if (cl->cl_flags & CL_DRAIN)
				client_close(cl, 0);
		}
	}

	/*
	 * Handle each readable client.  Ignore dead and paused clients.
	 */
	while (cl = SIMPLEQ_FIRST(&client_readable_list)) {
	int	nl = 0;
	ssize_t	n;

		if (DEBUG(CIO))
			client_log(LOG_DEBUG, cl, 
				"client %d on read list CL_READABLE=%d CL_DEAD=%d CL_PAUSED=%d", 
				cl->cl_fd, cl->cl_flags & CL_READABLE, cl->cl_flags & CL_DEAD,
				cl->cl_flags & CL_PAUSED);

		SIMPLEQ_REMOVE(&client_readable_list, cl, client, cl_read_list);

		if (!(cl->cl_flags & CL_READABLE))
			continue;

		cl->cl_flags &= ~CL_READABLE;

		if (cl->cl_flags & (CL_DEAD | CL_PAUSED | CL_PENDING)) {
			ev_io_stop(client_loop, &cl->cl_readable);
			continue;
		}

		if ((n = cq_read(cl->cl_rdbuf, cl->cl_fd)) <= 0) {
			client_close(cl, 0);
			if (n == 0)
				client_log(LOG_INFO, cl, "disconnected (EOF)");
			else
				client_log(LOG_INFO, cl, "read error: %s",
					strerror(errno));
			continue;
		}

		if (DEBUG(CIO))
			client_log(LOG_DEBUG, cl,
				"client %d read %d", cl->cl_fd, (int) n);

		for (;;) {
		char	*ln;

			if (DEBUG(CIO))
				client_log(LOG_DEBUG, cl, 
					   "client %d cq_len=%d", cl->cl_fd,
					   (int) cq_len(cl->cl_rdbuf));

			if ((ln = cq_read_line(cl->cl_rdbuf)) == NULL)
				break;
			client_handle_line(cl, ln);
			free(ln);
			ln = NULL;

			if (cl->cl_flags & (CL_DEAD | CL_PAUSED | CL_PENDING)) {
				ev_io_stop(client_loop, &cl->cl_readable);
				break;
			}
		}
	}

	/*
	 * Clean up any clients which have become dead.
	 */
	while (cl = SIMPLEQ_FIRST(&client_dead_list)) {
		SIMPLEQ_REMOVE(&client_dead_list, cl, client, cl_dead_list);

		if (!(cl->cl_flags & CL_PENDING))
			client_destroy(cl);
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
				if ((strlen(line) + 3 + cl->cl_artsize) >=
				    cl->cl_artalloc) {
					cl->cl_article = xrealloc(cl->cl_article,
								cl->cl_artalloc * 2);
					cl->cl_artalloc *= 2;
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
client_vprintf(client, fmt, ap)
	client_t	*client;
	char const	*fmt;
	va_list		 ap;
{
char	buf[8192];
char	*r = buf;
int	len;

	len = vsnprintf(buf, sizeof(buf), fmt, ap);
	if ((unsigned int) len >= sizeof (buf)) {
		r = xmalloc(len + 1);
		vsnprintf(r, len + 1, fmt, ap);
	}

	cq_append(client->cl_wrbuf, r, len);
	ev_io_start(client_loop, &client->cl_writable);

	if (r != buf)
		free(r);
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
client_new(fd)
{
client_t	*cl;
	cl = bzalloc(ba_client);
	cl->cl_fd = fd;
	cl->cl_state = CS_WAIT_COMMAND;
	cl->cl_artalloc = 16384;
	cl->cl_article = xmalloc(cl->cl_artalloc);
	cl->cl_article[0] = 0;
	return cl;
}

void
client_close(cl, drain)
	client_t	*cl;
{
	if (cl->cl_flags & CL_DEAD)
		return;

	if (drain && cq_len(cl->cl_wrbuf)) {
		cl->cl_flags |= CL_DRAIN;

		ev_io_stop(client_loop, &cl->cl_readable);
		cl->cl_flags &= ~CL_READABLE;
		return;
	}

	ev_io_stop(client_loop, &cl->cl_readable);
	ev_io_stop(client_loop, &cl->cl_writable);

	cl->cl_flags |= CL_DEAD;
	SIMPLEQ_INSERT_TAIL(&client_dead_list, cl, cl_dead_list);
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
	free(client->cl_msgid);
	free(client->cl_article);
	free(client->cl_username);
	free(client->cl_strname);
	cq_free(client->cl_wrbuf);
	cq_free(client->cl_rdbuf);
	close(client->cl_fd);
	bfree(ba_client, client);
}
