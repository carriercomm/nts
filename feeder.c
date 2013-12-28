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

#include	<string.h>
#include	<errno.h>
#include	<stdio.h>
#include	<stdarg.h>
#include	<assert.h>
#include	<ctype.h>

#include	"feeder.h"
#include	"nts.h"
#include	"server.h"
#include	"log.h"
#include	"spool.h"
#include	"config.h"
#include	"hash.h"

static feeder_t	*feeder_new(server_t *);
static void	 feeder_log(int sev, feeder_t *fe, char const *fmt, ...)
			attr_printf(3, 4);
static void	 feeder_vlog(int sev, feeder_t *fe, char const *fmt, va_list);
static void	 feeder_load(feeder_t *, int deferred);

static fconn_t	*fconn_new(feeder_t *);
static void	 on_fconn_connect_done(uv_connect_t *, int);
static void	 on_fconn_read(uv_stream_t *, ssize_t, const uv_buf_t *);
static void	 on_fconn_dns_done(uv_getaddrinfo_t *, int, struct addrinfo *);
static void	 on_fconn_write_done(uv_write_t *, int);
static void	 on_fconn_shutdown_done(uv_shutdown_t *, int);
static void	 on_fconn_close_done(uv_handle_t *);

static void	 fconn_connect(fconn_t *);
static void	 fconn_puts(fconn_t *, char const *text);
static void	 fconn_printf(fconn_t *, char const *fmt, ...) attr_printf(2, 3);
static void	 fconn_vprintf(fconn_t *, char const *fmt, va_list);
static void	 fconn_log(int sev, fconn_t *fe, char const *fmt, ...)
			attr_printf(3, 4);
static void	 fconn_vlog(int sev, fconn_t *fe, char const *fmt, va_list);
static void	 fconn_check(fconn_t *fe, qent_t *);
static void	 fconn_takethis(fconn_t *fe, qent_t *);
static void	 fconn_close(fconn_t *, int);
static void	 fconn_destroy(fconn_t *);
static void	 fconn_adp_check(fconn_t *, int accepted);

static int	 fc_wait_greeting(fconn_t *, char *);
static int	 fc_sent_capabilities(fconn_t *, char *);
static int	 fc_read_capabilities(fconn_t *, char *);
static int	 fc_sent_mode_stream(fconn_t *, char *);
static int	 fc_running(fconn_t *, char *);
/* }}} */

static int (*fconn_handlers[]) (fconn_t *, char *) = {
	NULL,	/* DNS */
	NULL,	/* CONNECT */
	fc_wait_greeting,
	fc_sent_capabilities,
	fc_read_capabilities,
	fc_sent_mode_stream,
	fc_running
};

int
feeder_init()
{
	return 0;
}

int
feeder_run()
{
server_t	*se;

	SLIST_FOREACH(se, &servers, se_list)
		se->se_feeder = feeder_new(se);

	return 0;
}

void
feeder_shutdown()
{
}

static feeder_t *
feeder_new(se)
	server_t	*se;
{
feeder_t	*fe;

	assert(se);

	fe = xcalloc(1, sizeof(*fe));
	fe->fe_server = se;
	fe->fe_pending = hash_new(4096, NULL, NULL, NULL);

	TAILQ_INIT(&fe->fe_conns);

	if (se->se_adp_hi == 0)
		fe->fe_flags |= FE_ADP;

	return fe;
}

static void
fconn_connect(fc)
	fconn_t	*fc;
{
char		 strname[1024 + NI_MAXHOST + NI_MAXSERV + 1];
char		 host[NI_MAXHOST], serv[NI_MAXSERV];
int		 ret;
feeder_t	*fe = fc->fc_feeder;
struct sockaddr	*bind = NULL;
uv_connect_t	*req;

        if (!fc->fc_addrs) {
	uv_getaddrinfo_t	*req;
	struct addrinfo		 hints;

		bzero(&hints, sizeof(hints));
		hints.ai_family = PF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;

		req = xcalloc(1, sizeof(*req));
		req->data = fc;

                fc->fc_state = FS_DNS;
		
		if (ret = uv_getaddrinfo(loop, req, on_fconn_dns_done, 
					 fe->fe_server->se_send_to,
					 fe->fe_server->se_port,
					 &hints)) {
			nts_log("feeder: %s: uv_getaddrinfo: %s",
				fe->fe_server->se_name, uv_strerror(ret));
			time(&fe->fe_server->se_feeder_last_fail);
			fconn_destroy(fc);
			free(req);
		}
                return;
        }

	if (!fc->fc_cur_addr)
		fc->fc_cur_addr = fc->fc_addrs;

	fc->fc_state = FS_CONNECT;

        if (ret = getnameinfo((struct sockaddr *) fc->fc_cur_addr->ai_addr,
                        fc->fc_cur_addr->ai_addrlen,
                        host, sizeof(host), serv, sizeof(serv),
                        NI_NUMERICHOST | NI_NUMERICSERV)) {
                nts_log("feeder: %s: getnameinfo failed: %s",
                        fe->fe_server->se_name, gai_strerror(ret));
                time(&fe->fe_server->se_feeder_last_fail);
                fconn_destroy(fc);
                return;
        }

	snprintf(strname, sizeof(strname), "[%s]:%s", host, serv);
	free(fc->fc_strname);
	fc->fc_strname = xstrdup(strname);

        if (fc->fc_cur_addr->ai_family == AF_INET &&
            fe->fe_server->se_bind_v4.sin_family != 0) {
                bind = (struct sockaddr *) &fe->fe_server->se_bind_v4;
        } else if (fc->fc_cur_addr->ai_family == AF_INET6 &&
            fe->fe_server->se_bind_v6.sin6_family != 0) {
                bind = (struct sockaddr *) &fe->fe_server->se_bind_v6;
        }

	if (ret = uv_tcp_init(loop, &fc->fc_stream)) {
		fconn_log(LOG_ERR, fc, "uv_tcp_init: %s", uv_strerror(ret));
		return;
	}

	fc->fc_stream.data = fc;

	if (ret = uv_tcp_nodelay(&fc->fc_stream, 1)) {
		fconn_log(LOG_ERR, fc, "uv_tcp_nodelay: %s", uv_strerror(ret));
		return;
	}

	if (bind) {
		if (ret = uv_tcp_bind(&fc->fc_stream, bind)) {
			fconn_log(LOG_ERR, fc, "uv_tcp_bind: %s", uv_strerror(ret));
			fconn_destroy(fc);
			return;
		}
	}

	req = xcalloc(1, sizeof(*req));
	req->data = fc;
	if (ret = uv_tcp_connect(req, &fc->fc_stream, fc->fc_cur_addr->ai_addr,
				 on_fconn_connect_done)) {
		fconn_log(LOG_ERR, fc, "uv_tcp_connect: %s", uv_strerror(ret));
		fconn_destroy(fc);
		return;
	}

#if 0
	if (cf->log_connections)
		fconn_log(LOG_INFO, fc, "connected");
#endif

	fc->fc_cur_addr = fc->fc_cur_addr->ai_next;
	fc->fc_state = FS_WAIT_GREETING;
	time(&fc->fc_last_used);
	return;
}

static void
on_fconn_connect_done(req, status)
	uv_connect_t	*req;
{
fconn_t		*fc = req->data;

	if (status) {
		fconn_log(LOG_INFO, fc, "connect: %s", uv_strerror(status));

		if ((fc->fc_cur_addr = fc->fc_cur_addr->ai_next) == NULL) {
			fconn_log(LOG_INFO, fc, "out of addresses");
			time(&fc->fc_feeder->fe_last_fail);
			fconn_destroy(fc);
			return;
		}

		fconn_connect(fc);
		return;
	}

        fconn_log(LOG_INFO, fc, "connected");

        fc->fc_state = FS_WAIT_GREETING;
        time(&fc->fc_last_used);

	uv_read_start((uv_stream_t *) &fc->fc_stream, uv_alloc,
		      on_fconn_read);
}

/*
 * New data is available to read on a feeder connection.
 */
static void
on_fconn_read(stream, nread, buf)
	uv_stream_t	*stream;
	ssize_t		 nread;
	const uv_buf_t	*buf;
{
fconn_t		*fc = stream->data;
feeder_t	*fe = fc->fc_feeder;
char		*line;

	if (nread == 0) {
		free(buf->base);
		return;
	}

	if (nread < 0) {
		fconn_log(LOG_INFO, fc, "read error: %s",
			  uv_strerror(nread));
		time(&fc->fc_feeder->fe_last_fail);
		fconn_close(fc, 0);
		return;
	}

	cq_append(fc->fc_rdbuf, buf->base, buf->len);
	free(buf->base);

	/*
	 * Read lines from the connection until there are none left, or an
	 * error occurs.
	 */
	while (line = cq_read_line(fc->fc_rdbuf)) {
		/*
		 * Ignore empty lines -- altough perhaps we should close the
		 * connection here, as there shouldn't be any.
		 */
		if (strlen(line) == 0) {
			free(line);
			line = NULL;
			continue;
		}

		/*
		 * Dispatch the command to the handler for this state.  If the
		 * handler returns 1, an error occurred and we should close the
		 * connection.  Errors here are always fatal, so update the
		 * last error time.
		 *
		 * NULL handler means we shouldn't receive any data in this
		 * state (i.e., we're not connected yet), so abort.
		 */
		if (fconn_handlers[fc->fc_state] == NULL)
			abort();

		if (fconn_handlers[fc->fc_state](fc, line) == 1) {
			time(&fe->fe_last_fail);
			free(line);
			line = NULL;
			fconn_close(fc, 0);
			return;
		}

		free(line);
		line = NULL;

		/*
		 * dead is set when a write error occurs; there's no point
		 * trying to read further data, we'll just get an error.
		 */
		if (fc->fc_flags & FC_DEAD)
			return;
	}
}

/******
 * fconn_t state handlers.
 */

/*
 * Waiting for the initial server greeting.  Accept any 2xx code as valid
 * (even 201), but anything else is an error.  Send MODE STREAM after the
 * greeting.
 */
static int
fc_wait_greeting(fc, line)
	fconn_t	*fc;
	char	*line;
{
	if (line[0] != '2') {
		fconn_log(LOG_ERR, fc, "connection rejected: %s",
			line);
		return 1;
	} else {
		fconn_puts(fc, "MODE STREAM\r\n");
		fc->fc_state = FS_SENT_MODE_STREAM;
	}
	return 0;
}

/*
 * We sent MODE STREAM, this is the reply.  If the server agrees to streaming,
 * go straight to running mode.  Otherwise, try to probe streaming support
 * via CAPABILITIES.  We do MODE STREAM first because some servers (e.g.
 * Cyclone) will close the connection when a CAPABILITIES command is
 * received.
 */
static int
fc_sent_mode_stream(fc, line)
	fconn_t	*fc;
	char	*line;
{
char	*resp;

	if ((resp = next_word(&line)) == NULL) {
		fconn_log(LOG_INFO, fc, "invalid response to MODE STREAM");
		return 1;
	}

	if (strcmp(resp, "203") != 0) {
		fconn_puts(fc, "CAPABILITIES\r\n");
		fc->fc_state = FS_SENT_CAPABILITIES;
		return 0;
	}

	fc->fc_mode = FM_STREAM;
#if 0
	if (cf->log_connections)
#endif
		fconn_log(LOG_INFO, fc, "running: streaming mode");
	fc->fc_state = FS_RUNNING;
	feeder_notify(fc->fc_feeder);

	return 0;
}

/*
 * We sent CAPABILITIES, this should be the 101 response.  We already tried
 * MODE STREAM, so if we don't get streaming support here either, we must be
 * using IHAVE mode.
 */
static int
fc_sent_capabilities(fc, line)
	fconn_t	*fc;
	char	*line;
{
char	*resp;
	
	if ((resp = next_word(&line)) == NULL) {
		fconn_log(LOG_INFO, fc, "invalid response to CAPABILITIES");
		return 1;
	}

	if (strcmp(resp, "101") != 0) {
		fc->fc_state = FS_RUNNING;
#if 0
		if (cf->log_connections)
#endif
			fconn_log(LOG_INFO, fc, "running: IHAVE mode");
		feeder_notify(fc->fc_feeder);
	} else
		fc->fc_state = FS_READ_CAPABILITIES;

	return 0;
}

/*
 * Reading the CAPABILITIES response; one per line, termined with a ".".
 */
static int
fc_read_capabilities(fc, line)
	fconn_t	*fc;
	char	*line;
{
char	*cap;

	if ((cap = next_word(&line)) == NULL)
		/* Empty line, just ignore it. */
		return 0;

		
	if (strcmp(cap, ".") == 0) {
#if 0
		if (cf->log_connections)
#endif
			fconn_log(LOG_INFO, fc, "running: %s mode",
				fc->fc_mode == FM_STREAM ? "streaming" : "IHAVE");
		fc->fc_state = FS_RUNNING;
		feeder_notify(fc->fc_feeder);
	} else if (strcmp(cap, "STREAMING") == 0)
		fc->fc_mode = FM_STREAM;

	return 0;
}

/*
 * We're done with negotiation and received a line, which must be a reply
 * to a CHECK, TAKETHIS or IHAVE command we sent.
 */
static int
fc_running(fc, line)
	fconn_t	*fc;
	char	*line;
{
	/*
	 * 238 <msg-id>	-- CHECK, send the article
	 * 431 <msg-id>	-- CHECK, defer the article
	 * 438 <msg-id>	-- CHECK, never send the article
	 * 239 <msg-id>	-- TAKETHIS, accepted
	 * 439 <msg-id>	-- TAKETHIS, rejected
	 */
char	*resps = NULL, *resps_ = NULL, *msgid = NULL;
int	 resp;
qent_t	*qe;

	time(&fc->fc_last_used);

	/*
	 * Extract a valid response code and message-id from the server.
	 */
	if ((resps_ = next_word(&line)) == NULL) {
		fconn_log(LOG_INFO, fc, "invalid response from command [%s]",
			  line);
		return 1;
	}
	resps = resps_;

	if (strlen(resps) != 3) {
		/*
		 * INN <= 2.5.2 has a bug where it sometimes writes a single
		 * junk character after a reply's \r\n.  This shows up as a
		 * reply of the form "y438 <...".  Detect this and work
		 * around it.
		 */
		if (
#if 0
		fc->feeder->server->inn_workaround &&
#endif
		    strlen(resps) == 4 &&
		    isdigit(resps[1]) &&
		    isdigit(resps[2]) &&
		    isdigit(resps[3])) {
			resps++;
		} else {
			fconn_log(LOG_INFO, fc, "invalid response from command [%s%s]",
				  resps, line);
			return 1;
		}
	}

	resp = (resps[0] - '0') * 100
	     + (resps[1] - '0') * 10
	     + (resps[2] - '0');

	/*
	 * Make sure the response code is one that we recognise.  Codes that
	 * aren't handled here include 400 (for temporary failure) which
	 * e.g. INN sends after TAKETHIS when the server is paused.  For that,
	 * pausing and reconnecting later is fine.
	 *
	 * At the moment we don't handle 501.  The most reasonable thing
	 * to do here is probably to treat it as a reject for the last sent
	 * CHECK or TAKETHIS.
	 */

	if (resp != 238 && resp != 431 && resp != 438 && resp != 239 &&
	    resp != 439) {
		/*
		 * Unrecognised response code, close the connection.
		 */
		fconn_log(LOG_NOTICE, fc, "unrecognised response "
				"to command: %d %s", resp,
				line);
		return 1;
	}

	/*
	 * Extract a valid message-id, and make sure it matches one of the
	 * commands we previously sent; if it doesn't, something is out of
	 * sync, so close the connection and start again.
	 */
	if (!(msgid = next_word(&line))) {
		fconn_log(LOG_INFO, fc, "received %d response with no "
				"message-id", resp);
		return 1;
	}

	/*
	 * Find the qent for the oldest sent command, and make sure the
	 * message-id matches.  INN <= 2.5.2 has a bug where it sends
	 * invalid responses if the server is paused, e.g.
	 * 	431 Flush log and syslog files
	 * If we don't recognise the message-id, close the connection and
	 * try again later, by which time the server will hopefully be
	 * unpaused.
	 */
	if ((qe = TAILQ_FIRST(&fc->fc_cq)) == NULL) {
		fconn_log(LOG_INFO, fc, "received response without sending "
			  "any command: %d %s%s", resp,
			  msgid, line);
		return 1;
	}

	hash_remove(fc->fc_feeder->fe_pending, msgid, strlen(msgid));

	TAILQ_REMOVE(&fc->fc_cq, qe, qe_list);
	if (strcmp(qe->qe_msgid, msgid) == 0) {
		fconn_log(LOG_INFO, fc, "expected response for %s message-id "
			  "%s, but got %d %s%s",
			  qe->qe_cmd == QE_CHECK ? "CHECK" : "TAKETHIS",
			  qe->qe_msgid, resp,
			  msgid, line);
		qefree(qe);
		return 1;
	}

	--fc->fc_ncq;

	switch (resp) {
	case 238:	/* CHECK, send the article */
		/*
		 * fconn_takethis() will free the qe for us (actually, it goes
		 * straight back into the cq).
		 */
		fconn_takethis(fc, qe);
		break;

	case 431:	/* CHECK, defer the article */
		/*
		 * Move the article to the deferred queue.  For adaptive 
		 * feeding, treat this as a rejection, because the server would 
		 * probably have rejected the article if we'd tried to send it.  
		 * (431 nearly always means another server is sending the 
		 * article at the same time).
		 */
		++fc->fc_feeder->fe_server->se_out_deferred;

		server_defer(fc->fc_feeder->fe_server, qe);
		fconn_adp_check(fc, 0);
		break;

	case 438:	/* CHECK, never send the article */
		/*
		 * Remove the article from the q.
		 */
		server_remove_q(fc->fc_feeder->fe_server, qe);
		++fc->fc_feeder->fe_server->se_out_refused;

		qefree(qe);
		fconn_adp_check(fc, 0);
		break;

	case 239:	/* TAKETHIS, accepted */
	case 439:	/* TAKETHIS, rejected */
		/*
		 * Remove the article from the backlog, it's no longer our
		 * responsibility.  Only difference between these two is
		 * the statistic we increment.
		 */
		server_remove_q(fc->fc_feeder->fe_server, qe);

		if (resp == 239)
			++fc->fc_feeder->fe_server->se_out_accepted;
		else
			++fc->fc_feeder->fe_server->se_out_rejected;

		fconn_adp_check(fc, resp == 239 ? 1 : 0);
		qefree(qe);
		break;
	}
	return 0;
}

/*
 * Write data to a feeder connection -- va_list version.
 */
static void
fconn_vprintf(fc, fmt, ap)
	fconn_t		*fc;
	char const	*fmt;
	va_list		 ap;
{
char            *buf;
int              len;
uv_write_t      *wr;
uv_buf_t         ubuf;

#define PRINTF_BUFSZ    1024

	buf = malloc(PRINTF_BUFSZ);
	len = vsnprintf(buf, PRINTF_BUFSZ, fmt, ap);
	if ((unsigned int) len >= PRINTF_BUFSZ) {
		buf = xrealloc(buf, len + 1);
		vsnprintf(buf, len + 1, fmt, ap);
	}

	wr = xcalloc(1, sizeof(*wr));

	ubuf = uv_buf_init(buf, len);
	wr->data = fc;

	uv_write(wr, (uv_stream_t *) &fc->fc_stream, &ubuf, 1, on_fconn_write_done);
}

static void
on_fconn_write_done(wr, status)
	uv_write_t	*wr;
{
fconn_t	*fc = wr->data;

	free(wr->bufs[0].base);
	free(wr);

	if (status == 0)
		return;

	fconn_log(LOG_INFO, fc, "write error: %s", uv_strerror(status));
	fconn_close(fc, 0);
}

/*
 * Write raw data to a feeder connection.  This is more efficient than
 * fconn_printf, and never copies.
 */
static void
fconn_puts(fc, text)
	fconn_t		*fc;
	char const	*text;
{
uv_write_t	*wr;
uv_buf_t         ubuf;
	wr = xcalloc(1, sizeof(*wr));

	ubuf = uv_buf_init(xstrdup(text), strlen(text));
	wr->data = fc;

	uv_write(wr, (uv_stream_t *) &fc->fc_stream, &ubuf, 1, on_fconn_write_done);
}

/*
 * Write formatted data to a feeder connection.  Don't use this for large data 
 * (like articles) since it will do a needless malloc and copy.
 */
static void
fconn_printf(fconn_t *fc, char const *fmt, ...)
{
va_list	ap;
	va_start(ap, fmt);
	fconn_vprintf(fc, fmt, ap);
	va_end(ap);
}

/*
 * Log a message relating to the feeder.
 */
static void
feeder_log(int sev, feeder_t *fe, char const *fmt, ...)
{
va_list	ap;
	va_start(ap, fmt);
	feeder_vlog(sev, fe, fmt, ap);
	va_end(ap);
}

/*
 * Log a message relating to the feeder (va_list version).
 */
static void
feeder_vlog(sev, fe, fmt, ap)
	feeder_t	*fe;
	char const	*fmt;
	va_list		 ap;
{
char	buf[8192];
char	*r = buf;
int	len;

	/*
	 * Try to write it into a static buffer on the stack to avoid a
	 * malloc().  If it's too large, allocate space.
	 */
	len = vsnprintf(buf, sizeof(buf), fmt, ap);
	if ((unsigned int) len >= sizeof(buf)) {
		r = (char *) xmalloc(len + 1);
		vsnprintf(r, len + 1, fmt, ap);
	}

	nts_log("feeder: %s: %s", fe->fe_server->se_name, r);

	if (r != buf)
		free(r);
}

/*
 * Log a message relating to the feeder connection.
 */
static void
fconn_log(int sev, fconn_t *fc, char const *fmt, ...)
{
va_list	ap;
	va_start(ap, fmt);
	fconn_vlog(sev, fc, fmt, ap);
	va_end(ap);
}

/*
 * Log a message relating to the feeder connection (va_list version).
 */
static void
fconn_vlog(sev, fc, fmt, ap)
	fconn_t		*fc;
	char const	*fmt;
	va_list		 ap;
{
char	buf[8192];
char	*r = buf;
int	len;

	/*
	 * Try to write it into a static buffer on the stack to avoid a
	 * malloc().  If it's too large, allocate space.
	 */
	len = vsnprintf(buf, sizeof(buf), fmt, ap);
	if ((unsigned int) len >= sizeof (buf)) {
		r = (char *) xmalloc(len + 1);
		vsnprintf(r, len + 1, fmt, ap);
	}

	nts_log("feeder: %s%s: %s", fc->fc_feeder->fe_server->se_name, 
			fc->fc_strname, r);

	if (r != buf)
		free(r);
}

/*
 * Send a CHECK command for the given article and add it to the waiting list.
 */
static void
fconn_check(fc, qe)
	fconn_t	*fc;
	qent_t	*qe;
{
	/*
	 * If this article has already been offered, don't offer it
	 * again.  Can sometimes happen with a slow server when
	 * processing deferred articles.
	 */
	if (hash_find(fc->fc_feeder->fe_pending,
		      qe->qe_msgid,
		      strlen(qe->qe_msgid))) {
		qefree(qe);
		return;
	}

	/*
	 * Don't send a CHECK at all if we're in adaptive mode.
	 */
	if (fc->fc_feeder->fe_flags & FE_ADP) {
		fconn_takethis(fc, qe);
		return;
	} 

	hash_insert(fc->fc_feeder->fe_pending,
		    qe->qe_msgid,
		    strlen(qe->qe_msgid),
		    fc);

	time(&fc->fc_last_used);
	qe->qe_cmd = QE_CHECK;
	TAILQ_INSERT_TAIL(&fc->fc_cq, qe, qe_list);

	fconn_printf(fc, "CHECK %s\r\n", qe->qe_msgid);
	++fc->fc_ncq;
}

/*
 * Send a TAKETHIS command for the qe, and put it on the cq.  The caller
 * will have removed it already if it was there previously (from a CHECK).
 */
static void
fconn_takethis(fconn_t *fc, qent_t *qe)
{
spool_header_t	  hdr;
char		 *text;

	/*
	 * If this article has already been offered, don't offer it
	 * again.  Can sometimes happen with a slow server when
	 * processing deferred articles.
	 */
	if (hash_find(fc->fc_feeder->fe_pending,
		      qe->qe_msgid,
		      strlen(qe->qe_msgid))) {
		qefree(qe);
		return;
	}

	/*
	 * Most likely cause of this is that the spool file containing
	 * the article expired.
	 */
	if (!spool_fetch_text(qe->qe_pos.sp_id, qe->qe_pos.sp_offset, &hdr, &text)) {
		qefree(qe);
		return;
	}

	hash_insert(fc->fc_feeder->fe_pending,
		    qe->qe_msgid,
		    strlen(qe->qe_msgid),
		    fc);

	qe->qe_cmd = QE_TAKETHIS;
	time(&fc->fc_last_used);
	++fc->fc_ncq;
	TAILQ_INSERT_TAIL(&fc->fc_cq, qe, qe_list);

	fconn_printf(fc, "TAKETHIS %s\r\n%s.\r\n",
			qe->qe_msgid,
			text);
	free(text);
}

static void
feeder_load(fe, backlog)
	feeder_t	*fe;
{
int		 ret;
DB_TXN		*txn;
DBC		*curs;
DBT		 key, data;
DB		*db;
unsigned char	 pbuf[4 + 8];

int i = 0;
	if (backlog)
		db = fe->fe_server->se_deferred;
	else
		db = fe->fe_server->se_q;

	bzero(&key, sizeof(key));
	bzero(&data, sizeof(data));
	data.flags = DB_DBT_REALLOC;

	txn = db_new_txn(DB_TXN_WRITE_NOSYNC);
	db->cursor(db, txn, &curs, 0);

	/*
	 * If we're not processing backlog, set the cursor to point at the
	 * last entry we loaded.  This means we don't continually process
	 * the same queue entries forever when the queue is long.
	 *
	 * pos starts at 0, so on startup we'll start at the beginning
	 * of the queue.
	 */
	if (backlog) {
		if (ret = curs->get(curs, &key, &data, DB_FIRST)) {
			if (ret == DB_NOTFOUND) {
				curs->close(curs);
				txn->commit(txn, 0);
				return;
			}
			panic("cannot set cursor position: %s", db_strerror(ret));
		}

	} else {
		pack(pbuf, "uU", fe->fe_server->se_pos.sp_id,
				 fe->fe_server->se_pos.sp_offset);
		key.data = pbuf;
		key.size = sizeof(pbuf);

		if (ret = curs->get(curs, &key, &data, DB_SET_RANGE)) {
			if (ret == DB_NOTFOUND) {
				curs->close(curs);
				txn->commit(txn, 0);
				return;
			}
			panic("cannot set cursor position: %s", db_strerror(ret));
		}
	}

	for (;;) {
	qent_t		*qe;
	fconn_t		*fc;
	int		 nconns = 0, nfull = 0;

		assert(key.size == sizeof(uint32_t) + sizeof(uint64_t));

		qe = qealloc();
		unpack((unsigned char const *) key.data, "uU",
			&qe->qe_pos.sp_id,
			&qe->qe_pos.sp_offset);
		qe->qe_msgid = xmalloc(data.size + 1);
		bcopy(data.data, qe->qe_msgid, data.size);
		qe->qe_msgid[data.size] = 0;
		qe->qe_type = backlog ? QT_DEFERRED : QT_Q;

		/*
		 * Find a suitable fconn to put the command on.
		 */
		TAILQ_FOREACH(fc, &fe->fe_conns, fc_list) {
			nconns++;
			if (fc->fc_state < FS_RUNNING) 
				continue;
			if (fc->fc_flags & FC_FULL) {
				nfull++;
				continue;
			}
			break;
		}

		i++;
		/*
		 * If we found an idle fconn, use that to check the article;
		 * otherwise, open a new one, but only if all the feeders
		 * were busy, not if (e.g.) a new one is in the middle of
		 * connecting. 
		 */
		if (fc) {
			if (!backlog) {
				assert(qe->qe_pos.sp_id != 0x5A5A5A5A);
				bcopy(&qe->qe_pos, &fe->fe_server->se_pos,
					sizeof(fe->fe_server->se_pos));
			}
			fconn_check(fc, qe);

			if (ret = curs->get(curs, &key, &data, DB_NEXT)) {
				if (ret == DB_NOTFOUND)
					break;
				else
					panic("feeder: cannot read backlog: %s",
							db_strerror(ret));
			}
			continue;
		} else if (nconns == nfull &&
			   nconns < fe->fe_server->se_maxconns_out) {
			feeder_log(LOG_INFO, fe, "raising active connections to %d",
					nconns + 1);
			fc = fconn_new(fe);
			TAILQ_INSERT_HEAD(&fe->fe_conns, fc, fc_list);
			fconn_connect(fc);
		}
		qefree(qe);
		break;
	}

	free(data.data);
#if 0
	if (i)
printf("[%s] loaded %d articles from %s\n", fe->server->name,
		i, backlog ? "backlog" : "q");
#endif
	curs->close(curs);
	db_txn_commit(txn);
}

static void
fconn_close(fc, drain)
	fconn_t	*fc;
{
hash_table_t	*pending = fc->fc_feeder->fe_pending;
hash_item_t	*ie, *next;
size_t		 i;
qent_t		*qe;

	if (fc->fc_flags & (FC_DRAIN | FC_DEAD))
		return;

	if (!TAILQ_EMPTY(&fc->fc_cq)) {
		bzero(&fc->fc_feeder->fe_server->se_pos,
		      sizeof(fc->fc_feeder->fe_server->se_pos));

		while (qe = TAILQ_FIRST(&fc->fc_cq)) {
			TAILQ_REMOVE(&fc->fc_cq, qe, qe_list);
			qefree(qe);
		}
	}

	for (i = 0; i < pending->ht_nbuckets; i++) {
		LIST_FOREACH_SAFE(ie, &pending->ht_buckets[i], hi_link, next) {
			if (ie->hi_data == fc) {
				LIST_REMOVE(ie, hi_link);
				free(ie->hi_key);
				free(ie);
			}
		}
	}

	TAILQ_REMOVE(&fc->fc_feeder->fe_conns, fc, fc_list);

	uv_freeaddrinfo(fc->fc_addrs);

	if (drain) {
	uv_shutdown_t   *req = xcalloc(1, sizeof(*req));

		req->data = fc;
		fc->fc_flags |= FC_DRAIN;
		uv_shutdown(req, (uv_stream_t *) &fc->fc_stream, on_fconn_shutdown_done);
		return;
	}

	fc->fc_flags |= FC_DEAD;
	uv_close((uv_handle_t *) &fc->fc_stream, on_fconn_close_done);
}

static void
on_fconn_shutdown_done(req, status)
	uv_shutdown_t	*req;
{
fconn_t	*fc = req->data;
	free(req);
	uv_close((uv_handle_t *) &fc->fc_stream, on_fconn_close_done);
};

static void
on_fconn_close_done(handle)
	uv_handle_t	*handle;
{
fconn_t	*fc = handle->data;
	fconn_destroy(fc);
}

static void
fconn_destroy(fc)
	fconn_t	*fc;
{
	if (fc->fc_addrs)
		uv_freeaddrinfo(fc->fc_addrs);

	free(fc->fc_strname);
	free(fc);
}

static void
fconn_adp_check(fc, accepted)
	fconn_t	*fc;
{
feeder_t	*fe = fc->fc_feeder;
server_t	*se = fe->fe_server;

	++fe->fe_adp_count;

	if (accepted)
		++fe->fe_adp_accepted;

	if (fe->fe_adp_count < 100 || (se->se_adp_hi <= 0))
		return;

	if ((fe->fe_flags & FE_ADP) && (fe->fe_adp_accepted < se->se_adp_lo)) {
		fconn_log(LOG_INFO, fc, "server rejected %d/100 articles, switching "
				"back to normal feed", 100 - fe->fe_adp_accepted);
		fe->fe_flags &= ~FE_ADP;
	} else if ((!fe->fe_flags & FE_ADP) && (fe->fe_adp_accepted >= se->se_adp_hi)) {
		fconn_log(LOG_INFO, fc, "server accepted %d/100 articles, eliding "
				"CHECK commands", fe->fe_adp_accepted);
		fe->fe_flags |= FE_ADP;
	}

	fe->fe_adp_count = fe->fe_adp_accepted = 0;
}

fconn_t *
fconn_new(fe)
	feeder_t	*fe;
{
fconn_t	*fc;
	fc = xcalloc(1, sizeof(*fc));
	fc->fc_feeder = fe;
	TAILQ_INIT(&fc->fc_cq);

	return fc;
}

void
feeder_notify(fe)
	feeder_t	*fe;
{
	feeder_load(fe, 0);
}

static void
on_fconn_dns_done(req, err, res)
	uv_getaddrinfo_t	*req;
	struct addrinfo		*res;
{
fconn_t		*fc = req->data;
feeder_t        *fe = fc->fc_feeder;

        if (err) {
                nts_log("feeder: %s: cannot resolve: %s",
                        fe->fe_server->se_name,
                        uv_strerror(err));
                time(&fe->fe_server->se_feeder_last_fail);
                fconn_destroy(fc);
                return;
        }

	fc->fc_addrs = res;
        fconn_connect(fc);
}
