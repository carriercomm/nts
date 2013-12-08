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
#include	"net.h"
#include	"spool.h"
#include	"balloc.h"
#include	"dns.h"
#include	"config.h"
#include	"hash.h"

static balloc_t	 *ba_fc;

static feeder_t	*feeder_new(server_t *);
static void	 feeder_log(int sev, feeder_t *fe, char const *fmt, ...)
			attr_printf(3, 4);
static void	 feeder_vlog(int sev, feeder_t *fe, char const *fmt, va_list);
static void	 feeder_load(feeder_t *, int deferred);

static fconn_t	*fconn_new(feeder_t *);
static void	 fconn_connect(fconn_t *);
static void	 fconn_connect_done(int fd, int what, void *udata);
static void      fconn_err(int fd, int what, int err, void *udata);
static void	 fconn_read(int fd, int what, void *udata);
static void	 fconn_puts(fconn_t *, char const *text);
static void	 fconn_printf(fconn_t *, char const *fmt, ...) attr_printf(2, 3);
static void	 fconn_vprintf(fconn_t *, char const *fmt, va_list);
static void	 fconn_log(int sev, fconn_t *fe, char const *fmt, ...)
			attr_printf(3, 4);
static void	 fconn_vlog(int sev, fconn_t *fe, char const *fmt, va_list);
static void	 fconn_check(fconn_t *fe, qent_t *);
static void	 fconn_takethis(fconn_t *fe, qent_t *);
static void	 fconn_close(fconn_t *);
static void	 fconn_adp_check(fconn_t *, int accepted);
static void      fconn_dns_done(char const *name, int, address_list_t *, void *);

static int	 fc_wait_greeting(fconn_t *, str_t);
static int	 fc_sent_capabilities(fconn_t *, str_t);
static int	 fc_read_capabilities(fconn_t *, str_t);
static int	 fc_sent_mode_stream(fconn_t *, str_t);
static int	 fc_running(fconn_t *, str_t);
/* }}} */

static int (*fconn_handlers[]) (fconn_t *, str_t) = {
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
	ba_fc = balloc_new(sizeof(fconn_t), 64, "fconn");
	return 0;
}

int
feeder_run()
{
server_t	*se;
	SLIST_FOREACH(se, &servers, se_list) {
		se->se_feeder = feeder_new(se);
	}

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
socklen_t	 bindlen = 0;

        if (!fc->fc_addrs) {
                fc->fc_state = FS_DNS;
                dns_resolve(fe->fe_server->se_send_to, fe->fe_server->se_port,
                            DNS_TYPE_ANY, fconn_dns_done, fc);
                return;
        }

	if (!fc->fc_cur_addr)
		fc->fc_cur_addr = SIMPLEQ_FIRST(fc->fc_addrs);

	fc->fc_state = FS_CONNECT;

        if (ret = getnameinfo((struct sockaddr *) &fc->fc_cur_addr->ad_addr,
                        fc->fc_cur_addr->ad_len,
                        host, sizeof(host), serv, sizeof(serv),
                        NI_NUMERICHOST | NI_NUMERICSERV)) {
                nts_log(LOG_WARNING, "feeder: %s: getnameinfo failed: %s",
                        fe->fe_server->se_name, gai_strerror(ret));
                time(&fe->fe_server->se_feeder_last_fail);
                fconn_close(fc);
                return;
        }

	snprintf(strname, sizeof(strname), "[%s]:%s", host, serv);
	free(fc->fc_strname);
	fc->fc_strname = xstrdup(strname);

        if (fc->fc_cur_addr->ad_addr.ss_family == AF_INET &&
            fe->fe_server->se_bind_v4.sin_family != 0) {
                bind = (struct sockaddr *) &fe->fe_server->se_bind_v4;
                bindlen = sizeof(fe->fe_server->se_bind_v4);
        } else if (fc->fc_cur_addr->ad_addr.ss_family == AF_INET6 &&
            fe->fe_server->se_bind_v6.sin6_family != 0) {
                bind = (struct sockaddr *) &fe->fe_server->se_bind_v6;
                bindlen = sizeof(fe->fe_server->se_bind_v6);
        }

        net_connect(NET_DEFPRIO,
                        (struct sockaddr *) &fc->fc_cur_addr->ad_addr,
                        fc->fc_cur_addr->ad_len,
                        bind, bindlen,
                        fconn_connect_done,
                        fconn_err,
                        fconn_read,
                        fc);

#if 0
	if (cf->log_connections)
#endif
		fconn_log(LOG_INFO, fc, "connected");

	fc->fc_state = FS_WAIT_GREETING;
	time(&fc->fc_last_used);
	return;
}

static void
fconn_connect_done(fd, what, udata)
        void    *udata;
{
fconn_t		*fc = udata;
feeder_t	*fe = fc->fc_feeder;
int              one = 1;

        if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) == -1) {
                fconn_log(LOG_ERR, fc, "setsockopt(TCP_NODELAY): %s",
                        strerror(errno));
                time(&fe->fe_server->se_feeder_last_fail);
                fconn_close(fc);
                return;
        }

        fconn_log(LOG_INFO, fc, "connected");

        fc->fc_fd = fd;
        fc->fc_state = FS_WAIT_GREETING;
        time(&fc->fc_last_used);
}

/*
 * New data is available to read on a feeder connection.
 */
static void
fconn_read(fd, what, udata)
	void	*udata;
{
fconn_t		*fc = udata;
feeder_t	*fe = fc->fc_feeder;
str_t		 line;
int		 n;

	/*
	 * Read lines from the connection until there are none left, or an
	 * error occurs.
	 */
	while ((n = net_readline(fd, &line)) == 1) {
		/*
		 * Ignore empty lines -- altough perhaps we should close the
		 * connection here, as there shouldn't be any.
		 */
		if (str_length(line) == 0) {
			str_free(line);
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
			str_free(line);
			return;
		}

		/*
		 * dead is set when a write error occurs; there's no point
		 * trying to read further data, we'll just get an error.
		 */
		if (fc->fc_flags & FC_DEAD)
			return;
	}

	/*
	 * Close the connection if an error occurred reading data.  Update the
	 * last fail time so we don't reconnect too soon.
	 */
	if (n == -1) {
#if 0
		if (cf->log_connections)
#endif
			fconn_log(LOG_INFO, fc, "read error: %s", errno ? strerror(errno) : "EOF");
		time(&fc->fc_feeder->fe_last_fail);
		return;
	}
	return;
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
	str_t	 line;
{
	if (str_index(line, 0) != '2') {
		fconn_log(LOG_ERR, fc, "connection rejected: %.*s",
			str_printf(line));
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
	str_t	 line;
{
str_t	resp;

	if (!(resp = str_next_word(line))) {
		fconn_log(LOG_INFO, fc, "invalid response to MODE STREAM");
		return 1;
	}

	if (!str_equal_c(resp, "203")) {
		fconn_puts(fc, "CAPABILITIES\r\n");
		fc->fc_state = FS_SENT_CAPABILITIES;
		return 0;
	}

	fc->fc_mode = FM_STREAM;
#if 0
	if (cf->log_connections)
#endif
		fconn_log(LOG_INFO, fc, "running: %s mode",
			fc->fc_mode == FM_STREAM ? "streaming" : "IHAVE");
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
	str_t	 line;
{
str_t	resp;
	
	if (!(resp = str_next_word(line))) {
		fconn_log(LOG_INFO, fc, "invalid response to CAPABILITIES");
		return 1;
	}

	if (!str_equal_c(resp, "101")) {
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
	str_t	 line;
{
str_t	cap;

	if (!(cap = str_next_word(line)))
		/* Empty line, just ignore it. */
		return 0;

		
	if (str_equal_c(cap, ".")) {
#if 0
		if (cf->log_connections)
#endif
			fconn_log(LOG_INFO, fc, "running: %s mode",
				fc->fc_mode == FM_STREAM ? "streaming" : "IHAVE");
		fc->fc_state = FS_RUNNING;
		feeder_notify(fc->fc_feeder);
	} else if (str_equal_c(cap, "STREAMING"))
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
	str_t	 line;
{
	/*
	 * 238 <msg-id>	-- CHECK, send the article
	 * 431 <msg-id>	-- CHECK, defer the article
	 * 438 <msg-id>	-- CHECK, never send the article
	 * 239 <msg-id>	-- TAKETHIS, accepted
	 * 439 <msg-id>	-- TAKETHIS, rejected
	 */
str_t	 resps = NULL,  msgid = NULL;
int	 resp;
qent_t	*qe;

	time(&fc->fc_last_used);

	/*
	 * Extract a valid response code and message-id from the server.
	 */
	if (!(resps = str_next_word(line))) {
		fconn_log(LOG_INFO, fc, "invalid response from command [%.*s]",
			  str_printf(line));
		return 1;
	}

	if (str_length(resps) != 3) {
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
		    str_length(resps) == 4 &&
		    isdigit(str_index(resps, 1)) &&
		    isdigit(str_index(resps, 2)) &&
		    isdigit(str_index(resps, 3))) {
			str_remove_start(resps, 1);
		} else {
			fconn_log(LOG_INFO, fc, "invalid response from command [%.*s%.*s]",
				  str_printf(resps), str_printf(line));
			str_free(resps);
			return 1;
		}
	}

	resp = (str_index(resps, 0) - '0') * 100
		+ (str_index(resps, 1) - '0') * 10
		+ (str_index(resps, 2) - '0');
	str_free(resps);
	resps = NULL;

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
				"to command: %d %.*s", resp,
				str_printf(line));
		return 1;
	}

	/*
	 * Extract a valid message-id, and make sure it matches one of the
	 * commands we previously sent; if it doesn't, something is out of
	 * sync, so close the connection and start again.
	 */
	if (!(msgid = str_next_word(line))) {
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
			  "any command: %d %.*s%.*s", resp,
			  str_printf(msgid), str_printf(line));
		str_free(msgid);
		return 1;
	}

	hash_remove(fc->fc_feeder->fe_pending, str_begin(msgid), str_length(msgid));

	TAILQ_REMOVE(&fc->fc_cq, qe, qe_list);
	if (!str_equal(qe->qe_msgid, msgid)) {
		fconn_log(LOG_INFO, fc, "expected response for %s message-id "
			  "%.*s, but got %d %.*s%.*s",
			  qe->qe_cmd == QE_CHECK ? "CHECK" : "TAKETHIS",
			  str_printf(qe->qe_msgid), resp,
			  str_printf(msgid), str_printf(line));
		str_free(msgid);
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
char	 buf[8192];
char	*r = buf;
int	 len;

	/*
	 * Try to write it into a static buffer on the stack to avoid a
	 * malloc().  If it's too large, allocate space.
	 */
	len = vsnprintf(buf, sizeof(buf), fmt, ap);
	if ((unsigned int) len >= sizeof (buf)) {
		r = (char *) xmalloc(len + 1);
		vsnprintf(r, len + 1, fmt, ap);
	}

	net_write(fc->fc_fd, r, len);

	if (r != buf)
		free(r);
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
	net_write(fc->fc_fd, text, strlen(text));
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

	nts_log(sev, "feeder: %s: %s", fe->fe_server->se_name, r);

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

	nts_log(sev, "feeder: %s%s: %s", fc->fc_feeder->fe_server->se_name, 
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
char	buf[512];
int	len;

	/*
	 * If this article has already been offered, don't offer it
	 * again.  Can sometimes happen with a slow server when
	 * processing deferred articles.
	 */
	if (hash_find(fc->fc_feeder->fe_pending,
		      str_begin(qe->qe_msgid),
		      str_length(qe->qe_msgid))) {
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
		    str_begin(qe->qe_msgid),
		    str_length(qe->qe_msgid),
		    fc);

	time(&fc->fc_last_used);
	qe->qe_cmd = QE_CHECK;
	TAILQ_INSERT_TAIL(&fc->fc_cq, qe, qe_list);

	len = snprintf(buf, sizeof(buf), "CHECK %.*s\r\n", str_printf(qe->qe_msgid));
	net_write(fc->fc_fd, buf, len);
	++fc->fc_ncq;
}

/*
 * Send a TAKETHIS command for the qe, and put it on the cq.  The caller
 * will have removed it already if it was there previously (from a CHECK).
 */
static void
fconn_takethis(fconn_t *fc, qent_t *qe)
{
spool_header_t	 hdr;
str_t		 text;

	/*
	 * If this article has already been offered, don't offer it
	 * again.  Can sometimes happen with a slow server when
	 * processing deferred articles.
	 */
	if (hash_find(fc->fc_feeder->fe_pending,
		      str_begin(qe->qe_msgid),
		      str_length(qe->qe_msgid))) {
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
		    str_begin(qe->qe_msgid),
		    str_length(qe->qe_msgid),
		    fc);

	qe->qe_cmd = QE_TAKETHIS;
	time(&fc->fc_last_used);
	++fc->fc_ncq;
	TAILQ_INSERT_TAIL(&fc->fc_cq, qe, qe_list);

	fconn_printf(fc, "TAKETHIS %.*s\r\n%.*s.\r\n",
			str_printf(qe->qe_msgid),
			str_printf(text));
	str_free(text);
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
		qe->qe_msgid = str_new_cl(data.data, data.size);
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
fconn_close(fc)
	fconn_t	*fc;
{
hash_table_t	*pending = fc->fc_feeder->fe_pending;
hash_item_t	*ie, *next;
size_t		 i;
qent_t		*qe;

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

	alist_free(fc->fc_addrs);

	net_close(fc->fc_fd);
	free(fc->fc_strname);
	bfree(ba_fc, fc);
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
	fc = bzalloc(ba_fc);
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
fconn_dns_done(name, err, alist, udata)
        char const      *name;
        address_list_t  *alist;
        void            *udata;
{
fconn_t		*fc = udata;
feeder_t        *fe = fc->fc_feeder;

        if (err) {
                nts_log(LOG_ERR, "feeder: %s: cannot resolve: %s",
                        fe->fe_server->se_name,
                        dns_strerror(err));
                time(&fe->fe_server->se_feeder_last_fail);
                fconn_close(fc);
                return;
        }

        fc->fc_addrs = alist;
        fconn_connect(fc);
}

static void
fconn_err(fd, what, err, udata)
	void	*udata;
{
fconn_t		*fc = udata;
feeder_t	*fe = fc->fc_feeder;

	if (fc->fc_fd == 0) {
		fconn_log(LOG_INFO, fc, "connect: %s", strerror(err));
		if (SIMPLEQ_NEXT(fc->fc_cur_addr, ad_list) == NULL)
			fconn_log(LOG_INFO, fc, "out of addresses");
		else {
			fconn_connect(fc);
			return;
		}
	} else
		fconn_log(LOG_INFO, fc, "%s", err ? strerror(err) : "EOF");

	time(&fe->fe_server->se_feeder_last_fail);
	fconn_close(fc);
}
