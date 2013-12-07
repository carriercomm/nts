/* RT/NTS -- a lightweight, high performance news transit server. */
/* 
 * Copyright (c) 2011, 2012 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */
/* $Header: /cvsroot/nts/feeder.c,v 1.56 2012/01/10 17:14:13 river Exp $ */

#include	<sys/types.h>
#include	<sys/socket.h>

#include	<netinet/in.h>
#include	<netinet/tcp.h>

#include	<string.h>
#include	<errno.h>
#include	<stdio.h>
#include	<stdarg.h>
#include	<assert.h>

#include	"feeder.h"
#include	"nts.h"
#include	"server.h"
#include	"log.h"
#include	"net.h"
#include	"spool.h"
#include	"balloc.h"
#include	"dns.h"

static balloc_t	 *ba_ae;
static balloc_t	 *ba_fe;

static feeder_t	*feeder_new(server_t *);
static void	 feeder_connect(feeder_t *);
static void	 feeder_connect_done(int fd, int what, void *udata);
static void	 feeder_err(int fd, int what, int err, void *udata);
static void	 feeder_read(int fd, int what, void *udata);
static void	 feeder_printf(feeder_t *, char const *fmt, ...) attr_printf(2, 3);
static void	 feeder_vprintf(feeder_t *, char const *fmt, va_list);
static void	 feeder_log(int sev, feeder_t *fe, char const *fmt, ...)
			attr_printf(3, 4);
static void	 feeder_vlog(int sev, feeder_t *fe, char const *fmt, va_list);
static void	 feeder_check(feeder_t *fe, article_entry_t *ae);
static void	 feeder_takethis(feeder_t *fe, article_entry_t *ae);
static void	 feeder_resend_backlog(void *);
static void	 feeder_load_backlog(feeder_t *);
static void	 feeder_go(feeder_t *);
static void	 feeder_close(feeder_t *);
static void	 feeder_remove_backlog(feeder_t *, article_t *);
static void	 feeder_adp_check(feeder_t *, int accepted);
static void	 feeder_dns_done(char const *name, int, address_list_t *, void *);
static void	 feeder_close_impl(void *);

static int	 fe_connect(feeder_t *, str_t);
static int	 fe_wait_greeting(feeder_t *, str_t);
static int	 fe_sent_capabilities(feeder_t *, str_t);
static int	 fe_read_capabilities(feeder_t *, str_t);
static int	 fe_sent_mode_stream(feeder_t *, str_t);
static int	 fe_running(feeder_t *, str_t);

static int (*feeder_handlers[]) (feeder_t *, str_t) = {
	NULL,
	fe_connect,
	fe_wait_greeting,
	fe_sent_capabilities,
	fe_read_capabilities,
	fe_sent_mode_stream,
	fe_running
};

#define MAXQ	35

int
feeder_init()
{
	ba_fe = balloc_new(sizeof(feeder_t), 64, "feeder");
	ba_ae = balloc_new(sizeof(article_entry_t), 512, "article_entry");
	return 0;
}

int
feeder_run()
{
#if 1
	net_cron(30, feeder_resend_backlog, NULL);
#endif
	return 0;
}

static feeder_t *
feeder_new(se)
	server_t	*se;
{
feeder_t	*fe;

	fe = bzalloc(ba_fe);

	fe->fe_strname = xstrdup(se->se_name);
	fe->fe_server = se;

	SIMPLEQ_INIT(&fe->fe_send_queue);

	if (se->se_adp_hi == 0)
		fe->fe_flags |= FE_ADP;

	fe->fe_waiting_hash = hash_new(128, NULL, NULL, NULL);
	fe->fe_type = FT_BACKLOG;
	return fe;
}

static void
feeder_dns_done(name, err, alist, udata)
	char const	*name;
	address_list_t	*alist;
	void		*udata;
{
feeder_t	*fe = udata;

	if (err) {
		nts_log(LOG_ERR, "feeder: %s: cannot resolve: %s",
			fe->fe_server->se_name,
			dns_strerror(err));
		time(&fe->fe_server->se_feeder_last_fail);
		feeder_close(fe);
		return;
	}

	fe->fe_addrs = alist;
	feeder_connect(fe);
}

static void
feeder_connect(fe)
	feeder_t	*fe;
{
char		 strname[1024 + NI_MAXHOST + NI_MAXSERV + 1];
char		 host[NI_MAXHOST], serv[NI_MAXSERV];
struct sockaddr	*bind = NULL;
socklen_t	 bindlen = 0;
int		 ret;

	if (!fe->fe_addrs) {
		fe->fe_state = FS_DNS;
		dns_resolve(fe->fe_server->se_send_to, fe->fe_server->se_port,
			    DNS_TYPE_ANY, feeder_dns_done, fe);
		return;
	}

	if (fe->fe_cur_addr)
		fe->fe_cur_addr = SIMPLEQ_NEXT(fe->fe_cur_addr, ad_list);
	if (fe->fe_cur_addr == NULL)
		fe->fe_cur_addr = SIMPLEQ_FIRST(fe->fe_addrs);

	fe->fe_state = FS_CONNECT;

	if (ret = getnameinfo((struct sockaddr *) &fe->fe_cur_addr->ad_addr, 
			fe->fe_cur_addr->ad_len,
			host, sizeof(host), serv, sizeof(serv),
			NI_NUMERICHOST | NI_NUMERICSERV)) {
		nts_log(LOG_WARNING, "feeder: %s: getnameinfo failed: %s",
			fe->fe_server->se_name, gai_strerror(ret));
		time(&fe->fe_server->se_feeder_last_fail);
		feeder_close(fe);
		return;
	}

	snprintf(strname, sizeof(strname), "[%s]:%s", host, serv);
	free(fe->fe_strname);
	fe->fe_strname = xstrdup(strname);

	if (fe->fe_cur_addr->ad_addr.ss_family == AF_INET &&
	    fe->fe_server->se_bind_v4.sin_family != 0) {
		bind = (struct sockaddr *) &fe->fe_server->se_bind_v4;
		bindlen = sizeof(fe->fe_server->se_bind_v4);
	} else if (fe->fe_cur_addr->ad_addr.ss_family == AF_INET6 &&
	    fe->fe_server->se_bind_v6.sin6_family != 0) {
		bind = (struct sockaddr *) &fe->fe_server->se_bind_v6;
		bindlen = sizeof(fe->fe_server->se_bind_v6);
	}

	net_connect(NET_DEFPRIO,
			(struct sockaddr *) &fe->fe_cur_addr->ad_addr,
			fe->fe_cur_addr->ad_len,
			bind, bindlen,
			feeder_connect_done,
			feeder_err,
			feeder_read,
			fe);
}

static void
feeder_connect_done(fd, what, udata)
	void	*udata;
{
feeder_t	*fe = udata;
int		 one = 1;

	if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) == -1) {
		feeder_log(LOG_ERR, fe, "setsockopt(TCP_NODELAY): %s",
			strerror(errno));
		time(&fe->fe_server->se_feeder_last_fail);
		feeder_close(fe);
		return;
	}

	feeder_log(LOG_INFO, fe, "connected");

	fe->fe_fd = fd;
	fe->fe_state = FS_WAIT_GREETING;
	time(&fe->fe_last_used);
}

static void
feeder_err(fd, what, err, udata)
	void	*udata;
{
feeder_t	*fe = udata;

	if (fe->fe_fd == 0) {
		feeder_log(LOG_INFO, fe, "connect: %s", strerror(err));
		if (SIMPLEQ_NEXT(fe->fe_cur_addr, ad_list) == NULL)
			feeder_log(LOG_INFO, fe, "out of addresses");
		else {
			feeder_connect(fe);
			return;
		}
	} else
		feeder_log(LOG_INFO, fe, "%s", err ? strerror(err) : "EOF");

	time(&fe->fe_server->se_feeder_last_fail);
	feeder_close(fe);
}

void
feeder_notify_article(art)
	article_t	*art;
{
server_t	*se;
DB_TXN		*txn;
int		 ret;
	
	art->art_refs = 0;

	txn = db_new_txn(0);

	SLIST_FOREACH(se, &servers, se_list) {
	feeder_t	*fe = se->se_feeder;

		if (!se->se_send_to || !server_wants_article(se, art))
			continue;

		server_add_backlog(se, art, txn);

		if (!fe) {
			if (se->se_feeder_last_fail + 60 > time(NULL))
				continue;

			se->se_feeder = feeder_new(se);
			feeder_connect(se->se_feeder);
			continue;
		}

		if (fe->fe_state < FS_RUNNING || fe->fe_type != FT_REALTIME)
			continue;

		if (SIMPLEQ_EMPTY(&fe->fe_send_queue)) {
		article_entry_t	*ae;

			if (!server_wants_article(se, art))
				continue;

			ae = bzalloc(ba_ae);
			++art->art_refs;
			++fe->fe_send_queue_size;
			ae->ae_article = art;
			SIMPLEQ_INSERT_TAIL(&fe->fe_send_queue, ae, ae_list);
			feeder_go(fe);
		}
	}

	if (ret = txn->commit(txn, 0))
		panic("cannot commit backlog txn: %s", db_strerror(ret));
}

static void
feeder_read(fd, what, udata)
	void	*udata;
{
feeder_t	*fe = udata;
str_t		 line;
int		 n;

	while ((n = net_readline(fe->fe_fd, &line)) == 1) {
		if (str_length(line) == 0) {
			str_free(line);
			continue;
		}

		if (feeder_handlers[fe->fe_state](fe, line) == 1) {
			str_free(line);
			feeder_close(fe);
			return;
		}

		str_free(line);

		if (fe->fe_flags & FE_DEAD)
			return;
	}

	if (n == -1) {
		feeder_log(LOG_INFO, fe, "read error: %s", errno ? strerror(errno) : "EOF");
		time(&fe->fe_server->se_feeder_last_fail);
		feeder_close(fe);
	}
}

static int 
fe_connect(fe, line)
	feeder_t	*fe;
	str_t		 line;
{
	abort();
}

static int
fe_wait_greeting(fe, line)
	feeder_t	*fe;
	str_t		 line;
{
	if (str_index(line, 0) != '2') {
		feeder_log(LOG_ERR, fe, "connection rejected: %.*s",
			str_printf(line));
		time(&fe->fe_server->se_feeder_last_fail);
		return 1;
	} else {
		feeder_printf(fe, "MODE STREAM\r\n");
		fe->fe_state = FS_SENT_MODE_STREAM;
	}
	return 0;
}

static int
fe_sent_capabilities(fe, line)
	feeder_t	*fe;
	str_t		 line;
{
str_t	resp;
	
	if ((resp = str_next_word(line)) == NULL) {
		feeder_log(LOG_INFO, fe, "invalid response to CAPABILITIES");
		time(&fe->fe_server->se_feeder_last_fail);
		return 1;
	}

	if (!str_equal_c(resp, "101")) {
		fe->fe_state = FS_RUNNING;
		feeder_log(LOG_INFO, fe, "running: IHAVE mode");
		feeder_go(fe);
	} else
		fe->fe_state = FS_READ_CAPABILITIES;

	str_free(resp);
	return 0;
}

static int
fe_read_capabilities(fe, line)
	feeder_t	*fe;
	str_t		 line;
{
str_t	cap;
	if ((cap = str_next_word(line)) == NULL)
		/* Empty line, just ignore it. */
		return 0;

	if (str_equal_c(cap, ".")) {
		feeder_log(LOG_INFO, fe, "running: %s mode",
			fe->fe_mode == FM_STREAM ? "streaming" : "IHAVE");
		fe->fe_state = FS_RUNNING;
		feeder_go(fe);
	} else if (str_equal_c(cap, "STREAMING"))
		fe->fe_mode = FM_STREAM;

	str_free(cap);
	return 0;
}

static int
fe_sent_mode_stream(fe, line)
	feeder_t	*fe;
	str_t		 line;
{
str_t	resp;

	if ((resp = str_next_word(line)) == NULL) {
		feeder_log(LOG_INFO, fe, "invalid response to MODE STREAM");
		time(&fe->fe_server->se_feeder_last_fail);
		return 1;
	}

	if (str_equal_c(resp, "203")) {
		fe->fe_mode = FM_STREAM;
		feeder_log(LOG_INFO, fe, "running: %s mode",
			fe->fe_mode == FM_STREAM ? "streaming" : "IHAVE");
		fe->fe_state = FS_RUNNING;
		feeder_go(fe);
	} else {
		feeder_printf(fe, "CAPABILITIES\r\n");
		fe->fe_state = FS_SENT_CAPABILITIES;
	}

	str_free(resp);
	return 0;
}

static int
fe_running(fe, line)
	feeder_t	*fe;
	str_t		 line;
{
	/*
	 * 238 <msg-id>	-- CHECK, send the article
	 * 431 <msg-id>	-- CHECK, defer the article
	 * 438 <msg-id>	-- CHECK, never send the article
	 * 239 <msg-id>	-- TAKETHIS, accepted
	 * 439 <msg-id>	-- TAKETHIS, rejected
	 */
str_t		 resps = NULL, msgid = NULL;
int		 resp;
article_entry_t	*ae;
article_t	*art;

	if ((resps = str_next_word(line)) == NULL) {
		feeder_log(LOG_INFO, fe, "invalid response from command");
		time(&fe->fe_server->se_feeder_last_fail);
		return 1;
	}

	if (str_length(resps) != 3) {
		str_free(resps);
		feeder_log(LOG_INFO, fe, "invalid response from command");
		time(&fe->fe_server->se_feeder_last_fail);
		return 1;
	}

	resp = (str_index(resps, 0) - '0') * 100
		+ (str_index(resps, 1) - '0') * 10
		+ (str_index(resps, 2) - '0');
	str_free(resps);

	if ((msgid = str_next_word(line)) == NULL) {
		feeder_log(LOG_INFO, fe, "invalid response from command");
		time(&fe->fe_server->se_feeder_last_fail);
		return 1;
	}

	if (resp == 238 || resp == 431 || resp == 438 || resp == 239 || resp == 439) {
		if (!(ae = hash_remove(fe->fe_waiting_hash,
				str_begin(msgid), str_length(msgid)))) {
			time(&fe->fe_server->se_feeder_last_fail);
			feeder_log(LOG_INFO, fe, "received %d response for "
					"unexpected message-id %.*s",
					resp, str_printf(msgid));
			str_free(msgid);
			return 1;
		}
	} else {
		time(&fe->fe_server->se_feeder_last_fail);
		feeder_log(LOG_NOTICE, fe, "unrecognised response "
				"to command: %d %.*s %.*s",
				resp, str_printf(msgid), str_printf(line));
		str_free(msgid);
		return 1;
	}

	art = ae->ae_article;
	str_free(msgid);

	--fe->fe_waiting_size;

	switch (resp) {
	case 238:	/* CHECK, send the article */
		feeder_takethis(fe, ae);
		break;

	case 431:	/* CHECK, defer the article */
		++fe->fe_server->se_out_deferred;
		++fe->fe_defer;

		art_deref(art);
		bfree(ba_ae, ae);
		feeder_adp_check(fe, 0);
		break;

	case 438:	/* CHECK, never send the article */
		feeder_remove_backlog(fe, art);
		++fe->fe_server->se_out_refused;
		++fe->fe_refuse;

		art_deref(art);
		bfree(ba_ae, ae);
		feeder_adp_check(fe, 0);
		feeder_go(fe);
		break;

	case 239:	/* TAKETHIS, accepted */
		feeder_remove_backlog(fe, art);

		++fe->fe_server->se_out_accepted;
		++fe->fe_accept;
		art_deref(art);
		bfree(ba_ae, ae);
		feeder_adp_check(fe, 1);
		feeder_go(fe);
		break;

	case 439:	/* TAKETHIS, rejected */
		feeder_remove_backlog(fe, art);

		++fe->fe_server->se_out_rejected;
		++fe->fe_reject;
		art_deref(art);
		bfree(ba_ae, ae);
		feeder_adp_check(fe, 0);
		feeder_go(fe);
		break;
	}

	return 0;
}

static void
feeder_vprintf(fe, fmt, ap)
	feeder_t	*fe;
	char const	*fmt;
	va_list		 ap;
{
char	 buf[8192];
char	*r = buf;
int	 len;

	len = vsnprintf(buf, sizeof(buf), fmt, ap);
	if ((unsigned int) len >= sizeof (buf)) {
		r = xmalloc(len + 1);
		vsnprintf(r, len + 1, fmt, ap);
	}

	net_write(fe->fe_fd, r, len);

	if (r != buf)
		free(r);
}

static void
feeder_printf(feeder_t *fe, char const *fmt, ...)
{
va_list	ap;
	va_start(ap, fmt);
	feeder_vprintf(fe, fmt, ap);
	va_end(ap);
}

static void
feeder_log(int sev, feeder_t *fe, char const *fmt, ...)
{
va_list	ap;
	va_start(ap, fmt);
	feeder_vlog(sev, fe, fmt, ap);
	va_end(ap);
}

static void
feeder_vlog(int sev, feeder_t *fe, char const *fmt, va_list ap)
{
char	buf[8192];
char	*r = buf;
int	len;

	len = vsnprintf(buf, sizeof(buf), fmt, ap);
	if ((unsigned int) len >= sizeof (buf)) {
		r = xmalloc(len + 1);
		vsnprintf(r, len + 1, fmt, ap);
	}

	nts_log(sev, "feeder: %s%s: %s", fe->fe_server->se_name, 
			fe->fe_strname, r);

	if (r != buf)
		free(r);
}

static void
feeder_check(fe, ae)
	feeder_t	*fe;
	article_entry_t	*ae;
{
	if (fe->fe_flags & FE_ADP) {
		feeder_takethis(fe, ae);
	} else {
		time(&fe->fe_last_used);
		hash_insert(fe->fe_waiting_hash, str_begin(ae->ae_article->art_msgid),
				str_length(ae->ae_article->art_msgid), ae);

		net_pause(fe->fe_fd);
		net_write(fe->fe_fd, "CHECK ", 6);
		net_write(fe->fe_fd, str_begin(ae->ae_article->art_msgid),
				str_length(ae->ae_article->art_msgid));
		net_write(fe->fe_fd, "\r\n", 2);
		net_unpause(fe->fe_fd);
		++fe->fe_waiting_size;
	}
}

static void
feeder_takethis(fe, ae)
	feeder_t	*fe;
	article_entry_t	*ae;
{
	time(&fe->fe_last_used);
	++fe->fe_waiting_size;
	hash_insert(fe->fe_waiting_hash, str_begin(ae->ae_article->art_msgid),
			str_length(ae->ae_article->art_msgid), ae);

	net_pause(fe->fe_fd);
	net_write(fe->fe_fd, "TAKETHIS ", 9);
	net_write(fe->fe_fd, str_begin(ae->ae_article->art_msgid),
			str_length(ae->ae_article->art_msgid));
	net_write(fe->fe_fd, "\r\n", 2);
	net_write(fe->fe_fd, str_begin(ae->ae_article->art_content),
			str_length(ae->ae_article->art_content));
	net_write(fe->fe_fd, ".\r\n", 3);
	net_unpause(fe->fe_fd);
}

static void
feeder_resend_backlog(udata)
	void	*udata;
{
server_t	*se;
	SLIST_FOREACH(se, &servers, se_list) {
		if (!se->se_send_to)
			continue;
		if (!server_has_backlog(se))
			continue;

		if (!se->se_feeder) {
			if (se->se_feeder_last_fail + 60 > time(NULL))
				continue;

			se->se_feeder = feeder_new(se);
			feeder_connect(se->se_feeder);
		} else if (se->se_feeder->fe_state == FS_RUNNING) {
			feeder_load_backlog(se->se_feeder);
			feeder_go(se->se_feeder);
		}
	}
}

static void
feeder_load_backlog(fe)
	feeder_t	*fe;
{
int		 ret;
DB_TXN		*txn;
DBC		*curs;
int		 n = 50;
server_t	*se = fe->fe_server;
DBT		 key, data;
char		 dbuf[sizeof(uint32_t) + sizeof(uint64_t)];

	if (fe->fe_send_queue_size >= MAXQ)
		return;

	bzero(&key, sizeof(key));
	bzero(&data, sizeof(data));
	key.data = dbuf;
	key.size = sizeof(dbuf);

	txn = db_new_txn(0);
	se->se_backlog_db->cursor(se->se_backlog_db, txn, &curs, 0);

	if (fe->fe_type == FT_BACKLOG && fe->fe_spool_pos.sp_offset != 0) {
		int32put(dbuf, fe->fe_spool_pos.sp_id);
		int64put(dbuf + sizeof(uint32_t), fe->fe_spool_pos.sp_offset);
		if ((ret = curs->get(curs, &key, &data, DB_SET_RANGE)) == DB_NOTFOUND) {
			curs->close(curs);
			txn->commit(txn, 0);
			return;
		}
	}

	while (n > 0 && fe->fe_send_queue_size < MAXQ) {
	spool_pos_t	 pos;
	article_t	*art;
	article_entry_t	*ae;

		if (ret = curs->get(curs, &key, &data, DB_NEXT)) {
			if (ret == DB_NOTFOUND) {
				fe->fe_type = FT_REALTIME;
				bzero(&fe->fe_spool_pos, sizeof(fe->fe_spool_pos));
				break;
			} else
				panic("feeder: cannot read backlog: %s",
						db_strerror(ret));
		}

		assert(key.size == sizeof(uint32_t) + sizeof(uint64_t));
		pos.sp_id = int32get(key.data);
		pos.sp_offset = int64get(key.data + sizeof(uint32_t));

		bcopy(&pos, &fe->fe_spool_pos, sizeof(pos));

		if ((art = spool_fetch(pos.sp_id, pos.sp_offset)) == NULL) {
			curs->del(curs, 0);
			continue;
		}

		if (hash_find(fe->fe_waiting_hash, str_begin(art->art_msgid),
					str_length(art->art_msgid))) {
			article_free(art);
			break;
		}

		ae = bzalloc(ba_ae);
		art->art_refs = 1;
		ae->ae_article = art;
		SIMPLEQ_INSERT_TAIL(&fe->fe_send_queue, ae, ae_list);
		++fe->fe_send_queue_size;
		n--;
	}

	curs->close(curs);
	db_txn_commit(txn);
}

static void
feeder_go(fe)
	feeder_t	*fe;
{
	while (fe->fe_waiting_size < MAXQ) {
	article_entry_t	*ae;

		if (fe->fe_type == FT_BACKLOG &&
		    fe->fe_send_queue_size < MAXQ)
			feeder_load_backlog(fe);

		if (SIMPLEQ_EMPTY(&fe->fe_send_queue))
			return;

		ae = SIMPLEQ_FIRST(&fe->fe_send_queue);
		SIMPLEQ_REMOVE_HEAD(&fe->fe_send_queue, ae_list);
		--fe->fe_send_queue_size;

		if (hash_find(fe->fe_waiting_hash,
					str_begin(ae->ae_article->art_msgid),
					str_length(ae->ae_article->art_msgid))) {
			art_deref(ae->ae_article);
			bfree(ba_ae, ae);
			continue;
		}
		feeder_check(fe, ae);
	}
}

static void
feeder_close(fe)
	feeder_t	*fe;
{
	if (fe->fe_flags & FE_DEAD)
		return;
	fe->fe_flags |= FE_DEAD;
	feeder_log(LOG_INFO, fe, "offer %d, accept %d, defer %d, refuse %d, reject %d",
			fe->fe_offer, fe->fe_accept, fe->fe_defer,
			fe->fe_refuse, fe->fe_reject);
	net_soon(feeder_close_impl, fe);
}

static void
feeder_close_impl(udata)
	void	*udata;
{
feeder_t	*fe = udata;
article_entry_t	*ae;
address_t	*addr;
size_t		 i;

	while (ae = SIMPLEQ_FIRST(&fe->fe_send_queue)) {
		SIMPLEQ_REMOVE_HEAD(&fe->fe_send_queue, ae_list);
		art_deref(ae->ae_article);
		bfree(ba_ae, ae);
	}

	for (i = 0; i < fe->fe_waiting_hash->ht_nbuckets; i++) {
	hash_item_t	*ie, *next;
		LIST_FOREACH_SAFE(ie, &fe->fe_waiting_hash->ht_buckets[i], hi_link, next) {
		article_entry_t	*ae = ie->hi_data;
			LIST_REMOVE(ie, hi_link);
			art_deref(ae->ae_article);
			bfree(ba_ae, ae);
			free(ie->hi_key);
			free(ie);
		}
	}
	hash_free(fe->fe_waiting_hash);

	if (fe->fe_addrs) {
		while (addr = SIMPLEQ_FIRST(fe->fe_addrs)) {
			SIMPLEQ_REMOVE_HEAD(fe->fe_addrs, ad_list);
			free(addr);
		}
	}

	fe->fe_server->se_feeder = NULL;
	if (fe->fe_fd)
		net_close(fe->fe_fd);
	free(fe->fe_strname);
	bfree(ba_fe, fe);
}

static void
feeder_remove_backlog(fe, art)
	feeder_t	*fe;
	article_t	*art;
{
DBT	key;
int	ret;
char	dbuf[sizeof(uint32_t) + sizeof(uint64_t)];
DB_TXN	*txn;

	int32put(dbuf, art->art_spool_pos.sp_id);
	int64put(dbuf + sizeof(uint32_t), 
		art->art_spool_pos.sp_offset);

	bzero(&key, sizeof(key));
	key.data = dbuf;
	key.size = sizeof(dbuf);

	txn = db_new_txn(DB_TXN_WRITE_NOSYNC);
	if (ret = fe->fe_server->se_backlog_db->del(
			fe->fe_server->se_backlog_db, txn, &key, 0))
	/*	if (ret != DB_NOTFOUND)*/
	/*		panic("cannot remove backlog entry: %s",
					db_strerror(ret));*/
		nts_log(LOG_WARNING, "cannot remove backlog entry %.8lX,%lu: %s",
				(long unsigned) art->art_spool_pos.sp_id,
				(long unsigned) art->art_spool_pos.sp_offset,
				db_strerror(ret));
	txn->commit(txn, 0);
}

static void
feeder_adp_check(fe, accepted)
	feeder_t	*fe;
{
server_t	*se = fe->fe_server;

	++fe->fe_adp_count;

	if (accepted)
		++fe->fe_adp_accepted;

	if (fe->fe_adp_count < 100 || (se->se_adp_hi <= 0))
		return;


	if ((fe->fe_flags & FE_ADP) && (fe->fe_adp_accepted < se->se_adp_lo)) {
		feeder_log(LOG_INFO, fe, "server rejected %d/100 articles, switching "
				"back to normal feed", 100 - fe->fe_adp_accepted);
		fe->fe_flags &= ~FE_ADP;
	} else if (!(fe->fe_flags & FE_ADP) && (fe->fe_adp_accepted >= se->se_adp_hi)) {
		feeder_log(LOG_INFO, fe, "server accepted %d/100 articles, eliding "
				"CHECK commands", fe->fe_adp_accepted);
		fe->fe_flags |= FE_ADP;
	}

	fe->fe_adp_count = fe->fe_adp_accepted = 0;
}
