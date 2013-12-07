/* RT/NTS -- a lightweight, high performance news transit server. */
/* 
 * Copyright (c) 2011, 2012 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */
/* $Header: /cvsroot/nts/client.c,v 1.56 2012/01/10 17:13:42 river Exp $ */

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

#include	<openssl/ssl.h>
#include	<openssl/err.h>

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
#include	"setup.h"
#include	"balloc.h"
#include	"auth.h"
#include	"thread.h"
#include	"emp.h"
#include	"str.h"

static listener_t *listeners;

static void	 client_accept(int, struct sockaddr *addr, socklen_t len, SSL *ssl, void *udata);
static void	 client_read(int fd, int what, void *udata);
static void	 client_error(int fd, int what, int err, void *udata);
static void	*client_filter(void *);
static void	 client_filter_done(void *);
static void	 client_pause(client_t *);
static int	 client_unpause(client_t *);
static void	 client_tls_done(int fd, SSL *ssl, void *udata);

static void *listen_stanza_start(conf_stanza_t *, void *);
static void  listen_stanza_end(conf_stanza_t *, void *);
static void  listen_set_ssl(conf_stanza_t *, conf_option_t *, void *, void *);
static void  listen_set_ssl_key(conf_stanza_t *, conf_option_t *, void *, void *);
static void  listen_set_ssl_certificate(conf_stanza_t *, conf_option_t *, void *, void *);
static void  listen_set_ssl_cyphers(conf_stanza_t *, conf_option_t *, void *, void *);

static config_schema_opt_t listen_opts[] = {
	{ "ssl",		OPT_TYPE_STRING,	listen_set_ssl	},
	{ "ssl-certificate",	OPT_TYPE_STRING,	listen_set_ssl_certificate },
	{ "ssl-key",		OPT_TYPE_STRING,	listen_set_ssl_key },
	{ "ssl-cyphers",	OPT_TYPE_STRING,	listen_set_ssl_cyphers },
	{ "ssl-ciphers",	OPT_TYPE_STRING,	listen_set_ssl_cyphers }
};

static config_schema_stanza_t listen_stanza = {
	"listen", 
	SC_MANY | SC_REQTITLE, 
	listen_opts, 
	listen_stanza_start, 
	listen_stanza_end
};

static void	 pending_init(void);
static int	 pending_check(str_t msgid);
static void	 pending_add(client_t *, str_t msgid);
static void	 pending_remove(str_t msgid);
static void	 pending_remove_client(client_t *);

static client_t	*client_new(int fd);
static void	 client_printf(client_t *, char const *, ...);
static void	 client_vprintf(client_t *, char const *, va_list ap);
static void	 client_log(int sev, client_t *, char const *, ...)
			attr_printf(3, 4);
static void	 client_vlog(int sev, client_t *, char const *, va_list ap);
static void	 client_close(client_t *);
static void	 client_close_impl(void *);
static void	 client_reader(client_t *);

typedef void (*cmd_handler) (client_t *, str_t, str_t);

static void	c_capabilities(client_t *, str_t, str_t);
static void	c_mode(client_t *, str_t, str_t);
static void	c_ihave(client_t *, str_t, str_t);
static void	c_check(client_t *, str_t, str_t);
static void	c_quit(client_t *, str_t, str_t);
static void	c_takethis(client_t *, str_t, str_t);
static void	c_help(client_t *, str_t, str_t);
static void	c_authinfo(client_t *, str_t, str_t);
static void	c_starttls(client_t *, str_t, str_t);
static void	client_takethis_done(client_t *);

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

int
client_init()
{
	ba_client = balloc_new(sizeof(client_t), 128, "client");
	pending_init();
	config_add_stanza(&listen_stanza);

#ifdef HAVE_OPENSSL
	SSL_load_error_strings();
	SSL_library_init();
#endif
	return 0;
}

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

	li->li_next = listeners;
	listeners = li;
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
client_run()
{
	listener_t	*li;
	for (li = listeners; li; li = li->li_next) {
		if (net_listen(li->li_address,
			       li->li_ssl_type == SSL_ALWAYS?
			       		li->li_ssl : NULL, 
			       NET_DEFPRIO, SOCK_STREAM,
			       client_accept, li) == -1)
			return -1;
	}

	return 0;
}

void
client_accept(fd, addr, addrlen, ssl, udata)
	struct sockaddr	*addr;
	socklen_t	 addrlen;
	void		*udata;
	SSL		*ssl;
{
listener_t	*li = udata;
client_t	*client;
server_t	*server;
char		 host[NI_MAXHOST], serv[NI_MAXSERV],
		 strname[NI_MAXHOST + NI_MAXSERV + 1024];
int		 one = 1;

	if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) == -1) {
		nts_log(LOG_ERR, "setsockopt(TCP_NODELAY): %s",
			strerror(errno));
		close(fd);
		return;
	}

	client = client_new(fd);
	client->cl_listener = li;
	client->cl_ssl = ssl;

	if (ssl)
		client->cl_flags |= CL_SSL;

	net_open(fd, ssl, NET_DEFPRIO, client_read, client_error, client);

	getnameinfo(addr, addrlen, host, sizeof(host), serv, sizeof(serv),
			NI_NUMERICHOST | NI_NUMERICSERV);

	bcopy(addr, &client->cl_addr, addrlen);
	client->cl_addrlen = addrlen;

	if ((server = server_find_by_address((struct sockaddr_storage *) addr)) == NULL
	    && !allow_unauthed) {
		nts_log(LOG_NOTICE, "unknown[%s]:%s: connection rejected: access denied",
				host, serv);
		if (reader_handler) {
			client_reader(client);
		} else {
			client_printf(client, "502 Access denied (%s).\r\n", contact_address);
		}
		client_close(client);
		return;
	}

	if (server) {
		if (server->se_nconns == server->se_maxconns) {
			nts_log(LOG_NOTICE, "%s[%s]:%s: connection rejected: too many connections",
					server->se_name, host, serv);
			client_printf(client, "400 Too many connection (%s).\r\n", contact_address);
			client_close(client);
			return;
		}
		++server->se_nconns;

		client->cl_server = server;
		snprintf(strname, sizeof(strname), "%s[%s]:%s", server->se_name, host, serv);
		client->cl_strname = xstrdup(strname);
	} else { 
		snprintf(strname, sizeof(strname), "unknown[%s]:%s", host, serv);
		client->cl_strname = xstrdup(strname);
	}

	client_printf(client, "200 RT/NTS %s #%d ready (%s).\r\n",
			PACKAGE_VERSION, build_number, contact_address);

	if (log_incoming_connections)
		client_log(LOG_INFO, client, "client connected");
}

void
client_read(fd, what, udata)
	void	*udata;
{
str_t		 line = NULL;
client_t	*client = udata;
int		 n;

	while ((n = net_readline(fd, &line)) == 1) {
		if (client->cl_state == CS_WAIT_COMMAND) {
		str_t	 command;
		size_t	 i;

			if ((command = str_next_word(line)) == NULL)
				goto next;

			for (i = 0; i < sizeof(cmds) / sizeof(*cmds); i++) {
				if (str_case_compare_c(command, cmds[i].cmd))
					continue;

				if (cmds[i].need_auth &&
				    (!client->cl_server ||
				     (client->cl_server->se_username_in
				      && !client->cl_authenticated))) {
					client_printf(client, "480 Authentication required.\r\n");
				} else {
					cmds[i].handler(client, command, line);
				}

				str_free(command);
				goto next;
			}

			str_free(command);
			client_printf(client, "500 Unknown command.\r\n");
		} else if (client->cl_state == CS_TAKETHIS || client->cl_state == CS_IHAVE) {
			if (str_compare_c(line, ".") == 0) {
				client_takethis_done(client);
			} else {
				if (client->cl_artsize <= max_article_size) {
					str_append(client->cl_article, line);
					str_append_c(client->cl_article, "\r\n");
				}

				client->cl_artsize += str_length(line) + 2;
			}
		}
next:
		str_free(line);

		if (client->cl_flags & CL_PAUSED)
			return;

		if (client->cl_state == CS_DEAD) {
			client_close(client);
			return;
		}
	}

	if (n == -1) {
		if (errno == 0) {
			if (log_incoming_connections)
				client_log(LOG_INFO, client, "disconnected (EOF)");
		} else {
			client_log(LOG_INFO, client, "read error: %s",
				strerror(errno));
		}
		client_close(client);
	}
}

void
client_error(fd, what, err, udata)
	void	*udata;
{
client_t	*client = udata;
	if (err == 0) {
		if (log_incoming_connections)
			client_log(LOG_INFO, client, "disconnected (EOF)");
	} else {
		client_log(LOG_INFO, client, "%s error callback: %s",
				what == FDE_READ ? "read" : "write",
				strerror(err));
	}
	client_close(client);
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

	net_write(client->cl_fd, r, len);

	if (r != buf)
		free(r);
}

static void
client_printf(client_t *client, char const *fmt, ...)
{
va_list	ap;
	va_start(ap, fmt);
	client_vprintf(client, fmt, ap);
	va_end(ap);
}

static void
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
	return cl;
}

static void
c_capabilities(client, cmd, line)
	client_t	*client;
	str_t		 cmd, line;
{
	client_printf(client,
			"101 Capability list:\r\n"
			"VERSION 2\r\n"
			"IMPLEMENTATION RT/NTS %s #%d\r\n",
			PACKAGE_VERSION, build_number);
	if (!auth_enabled || client->cl_authenticated)
		client_printf(client, "IHAVE\r\nSTREAMING\r\n");
	if (reader_handler && !client->cl_authenticated && !client->cl_ssl)
		client_printf(client, "MODE-READER\r\n");
	if (auth_enabled && !client->cl_authenticated &&
	    (insecure_auth || (client->cl_flags & CL_SSL)))
		client_printf(client, "AUTHINFO USER\r\n");
	if (client->cl_listener->li_ssl && !client->cl_ssl)
		client_printf(client, "STARTTLS\r\n");
	client_printf(client, ".\r\n");
}

static void
c_check(client, cmd, line)
	client_t	*client;
	str_t		 cmd, line;
{
str_t	msgid = NULL, junk = NULL;

	if ((msgid = str_next_word(line)) == NULL || (junk = str_next_word(line))) {
		client_printf(client, "501 Syntax: CHECK <message-id>\r\n");
		goto done;
	}

	if (!valid_msgid(msgid)) {
		client_printf(client, "438 %.*s\r\n", str_printf(msgid));
		goto done;
	}

	if (!server_accept_offer(client->cl_server, msgid)) {
		++client->cl_server->se_in_refused;
		client_printf(client, "438 %.*s\r\n", str_printf(msgid));
		goto done;
	}

	if (pending_check(msgid)) {
		++client->cl_server->se_in_deferred;
		client_printf(client, "431 %.*s\r\n", str_printf(msgid));
		goto done;
	}

	if (history_check(msgid)) {
		++client->cl_server->se_in_refused;
		client_printf(client, "438 %.*s\r\n", str_printf(msgid));
	} else {
		client_printf(client, "238 %.*s\r\n", str_printf(msgid));
		pending_add(client, msgid);
	}

done:
	str_free(msgid);
	str_free(junk);
}

static void
c_ihave(client, cmd, line)
	client_t	*client;
	str_t		 cmd, line;
{
str_t	msgid = NULL, junk = NULL;
	if ((msgid = str_next_word(line)) == NULL || (junk = str_next_word(line))) {
		client_printf(client, "501 Syntax: CHECK <message-id>\r\n");
		goto done;
	}

	if (!valid_msgid(msgid)) {
		client_printf(client, "435 Invalid message-id.\r\n");
		log_article(msgid, NULL, client->cl_server, '-', "invalid-msgid");
		goto done;
	}

	if (pending_check(msgid)) {
		client->cl_server->se_in_deferred++;
		client_printf(client, "436 %.*s Try again later.\r\n", str_printf(msgid));
		goto done;
	}

	if (!server_accept_offer(client->cl_server, msgid)) {
		client->cl_server->se_in_rejected++;
		client_printf(client, "435 %.*s Don't want it.\r\n", str_printf(msgid));
		log_article(msgid, NULL, client->cl_server, '-', "offer-filter");
		goto done;
	}

	if (history_check(msgid)) {
		client->cl_server->se_in_refused++;
		client_printf(client, "435 %.*s Already have it.\r\n", str_printf(msgid));
		log_article(msgid, NULL, client->cl_server, '-', "duplicate");
	} else {
		pending_add(client, msgid);
		client_printf(client, "335 %.*s OK, send it.\r\n", str_printf(msgid));
		client->cl_msgid = str_copy(msgid);
		client->cl_artsize = 0;
		client->cl_state = CS_IHAVE;
	}

done:
	str_free(msgid);
	str_free(junk);
}

static void
c_help(client, cmd, line)
	client_t	*client;
	str_t		 cmd, line;
{
str_t	junk;

	if (junk = str_next_word(line)) {
		str_free(junk);
		client_printf(client, "501 Syntax: HELP\r\n");
		return;
	}

	client_printf(client,
		"100 Command list:\r\n"
		"  CAPABILITIES\r\n"
		"  CHECK <msg-id>\r\n"
		"  HELP\r\n"
		"  IHAVE <msg-id>\r\n"
		"  MODE STREAM\r\n"
		"  QUIT\r\n"
		"  TAKETHIS <msg-id>\r\n"
		".\r\n"
		);
}

static void
c_starttls(client, cmd, line)
	client_t	*client;
	str_t		 cmd, line;
{
#ifndef HAVE_OPENSSL
	client_printf(client, "580 TLS not available.\r\n");
	return;
#else
	if (!client->cl_listener->li_ssl) {
		client_printf(client, "580 TLS not available.\r\n");
		return;
	}

	if (client->cl_ssl) {
		client_printf(client, "502 TLS already in use.\r\n");
		return;
	}

	client_printf(client, "382 OK, start negotiation.\r\n");
	net_starttls(client->cl_fd, client->cl_listener->li_ssl, client_tls_done);
#endif
}

static void
client_tls_done(fd, ssl, udata)
	SSL	*ssl;
	void	*udata;
{
client_t	*client = udata;
	client->cl_ssl = ssl;
}

static void
c_authinfo(client, cmd, line)
	client_t	*client;
	str_t		 cmd, line;
{
str_t	type;

	if (client->cl_authenticated) {
		client_printf(client, "502 Already authenticated.\r\n");
		return;
	}
	
	if (!auth_enabled || (client->cl_server &&
			      !client->cl_server->se_username_in)) {
		client_printf(client, "502 Authentication unavailable.\r\n");
		return;
	}

	if (!insecure_auth && !(client->cl_flags & CL_SSL)) {
		client_printf(client, "483 TLS required.\r\n");
		return;
	}

	if ((type = str_next_word(line)) == NULL) {
		client_printf(client, "501 Syntax error.\r\n");
		return;
	}

	if (str_case_equal_c(type, "USER")) {
	str_t	un;
		if ((un = str_next_word(line)) == NULL) {
			client_printf(client, "501 Syntax error.\r\n");
			goto done;
		}

		str_free(client->cl_username);
		client->cl_username = un;
		client_printf(client, "381 Enter password.\r\n");
	} else if (str_case_equal_c(type, "PASS")) {
	str_t	password;

		if (!client->cl_username) {
			client_printf(client, "482 Need a username first.\r\n");
			goto done;
		}

		if ((password = str_next_word(line)) == NULL) {
			client_printf(client, "501 Syntax error.\r\n");
			goto done;
		}

		if (auth_check(client->cl_username, password)) {
			if (!client->cl_server) {
			char		 strname[NI_MAXHOST + NI_MAXSERV + 1024];
			char		 host[NI_MAXHOST], serv[NI_MAXSERV];
			server_t	*se;

				SLIST_FOREACH(se, &servers, se_list) {
					if (se->se_username_in &&
					    str_equal_c(client->cl_username,
							se->se_username_in)) {
						client->cl_server = se;
						break;
					}
				}

				if (!client->cl_server) {
					client_log(LOG_INFO, client,
						"authentication as \"%.*s\" failed",
						str_printf(client->cl_username));
					client_printf(client, "481 Authentication failed.\r\n");
					goto done;
				}

				getnameinfo((struct sockaddr *) &client->cl_addr,
					client->cl_addrlen,
					host, sizeof(host), serv, sizeof(serv),
					NI_NUMERICHOST | NI_NUMERICSERV);

				if (se->se_nconns == se->se_maxconns) {
					nts_log(LOG_NOTICE, "%s[%s]:%s: "
						"connection rejected: "
						"too many connections",
						se->se_name, host, serv);
					client_printf(client, 
						"481 Too many connections "
						"(%s).\r\n", contact_address);
					goto done;
				}
				++se->se_nconns;

				snprintf(strname, sizeof(strname), "%s[%s]:%s",
						se->se_name, host, serv);
				client->cl_strname = xstrdup(strname);
			}

			client_log(LOG_INFO, client, "authenticated as \"%.*s\"",
					str_printf(client->cl_username));
			client_printf(client, "281 Authentication accepted.\r\n");
			client->cl_authenticated = 1;
		} else {
			client_log(LOG_INFO, client, "authentication as \"%.*s\" failed",
					str_printf(client->cl_username));
			client_printf(client, "481 Authentication failed.\r\n");
		}
		str_free(password);
	} else {
		client_printf(client, "501 Syntax error.\r\n");
	}

done:
	str_free(type);
}

static void
c_takethis(client, cmd, line)
	client_t	*client;
	str_t		 cmd, line;
{
str_t	msgid = NULL, junk = NULL;
	if ((msgid = str_next_word(line)) == NULL || (junk = str_next_word(line))) {
		/*
		 * We have to close the connection here because the
		 * client will be expecting to send a message after
		 * the command.
		 */
		client_printf(client, "501 Syntax: TAKETHIS <message-id>\r\n");
		client_log(LOG_INFO, client, "disconnected (missing message-id in TAKETHIS)");
		client->cl_state = CS_DEAD;
		goto done;
	}

	client->cl_state = CS_TAKETHIS;
	client->cl_msgid = str_copy(msgid);
	client->cl_artsize = 0;
	client->cl_article = str_new_c("");

	pending_add(client, msgid);

done:
	str_free(msgid);
	str_free(junk);
}

static void
client_takethis_done(client)
	client_t	*client;
{
article_t	*article = NULL;
int		 rejected = (client->cl_state == CS_TAKETHIS) ? 439 : 437,
		 age, oldest;

	pending_remove(client->cl_msgid);

	if (client->cl_artsize > max_article_size) {
		client->cl_server->se_in_rejected++;
		history_add(client->cl_msgid);
		client_log(LOG_INFO, client, "%.*s: too large (%d > %d)",
				str_printf(client->cl_msgid),
				(int) client->cl_artsize,
				(int) max_article_size);
		client_printf(client, "%d %.*s\r\n", rejected, str_printf(client->cl_msgid));
		log_article(client->cl_msgid, NULL, client->cl_server, '-', "too-large");
		goto err;
	}

	if (!valid_msgid(client->cl_msgid)) {
		client_printf(client, "%d %.*s\r\n", rejected, 
				str_printf(client->cl_msgid));
		goto err;
	}

	if ((article = article_parse(client->cl_article)) == NULL) {
		history_add(client->cl_msgid);
		client->cl_server->se_in_rejected++;
		client_log(LOG_NOTICE, client, "%.*s: cannot parse article", str_printf(client->cl_msgid));
		client_printf(client, "%d %.*s\r\n", rejected, str_printf(client->cl_msgid));
		log_article(client->cl_msgid, NULL, client->cl_server, '-', "cannot-parse");
		goto err;
	}

	age = (time(NULL) - article->art_date);
	oldest = history_remember - 60 * 60 * 24;
	if (age > oldest) {
		client->cl_server->se_in_rejected++;
		client_printf(client, "%d %.*s\r\n", rejected, str_printf(article->art_msgid));
		log_article(article->art_msgid, NULL, client->cl_server, '-', "too-old");
		client_log(LOG_NOTICE, client, "%.*s: too old (%d days)",
				str_printf(article->art_msgid), age / 60 / 60 / 24);
		goto err;
	}

	if (str_compare(article->art_msgid, client->cl_msgid))
		client_log(LOG_WARNING, client, "message-id mismatch: %.*s vs %.*s",
				str_printf(client->cl_msgid), str_printf(article->art_msgid));

	if (history_check(article->art_msgid)) {
		client->cl_server->se_in_rejected++;
		client_printf(client, "%d %.*s\r\n", rejected, str_printf(article->art_msgid));
		log_article(article->art_msgid, NULL, client->cl_server, '-', "duplicate");
	} else {
		client->cl_farticle = article;
		client_pause(client);
		thr_do_work(client_filter, client, client_filter_done);
		return;
	}

err:
	article_free(article);

	client->cl_state = CS_WAIT_COMMAND;
	str_free(client->cl_msgid);
	client->cl_msgid = NULL;

	str_free(client->cl_article);
	client->cl_article = NULL;
}

static void *
client_filter(udata)
	void	*udata;
{
client_t	*client = udata;

	emp_track(client->cl_farticle);
	client->cl_filter_result = filter_article(client->cl_farticle,
			client->cl_strname, &client->cl_server->se_filters_in,
			&client->cl_filter_name);
	return client;
}

static void
client_pause(client)
	client_t	*client;
{
	client->cl_flags |= CL_PAUSED;
	net_io_stop(client->cl_fd);
}

static int
client_unpause(client)
	client_t	*client;
{
	client->cl_flags &= ~CL_PAUSED;
	if (client->cl_flags & CL_DEAD) {
		client_close(client);
		return -1;
	}

	return 0;
}

static void
client_filter_done(udata)
	void	*udata;
{
client_t	*client = udata;
article_t	*article;
int		 rejected;

	if (client_unpause(client) == -1)
		return;

	article = client->cl_farticle;
	rejected = (client->cl_state == CS_TAKETHIS) ? 439 : 437;

	history_add(article->art_msgid);

	switch (client->cl_filter_result) {
	case FILTER_RESULT_DENY:
		client->cl_server->se_in_rejected++;
		log_article(article->art_msgid, NULL, client->cl_server, '-',
				"filter/%.*s", str_printf(client->cl_filter_name));
		client_printf(client, "%d %.*s\r\n", rejected,
				str_printf(client->cl_msgid));
		goto err;

	case FILTER_RESULT_DUNNO:
	case FILTER_RESULT_PERMIT:
		log_article(article->art_msgid, article->art_path, 
				client->cl_server, '+', NULL);
		article_munge_path(article);
		client->cl_server->se_in_accepted++;
		spool_store(article);
		client_printf(client, "239 %.*s\r\n", str_printf(client->cl_msgid));
		feeder_notify_article(article);
		if (article->art_refs == 0)
			article_free(article);
		goto done;
	}

err:
	article_free(client->cl_farticle);

done:
	client->cl_farticle = NULL;

	client->cl_state = CS_WAIT_COMMAND;
	str_free(client->cl_msgid);
	client->cl_msgid = NULL;

	str_free(client->cl_article);
	client->cl_article = NULL;

	net_io_start(client->cl_fd);
	client_read(client->cl_fd, FDE_READ, client);
}

static void
c_quit(client, cmd, line)
	client_t	*client;
	str_t		 cmd, line;
{
str_t	junk = NULL;
	if (junk = str_next_word(line)) {
		str_free(junk);
		client_printf(client, "501 Syntax: QUIT\r\n");
		return;
	}

	if (log_incoming_connections)
		client_log(LOG_INFO, client, "disconnected (QUIT)");
	client_printf(client, "205 Closing connection.\r\n");
	client->cl_state = CS_DEAD;
}

static void
c_mode(client, cmd, line)
	client_t	*client;
	str_t		 cmd, line;
{
str_t	mode = NULL, junk = NULL;
	if ((mode = str_next_word(line)) == NULL || (junk = str_next_word(line))) {
		client_printf(client, "501 Syntax: MODE STREAM\r\n");
		goto done;
	}

	if (str_case_equal_c(mode, "STREAM")) {
		client_printf(client, "203 Streaming permitted.\r\n");
	} else if (str_case_equal_c(mode, "READER")) {
		if (reader_handler) {
			client_reader(client);
		} else {
			client_printf(client, "502 Transit service only.\r\n");
		}
		client->cl_state = CS_DEAD;
	} else 
		client_printf(client, "501 Unknown MODE variant.\r\n");

done:
	str_free(mode);
	str_free(junk);
}

static void
client_close(client)
	client_t	*client;
{
	if (client->cl_flags & CL_PAUSED) {
		client->cl_flags |= CL_DEAD;
		return;
	}

	if (client->cl_flags & CL_FREE)
		return;
	client->cl_flags |= CL_FREE;
	net_soon(client_close_impl, client);
}

static void
client_close_impl(udata)
	void	*udata;
{
client_t	*client = udata;
	if (client->cl_server)
		--client->cl_server->se_nconns;

	pending_remove_client(client);
	net_close(client->cl_fd);
	str_free(client->cl_msgid);
	str_free(client->cl_article);
	str_free(client->cl_username);
	free(client->cl_strname);
	bfree(ba_client, client);
}

static void
client_reader(client)
	client_t	*client;
{
	if (reader_handoff(client->cl_fd) == -1)
		client_log(LOG_ERR, client, "cannot complete reader handoff: %s",
				strerror(errno));
}

/* ===
 * Pending defer list.
 */

static hash_table_t	*pending_list;

static void
pending_init(void)
{
	if (!defer_pending)
		return;

	pending_list = hash_new(128, NULL, NULL, NULL);
}

static void
pending_add(client, msgid)
	client_t	*client;
	str_t		 msgid;
{
	if (!defer_pending)
		return;

	hash_insert(pending_list, str_begin(msgid), str_length(msgid), client);
}

static int
pending_check(msgid)
	str_t		 msgid;
{
	if (!defer_pending)
		return 0;

	return hash_find(pending_list, str_begin(msgid), str_length(msgid)) != NULL;
}

static void
pending_remove(msgid)
	str_t	msgid;
{
	if (!defer_pending)
		return;

	hash_remove(pending_list, str_begin(msgid), str_length(msgid));
}

static void
pending_remove_client(client)
	client_t	*client;
{
hash_item_t	*ie, *next;
size_t		 i;

	if (!defer_pending)
		return;


	for (i = 0; i < pending_list->ht_nbuckets; i++) {
		LIST_FOREACH_SAFE(ie, &pending_list->ht_buckets[i], hi_link, next) {
			if (ie->hi_data == client) {
				LIST_REMOVE(ie, hi_link);
				free(ie->hi_key);
				free(ie);
			}
		}
	}
}
