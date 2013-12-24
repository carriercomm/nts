/* RT/NTS -- a lightweight, high performance news transit server. */
/* 
 * Copyright (c) 2011 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */
/* $Header: /cvsroot/nts/client.h,v 1.9 2012/01/10 17:14:13 river Exp $ */

#ifndef	NTS_CLIENT_H
#define	NTS_CLIENT_H

#include	<sys/types.h>
#include	<sys/socket.h>

#include	<stdlib.h>

#include	<ev.h>

#include	"setup.h"

#ifdef HAVE_OPENSSL
# include	<openssl/ssl.h>
#endif

#include	"queue.h"
#include	"filter.h"
#include	"charq.h"

struct server;
struct article;

typedef enum client_state {
	CS_SSL_HANDSHAKE,
	CS_WAIT_COMMAND,
	CS_TAKETHIS,
	CS_IHAVE,
	CS_DEAD
} client_state_t;

#define	CL_PAUSED	0x01	/* Ignoring reads from this client */
#define	CL_DEAD		0x02	/* Client marked to be freed */
#define	CL_SSL		0x04	/* SSL is enabled */
#define	CL_FREE		0x08
#define CL_READABLE	0x10
#define CL_WRITABLE	0x20
#define CL_DRAIN	0x40	/* Destroy once wrbuf is empty */
#define	CL_PENDING	0x80	/* Waiting for incoming reply */

typedef enum {
	SSL_NEVER = 0,
	SSL_ALWAYS,
	SSL_STARTTLS
} ssl_type_t;

typedef struct listener {
	int		 li_fd;
	ev_io		 li_event;
	char		*li_address;
	struct listener	*li_next;
#ifdef HAVE_OPENSSL
	SSL_CTX		*li_ssl;
	char		*li_ssl_cert;
	char		*li_ssl_key;
	ssl_type_t	 li_ssl_type;
	char		*li_ssl_cyphers;
#endif
} listener_t;

typedef struct client {
	int		 cl_fd;
	struct server	*cl_server;
	client_state_t	 cl_state;
	char		*cl_msgid;
	char		*cl_article;
	size_t		 cl_artsize;
	size_t		 cl_artalloc;
	char		*cl_strname;
	char		*cl_username;
	int		 cl_authenticated;
	struct sockaddr_storage
			 cl_addr;
	socklen_t	 cl_addrlen;
	int		 cl_flags;
	listener_t	*cl_listener;

	ev_io		 cl_readable;
	ev_io		 cl_writable;

	charq_t		*cl_wrbuf;
	charq_t		*cl_rdbuf;

#ifdef HAVE_OPENSSL
	SSL		*cl_ssl;
#endif

	SIMPLEQ_ENTRY(client)	cl_list;
	SIMPLEQ_ENTRY(client)	cl_read_list;
	SIMPLEQ_ENTRY(client)	cl_write_list;
	SIMPLEQ_ENTRY(client)	cl_dead_list;
} client_t;

typedef SIMPLEQ_HEAD(client_list, client) client_list_t;

int	client_init(void);
int	client_run(void);

void	client_incoming_reply(client_t *, int);

/*
 * Internal functions.
 */
void	 client_printf(client_t *, char const *, ...);
void	 client_log(int sev, client_t *, char const *, ...)
			attr_printf(3, 4);

extern	config_schema_stanza_t listen_stanza;
int	client_listen(void);

void	 client_accept(int, struct sockaddr *, socklen_t, SSL *, listener_t *);
void	 client_close(client_t *, int);
void	 client_destroy(void *);

void	 pending_init(void);
int	 pending_check(char const *msgid);
void	 pending_add(client_t *, char const *msgid);
void	 pending_remove(char const *msgid);
void	 pending_remove_client(client_t *);

void	 client_reader(client_t *);

extern struct ev_loop	*client_loop;
extern ev_async		 reply_ev;
void	 client_do_replies(struct ev_loop *, ev_async *, int);

/*
 * Client command handlers.
 */
void	c_authinfo(client_t *, char *, char *);
void	c_mode(client_t *, char *, char *);
void	c_capabilities(client_t *, char *, char *);
void	c_check(client_t *, char *, char *);
void	c_ihave(client_t *, char *, char *);
void	c_help(client_t *, char *, char *);
void	c_starttls(client_t *, char *, char *);
void	c_quit(client_t *, char *, char *);
void	c_takethis(client_t *, char *, char *);
void	client_takethis_done(client_t *);

#endif	/* !NTS_CLIENT_H */
