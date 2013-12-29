/* RT/NTS -- a lightweight, high performance news transit server. */
/* 
 * Copyright (c) 2011-2013 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */

#ifndef	NTS_CLIENT_H
#define	NTS_CLIENT_H

#include	<sys/types.h>
#include	<sys/socket.h>

#include	<stdlib.h>

#include	"uv.h"

#include	"setup.h"

#ifdef HAVE_OPENSSL
# include	<openssl/ssl.h>
# include	<openssl/bio.h>
#endif

#include	"queue.h"
#include	"filter.h"
#include	"charq.h"
#include	"msg.h"

struct server;
struct article;

/*
 * This could possibly be a configuration option to be tuned upward on
 * binary servers where most articles are large.
 */
#define	ARTBUF_START_SIZE	8192

typedef enum ab_type {
	AB_IHAVE,
	AB_TAKETHIS
} ab_type_t;

struct client;
typedef struct artbuf {
	char		*ab_text;
	size_t		 ab_alloc;
	size_t		 ab_len;
	char		*ab_msgid;
	int		 ab_flags;
	struct client	*ab_client;
	ab_type_t	 ab_type;
	int		 ab_status;
} artbuf_t;

typedef struct msglist {
	char		*ml_msgid;
	ab_type_t	 ml_type;

	TAILQ_ENTRY(msglist)
			 ml_list;
} msglist_t;

typedef TAILQ_HEAD(msglist_list, msglist) msglist_list_t;

typedef enum client_state {
	CS_SSL_HANDSHAKE,
	CS_WAIT_COMMAND,
	CS_TAKETHIS,
	CS_IHAVE,
	CS_DEAD
} client_state_t;

#define	CL_PAUSED	0x001	/* Ignoring reads from this client */
#define	CL_DEAD		0x002	/* Client marked to be freed */
#define	CL_SSL		0x004	/* SSL is enabled */
#define	CL_FREE		0x008
#define CL_READABLE	0x010
#define CL_WRITABLE	0x020
#define CL_DRAIN	0x040	/* Destroy once wrbuf is empty */
#define	CL_SSL_ACPTING	0x080	/* SSL_accept() in progress */
#define	CL_SSL_SHUTDN	0x100	/* SSL_shutdown() in progress */
#define	CL_DESTROY	0x200

typedef enum {
	SSL_NEVER = 0,
	SSL_ALWAYS,
	SSL_STARTTLS
} ssl_type_t;

typedef struct listener {
	uv_tcp_t	*li_uv;
	int		 li_nuv;
	char		*li_address;
	struct listener	*li_next;
	char		*li_ssl_cert;
	char		*li_ssl_key;
	ssl_type_t	 li_ssl_type;
	char		*li_ssl_cyphers;
#ifdef HAVE_OPENSSL
	SSL_CTX		*li_ssl;
#endif
} listener_t;

typedef struct client {
	uv_tcp_t	*cl_stream;
	struct server	*cl_server;
	client_state_t	 cl_state;
	char		*cl_strname;
	char		*cl_username;
	int		 cl_authenticated;
	struct sockaddr_storage
			 cl_addr;
	socklen_t	 cl_addrlen;
	int		 cl_flags;
	listener_t	*cl_listener;
	artbuf_t	*cl_buffer;

	charq_t		*cl_rdbuf;

#ifdef HAVE_OPENSSL
	SSL		*cl_ssl;
	BIO		*cl_bio_in,
			*cl_bio_out;
	charq_t		*cl_wrbuf;
#endif

	SIMPLEQ_ENTRY(client)	cl_list;
} client_t;

typedef SIMPLEQ_HEAD(client_list, client) client_list_t;

typedef struct client_write_req {
	client_t	*client;
	char		*buf;
} client_write_req_t;

int	client_init(void);
int	client_run(void);

void	client_incoming_reply(client_t *, artbuf_t *);

/*
 * Internal functions.
 */
void	 client_printf(client_t *, char const *, ...);
void	 client_log(int sev, client_t *, char const *, ...)
			attr_printf(3, 4);
void	 client_logm(msg_t fac[], int msg, client_t *, ...);

extern	config_schema_stanza_t listen_stanza;
int	client_listen(void);

#ifdef	HAVE_OPENSSL
void	 client_accept(uv_tcp_t *, SSL_CTX *, listener_t *);
#else
void	 client_accept(uv_tcp_t *, listener_t *);
#endif
void	 client_close(client_t *, int);
void	 client_destroy(void *);

void	 pending_init(void);
int	 pending_check(char const *msgid);
void	 pending_add(client_t *, char const *msgid);
void	 pending_remove(char const *msgid);
void	 pending_remove_client(client_t *);

void	 client_reader(client_t *);
int	 client_reader_init(void);
void	 reader_handoff(uv_tcp_t *);

void	 client_pause(client_t *);
void	 client_unpause(client_t *);

void	 client_do_replies(uv_async_t *, int);

#ifdef	HAVE_OPENSSL
void	 client_tls_accept(client_t *);
void	 client_tls_flush(client_t *);
void	 client_tls_write_pending(client_t *);
#endif

void	 on_client_read(uv_stream_t *, ssize_t, uv_buf_t const *);
void	 on_client_write_done(uv_write_t *, int);
void	 on_client_close_done(uv_handle_t *);
void	 on_client_shutdown_done(uv_shutdown_t *, int);

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
