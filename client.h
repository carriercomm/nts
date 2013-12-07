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

#include	"setup.h"

#ifdef HAVE_OPENSSL
# include	<openssl/ssl.h>
#endif

#include	"queue.h"
#include	"str.h"
#include	"filter.h"

struct server;
struct article;

typedef enum client_state {
	CS_SSL_HANDSHAKE,
	CS_WAIT_COMMAND,
	CS_TAKETHIS,
	CS_IHAVE,
	CS_DEAD
} client_state_t;

#define	CL_PAUSED	0x01
#define	CL_DEAD		0x02
#define	CL_SSL		0x04
#define	CL_FREE		0x08

typedef enum {
	SSL_NEVER = 0,
	SSL_ALWAYS,
	SSL_STARTTLS
} ssl_type_t;

typedef struct listener {
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
	str_t		 cl_article;
	str_t		 cl_msgid;
	size_t		 cl_artsize;
	char		*cl_strname;
	str_t		 cl_username;
	int		 cl_authenticated;
	struct sockaddr_storage
			 cl_addr;
	socklen_t	 cl_addrlen;
	int		 cl_flags;
	listener_t	*cl_listener;

#ifdef HAVE_OPENSSL
	SSL		*cl_ssl;
#endif

	/* for client_filter() */
	filter_result_t	 cl_filter_result;
	struct article	*cl_farticle;
	str_t		 cl_filter_name;

	SIMPLEQ_ENTRY(client)	cl_list;
} client_t;

typedef SIMPLEQ_HEAD(client_list, client) client_list_t;

int	client_init(void);
int	client_run(void);

#endif	/* !NTS_CLIENT_H */
