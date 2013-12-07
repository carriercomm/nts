/* RT/NTS -- a lightweight, high performance news transit server. */
/* 
 * Copyright (c) 2011 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */
/* $Header: /cvsroot/nts/net.h,v 1.16 2012/01/09 18:35:54 river Exp $ */

#ifndef	NTS_NET_H
#define	NTS_NET_H

#include	<sys/types.h>
#include	<sys/socket.h>
#include	<netdb.h>

#include	"setup.h"

#ifdef HAVE_OPENSSL
# include	<openssl/ssl.h>
#endif

#include	"str.h"

#define	NET_STRLEN 64

#define FDE_LISTENER			0x001
#define	FDE_READ			0x002
#define	FDE_WRITE			0x004
#define FDE_ERROR			0x008
#define FDE_DRAIN			0x010
#define FDE_DEAD			0x020
#define	FDE_CONNECT			0x040
#define	FDE_SSL_READ_WANTS_WRITE	0x080
#define FDE_SSL_WRITE_WANTS_READ	0x100
#define	FDE_SSL_ACCEPTING		0x200
#define	FDE_PAUSED			0x400

typedef struct address {
	struct sockaddr_storage	 ad_addr;
	socklen_t		 ad_len;
	SIMPLEQ_ENTRY(address)	 ad_list;
} address_t;

typedef SIMPLEQ_HEAD(address_list, address) address_list_t;

#define	NET_HIPRIO	1
#define	NET_DEFPRIO	0
#define	NET_LOWPRIO	-1

typedef void (*net_accepter) (int fd, struct sockaddr *, socklen_t, SSL *, void *udata);
typedef void (*net_tls_done_handler) (int fd, SSL *, void *udata);
typedef void (*net_err_handler) (int fd, int what, int err, void *udata);
typedef void (*net_handler) (int fd, int what, void *udata);
typedef void (*net_cron_handler) (void *);

int	 net_listen(char const *addr, SSL_CTX *ssl, int prio, int type, net_accepter, void *udata);
int	 net_listen_sa(struct sockaddr *, socklen_t, SSL_CTX *ssl, int prio, int type, net_accepter, void *udata);
int	 net_listen_unix(char const *, int prio, net_accepter, void *udata);
int	 net_resolve(char const *addr, struct addrinfo **, int flags, int type);

void	 net_register(int fd, int what, net_handler, void *udata);
int	 net_init(void);
int	 net_run(void);

int	 net_set_nonblocking(int fd);
int	 net_set_cloexec(int fd);

void	 net_open(int fd, SSL *, int prio, net_handler readh, net_err_handler errh, void *udata);
void	 net_connect(int prio, struct sockaddr *addr, socklen_t addrlen,
		struct sockaddr *bind, socklen_t bindlen,
		net_handler handler, net_err_handler err_handler,
		net_handler read_handler, void *udata);
void	 net_write(int fd, void const *, size_t);
ssize_t	 net_read(int fd, void *, size_t);
int	 net_readline(int fd, str_t *);
void	 net_io_stop(int);
void	 net_io_start(int);
void	 net_starttls(int, SSL_CTX *, net_tls_done_handler);
void	 net_pause(int);
void	 net_unpause(int);
void	 net_close(int fd);

void	 net_cron(int freq, net_cron_handler, void *);
void	 net_soon(net_cron_handler, void *);

#endif	/* !NTS_NET_H */
