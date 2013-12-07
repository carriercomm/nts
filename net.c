/* RT/NTS -- a lightweight, high performance news transit server. */
/* 
 * Copyright (c) 2011 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */
/* $Header: /cvsroot/nts/net.c,v 1.36 2012/01/09 18:35:54 river Exp $ */

#include	<sys/socket.h>
#include	<sys/un.h>

#include	<stdlib.h>
#include	<unistd.h>
#include	<stdio.h>
#include	<strings.h>
#include	<string.h>
#include	<errno.h>
#include	<fcntl.h>

#include	<ev.h>

#include	"setup.h"

#ifdef HAVE_OPENSSL
# include	<openssl/ssl.h>
# include	<openssl/err.h>
#endif

#include	"net.h"
#include	"log.h"
#include	"nts.h"
#include	"charq.h"
#include	"balloc.h"

#define	NET_DEBUG	0

#if NET_DEBUG
# define DPRINTF(x)	printf x
#else
# define DPRINTF(x)
#endif

typedef struct fde {
	int			 fde_flags;
	int			 fde_prio;
	void			*fde_udata;
	SSL			*fde_ssl;
	net_tls_done_handler	 fde_tls_done_handler;

	net_err_handler		 fde_error_handler;

	/* Read data */
	ev_io			 fde_read_watcher;
	net_handler		 fde_read_handler;
	charq_t			*fde_rbuf;

	/* Write data */
	ev_io			 fde_write_watcher;
	charq_t			*fde_wbuf;

	/* Listener sockets */
	net_accepter		 fde_accepter;
	SSL_CTX			*fde_ssl_ctx;

	/* Connect handler	*/
	net_handler		 fde_connect_handler;
} fde_t;

typedef struct net_ssl_accept_ctx {
	SSL			*sa_ssl;
	ev_io			 sa_reader;
	ev_io			 sa_writer;
	int			 sa_fd;
	int			 sa_nfd;
	struct sockaddr_storage	 sa_addr;
	socklen_t		 sa_addrlen;
} net_ssl_accept_ctx_t;

typedef struct error_handler_data {
	enum {
		F_READ,
		F_WRITE,
		F_ERROR,
		F_TLS_DONE
	}	eh_type;
	int	eh_fd;
	int	eh_error;
	int	eh_what;
} error_handler_data_t;

static balloc_t	*ba_fde, *ba_soon, *ba_iw, *ba_ehd;

static int	net_listen_ai(struct addrinfo *ai, SSL_CTX *, net_accepter accepter, int, void *udata);
static void	net_accept(int, int, void *);
static void	net_read_handler(struct ev_loop *, ev_io *, int);
static void	net_write_handler(struct ev_loop *, ev_io *, int);
static void	net_connect_handler(struct ev_loop *, ev_io *, int);
static void	net_free(int fd);
static void	net_close_impl(void *);
static void	net_signal(struct ev_loop *, ev_signal *, int);
static void	net_ssl_accept_handler(struct ev_loop *, ev_io *, int);
static void	net_call_error_handler(int, int, int);
static void	net_call_read_handler(int);
static void	net_call_write_handler(int);
static void	net_call_tls_done_handler(int);
static void	net_run_soon(struct ev_loop *, ev_prepare *w, int revents);
static void	net_ssl_do_accept(int);
static int	net_do_write(int);

static struct ev_loop *loop;

typedef struct soon {
	net_cron_handler	 hdl;
	void			*udata;
	ev_idle			*w;
	SIMPLEQ_ENTRY(soon)	 list;
} soon_t;

static SIMPLEQ_HEAD(soon_list, soon) soon_list;

fde_t	**fd_table;

static	ev_prepare	soon_ev;
static	ev_signal	sigint, sigterm;

int
net_init()
{
	ba_fde = balloc_new(sizeof(fde_t), 128, "fde_t");
	ba_soon = balloc_new(sizeof(soon_t), 128, "soon_t");
	ba_iw = balloc_new(sizeof(ev_idle), 128, "ev_idle");
	ba_ehd = balloc_new(sizeof(error_handler_data_t), 128, "error_handler_data");
	fd_table = xcalloc(getdtablesize(), sizeof(*fd_table));
	SIMPLEQ_INIT(&soon_list);
	loop = EV_DEFAULT;
	return 0;
}

int
net_resolve(addr, res, flags, type)
	char const	 *addr;
	struct addrinfo	**res;
{
struct addrinfo	 hints;
char		 host[NI_MAXHOST];
char		*s;

	bzero(&hints, sizeof(hints));
	hints.ai_socktype = type;
	hints.ai_flags = flags;

	/* Simple port number */
	strtol(addr, &s, 10);
	if (*s == 0)
		return getaddrinfo(NULL, addr, &hints, res);

	/* IPv6 literal */
	if (*addr == '[') {
		strlcpy(host, addr + 1, sizeof(host));
		if ((s = index(host, ']')) == NULL)
			return -1;
		*s++ = 0;
		if (*s++ == ':')
			return getaddrinfo(host, *s ? s : NULL, &hints, res);
	}

	/* Simple hostname, no port */
	if ((s = index(addr, ':')) == NULL)
		return getaddrinfo(addr, NULL, &hints, res);

	/* host:port */
	strlcpy(host, addr, sizeof(host));
	host[s - addr] = '\0';
	return getaddrinfo(host, s + 1, &hints, res);
}

void
net_open(fd, ssl, prio, readh, errh, udata)
	SSL		*ssl;
	net_handler	 readh;
	net_err_handler	 errh;
	void		*udata;
{
fde_t	*fde;

	if (!fd_table[fd])
		fd_table[fd] = bzalloc(ba_fde);

	fde = fd_table[fd];
	bzero(fde, sizeof(*fde));

	fde->fde_udata = udata;
	fde->fde_read_handler = readh;
	fde->fde_error_handler = errh;
	fde->fde_prio = prio;
	fde->fde_ssl = ssl;

	fde->fde_rbuf = cq_new();
	fde->fde_wbuf = cq_new();

	ev_io_init(&fde->fde_write_watcher, net_write_handler, fd, EV_WRITE);
	ev_set_priority(&fde->fde_write_watcher, prio);
	ev_io_init(&fde->fde_read_watcher, net_read_handler, fd, EV_READ);
	ev_set_priority(&fde->fde_read_watcher, prio);
	ev_io_start(loop, &fde->fde_read_watcher);
	return;
}

static int
net_listen_ai(ai, ctx, accepter, prio, udata)
	struct addrinfo	*ai;
	SSL_CTX		*ctx;
	net_accepter	 accepter;
	void		*udata;
{
	return net_listen_sa(ai->ai_addr, ai->ai_addrlen,
			ctx, prio, ai->ai_socktype, accepter, udata);
}

int
net_listen_sa(sa, len, ctx, prio, type, accepter, udata)
	struct sockaddr	*sa;
	socklen_t	 len;
	SSL_CTX		*ctx;
	net_accepter	 accepter;
	void		*udata;
{
int	sock = -1;
int	one = 1;

	if ((sock = socket(sa->sa_family, type, 0)) == -1)
		goto err;

	if (net_set_cloexec(sock) == -1)
		goto err;

	if (net_set_nonblocking(sock) == -1)
		goto err;

	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == -1)
		goto err;

	if (bind(sock, sa, len) == -1)
		goto err;

	if (listen(sock, 32) == -1)
		goto err;

	net_open(sock, NULL, prio, net_accept, NULL, udata);
	fd_table[sock]->fde_ssl_ctx = ctx;
	fd_table[sock]->fde_accepter = accepter;
	fd_table[sock]->fde_flags |= FDE_LISTENER;
	return 0;

err:
	if (sa->sa_family == AF_UNIX) {
	struct sockaddr_un	*sun = (struct sockaddr_un *) sa;
		nts_log(LOG_ERR, "listen: %.*s: %s",
				(int) sizeof(sun->sun_path),
				sun->sun_path, strerror(errno));
	} else {
	char	host[NI_MAXHOST], serv[NI_MAXSERV];
		getnameinfo(sa, len, host, sizeof(host),
				serv, sizeof(serv), NI_NUMERICHOST);
		nts_log(LOG_ERR, "listen: %s%s%s:%s: %s",
				sa->sa_family == AF_INET6 ? "[" : "",
				host,
				sa->sa_family == AF_INET6 ? "]" : "",
				serv, strerror(errno));
	}

	if (sock != -1)
		close(sock);
	return -1;
}

int
net_listen_unix(path, prio, accepter, udata)
	char const	*path;
	net_accepter	 accepter;
	void		*udata;
{
struct sockaddr_un	sun;

	unlink(path);

	bzero(&sun, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strncpy(sun.sun_path, path, sizeof(sun.sun_path));
	return net_listen_sa((struct sockaddr *) &sun, sizeof(sun), 
			NULL, prio, SOCK_STREAM, accepter, udata);
}

int
net_listen(addr, ctx, prio, type, accepter, udata)
	char const	*addr;
	SSL_CTX		*ctx;
	net_accepter	 accepter;
	void		*udata;
{
struct addrinfo	*res, *r;

	if (net_resolve(addr, &res, AI_PASSIVE, type)) {
		nts_log(LOG_ERR, "cannot resolve \"%s\"", addr);
		return -1;
	}

	for (r = res; r; r = r->ai_next) {
		if (net_listen_ai(r, ctx, accepter, prio, udata))
			return -1;
	}

	return 0;
}

static void
net_accept(fd, what, udata)
	int	 fd, what;
	void	*udata;
{
int			nfd;
struct sockaddr_storage	addr;
socklen_t		addrlen = sizeof(addr);
	
	if ((nfd = accept(fd, (struct sockaddr *) &addr, &addrlen)) == -1) {
		nts_log(LOG_ERR, "accept: %s", strerror(errno));
		return;
	}

	if (net_set_cloexec(nfd) == -1) {
		nts_log(LOG_ERR, "net_set_cloexec: %s\n", strerror(errno));
		close(nfd);
		return;
	}

	if (net_set_nonblocking(nfd) == -1) {
		nts_log(LOG_ERR, "net_set_nonblocking: %s\n", strerror(errno));
		close(nfd);
		return;
	}

#ifdef HAVE_OPENSSL
	if (fd_table[fd]->fde_ssl_ctx) {
	int			 ret;
	net_ssl_accept_ctx_t	*ctx;
	SSL			*ssl;

		ssl = SSL_new(fd_table[fd]->fde_ssl_ctx);
		SSL_set_fd(ssl, nfd);

		if ((ret = SSL_accept(ssl)) == 1) {
			fd_table[fd]->fde_accepter(nfd, (struct sockaddr *) &addr, 
						   addrlen, ssl, fd_table[fd]->fde_udata);
			return;
		} else if (ret == 0) {
			nts_log(LOG_WARNING, "SSL accept failed: %s",
				ERR_error_string(SSL_get_error(ssl, ret), NULL));
			close(nfd);
			return;
		}

		ctx = xcalloc(1, sizeof(*ctx));
		ctx->sa_ssl = ssl;
		ctx->sa_reader.data = ctx;
		ctx->sa_writer.data = ctx;
		ctx->sa_fd = fd;
		ctx->sa_nfd = nfd;
		bcopy(&addr, &ctx->sa_addr, sizeof(addr));
		ctx->sa_addrlen = addrlen;
		ev_io_init(&ctx->sa_reader, net_ssl_accept_handler, nfd, EV_READ);
		ev_io_init(&ctx->sa_writer, net_ssl_accept_handler, nfd, EV_WRITE);

		if (ret == -1) {
		int	err;
			switch (err = SSL_get_error(ctx->sa_ssl, ret)) {
			case SSL_ERROR_WANT_READ:
				ev_io_start(loop, &ctx->sa_reader);
				return;
			case SSL_ERROR_WANT_WRITE:
				ev_io_start(loop, &ctx->sa_writer);
				return;
			default:
				nts_log(LOG_WARNING, "SSL accept failed: %s",
					ERR_error_string(err, NULL));
				close(nfd);
				free(ctx);
				return;
			}
		}
	}
#endif

	fd_table[fd]->fde_accepter(nfd, (struct sockaddr *) &addr, 
			addrlen, NULL, fd_table[fd]->fde_udata);
}

static void
net_ssl_accept_handler(loop, w, revents)
	struct ev_loop	*loop;
	ev_io		*w;
{
int			 ret, err;
net_ssl_accept_ctx_t	*ctx = w->data;
	ev_io_stop(loop, w);

	if ((ret = SSL_accept(ctx->sa_ssl)) == 1) {
		fd_table[ctx->sa_fd]->fde_accepter(ctx->sa_nfd, 
				(struct sockaddr *) &ctx->sa_addr, ctx->sa_addrlen,
				ctx->sa_ssl, fd_table[ctx->sa_fd]->fde_udata);
		free(ctx);
		return;
	} else if (ret == 0) {
		nts_log(LOG_WARNING, "SSL accept failed: %s",
			ERR_error_string(SSL_get_error(ctx->sa_ssl, ret), NULL));
		close(ctx->sa_nfd);
		return;
	}

	switch (err = SSL_get_error(ctx->sa_ssl, ret)) {
	case SSL_ERROR_WANT_READ:
		ev_io_start(loop, &ctx->sa_reader);
		break;
	case SSL_ERROR_WANT_WRITE:
		ev_io_start(loop, &ctx->sa_writer);
		break;
	default:
		nts_log(LOG_WARNING, "SSL accept failed: %s",
			ERR_error_string(err, NULL));
		close(ctx->sa_nfd);
		free(ctx);
		return;
	}
}

void
net_starttls(fd, ctx, hdl)
	SSL_CTX			*ctx;
	net_tls_done_handler	 hdl;
{
fde_t	*fde = fd_table[fd];
	fde->fde_tls_done_handler = hdl;
	fde->fde_ssl_ctx = ctx;
	fde->fde_ssl = SSL_new(ctx);
	SSL_set_fd(fde->fde_ssl, fd);
	fde->fde_flags |= FDE_SSL_ACCEPTING;
	net_ssl_do_accept(fd);
}

static void
net_ssl_do_accept(fd)
{
fde_t	*fde = fd_table[fd];
int	 ret;

	if ((ret = SSL_accept(fde->fde_ssl)) == 1) {
		fde->fde_flags &= ~FDE_SSL_ACCEPTING;
		ev_io_start(loop, &fde->fde_read_watcher);
		cq_remove_start(fde->fde_rbuf, cq_len(fde->fde_rbuf));
		net_call_tls_done_handler(fd);
		return;
	} else if (ret == 0) {
		nts_log(LOG_WARNING, "SSL accept failed: %s",
			ERR_error_string(SSL_get_error(fde->fde_ssl, ret), NULL));
		net_call_error_handler(fd, FDE_READ, EIO);
		return;
	} else if (ret == -1) {
	int	err;
		switch (err = SSL_get_error(fde->fde_ssl, ret)) {
		case SSL_ERROR_WANT_READ:
			ev_io_start(loop, &fde->fde_read_watcher);
			ev_io_stop(loop, &fde->fde_write_watcher);
			return;
		case SSL_ERROR_WANT_WRITE:
			ev_io_start(loop, &fde->fde_write_watcher);
			ev_io_stop(loop, &fde->fde_read_watcher);
			return;
		default:
			net_call_error_handler(fd, FDE_READ, EIO);
			nts_log(LOG_WARNING, "SSL accept failed: %s",
				ERR_error_string(err, NULL));
			return;
		}
	}
}

void
net_pause(fd)
{
fde_t	*fde = fd_table[fd];
	ev_io_stop(loop, &fde->fde_write_watcher);
	ev_io_stop(loop, &fde->fde_read_watcher);
	fde->fde_flags |= FDE_PAUSED;
}

void
net_unpause(fd)
{
fde_t	*fde = fd_table[fd];
	fde->fde_flags &= ~FDE_PAUSED;
	net_do_write(fd);
	ev_io_start(loop, &fde->fde_read_watcher);
}

static void
net_read_handler(loop, w, revents)
	struct ev_loop	*loop;
	ev_io		*w;
	int		 revents;
{
fde_t	*fde = fd_table[w->fd];
	if (fde->fde_flags & FDE_SSL_ACCEPTING) {
		net_ssl_do_accept(w->fd);
		return;
	}

	net_call_read_handler(w->fd);
}

static ssize_t
net_read_some(fd)
{
fde_t	*fde = fd_table[fd];
ssize_t	 n;

#ifdef HAVE_OPENSSL
	if (fde->fde_ssl) {
	int		ret, err;
	static char	rdbuf[8192];
		if (fde->fde_flags & FDE_SSL_WRITE_WANTS_READ) {
			fde->fde_flags &= ~FDE_SSL_WRITE_WANTS_READ;
			ev_io_start(loop, &fde->fde_write_watcher);
		}

		ret = SSL_read(fde->fde_ssl, rdbuf, sizeof(rdbuf));
		if (ret >= 0) {
			cq_append(fde->fde_rbuf, rdbuf, ret);
			fde->fde_flags &= ~FDE_SSL_READ_WANTS_WRITE;
			return ret;
		}

		if (ret == 0) {
			ev_io_stop(loop, &fde->fde_write_watcher);
			ev_io_stop(loop, &fde->fde_read_watcher);
			fde->fde_flags |= FDE_ERROR;
			errno = 0;
			return -1;
		}

		switch (err = SSL_get_error(fde->fde_ssl, ret)) {
		case SSL_ERROR_WANT_READ:
			return 0;

		case SSL_ERROR_WANT_WRITE:
			fde->fde_flags |= FDE_SSL_READ_WANTS_WRITE;
			ev_io_start(loop, &fde->fde_write_watcher);
			return 0;

		default:
			nts_log(LOG_WARNING, "SSL read failed: %s",
				ERR_error_string(err, NULL));
			ev_io_stop(loop, &fde->fde_write_watcher);
			ev_io_stop(loop, &fde->fde_read_watcher);
			fde->fde_flags |= FDE_ERROR;
			errno = EIO;
			return -1;
		}
	}
#endif

	n = cq_read(fde->fde_rbuf, fd);

	if (n == -1) {
		if (errno == EAGAIN)
			return 0;

		DPRINTF(("net_read_some fd=%d n=-1 %s\n", fd, strerror(errno)));
		ev_io_stop(loop, &fde->fde_write_watcher);
		ev_io_stop(loop, &fde->fde_read_watcher);
		fde->fde_flags |= FDE_ERROR;
		return -1;
	}

	if (n == 0) {
		DPRINTF(("net_read_some fd=%d n=0\n", fd));
		ev_io_stop(loop, &fde->fde_write_watcher);
		ev_io_stop(loop, &fde->fde_read_watcher);
		fde->fde_flags |= FDE_ERROR;
		errno = 0;
		return -1;
	}

	return n;
}

ssize_t
net_read(fd, buf, buflen)
	void	*buf;
	size_t	 buflen;
{
ssize_t	 n;
fde_t	*fde = fd_table[fd];

	if (!cq_len(fde->fde_rbuf))
		if ((n = net_read_some(fd)) <= 0)
			return n;

	n = cq_len(fde->fde_rbuf);
	if (n > buflen)
		n = buflen;
	cq_extract_start(fde->fde_rbuf, buf, buflen);
	return n;
}

static int
net_do_write(fd)
{
fde_t	*fde = fd_table[fd];
ssize_t	 n;

	if (cq_len(fde->fde_wbuf) == 0) {
		if (fde->fde_flags & FDE_DRAIN) {
			fde->fde_flags |= FDE_DEAD;
			net_soon(net_close_impl, (void *) (uintptr_t) fd);
		}
		return 0;
	}

#ifdef HAVE_OPENSSL
	if (fde->fde_ssl) {
	int	err;
		n = SSL_write(fde->fde_ssl, cq_first_ent(fde->fde_wbuf)->cqe_data +
			      fde->fde_wbuf->cq_offs,
			      cq_nents(fde->fde_wbuf) > 1
			      	? (CHARQ_BSZ - fde->fde_wbuf->cq_offs)
				: cq_len(fde->fde_wbuf));


		if (n == 0) {
			ev_io_stop(loop, &fde->fde_write_watcher);
			ev_io_stop(loop, &fde->fde_read_watcher);

			if (!(fde->fde_flags & FDE_ERROR)) {
				fde->fde_flags |= FDE_ERROR;
				net_call_error_handler(fd, EV_WRITE, EIO);
			}

			return -1;
		}

		if (n == -1) {
			switch (err = SSL_get_error(fde->fde_ssl, n)) {
			case SSL_ERROR_WANT_READ:
				fde->fde_flags |= FDE_SSL_WRITE_WANTS_READ;
				return 0;

			case SSL_ERROR_WANT_WRITE:
				return 0;

			default:
				nts_log(LOG_WARNING, "SSL write failed: %s",
					ERR_error_string(err, NULL));
				ev_io_stop(loop, &fde->fde_write_watcher);
				ev_io_stop(loop, &fde->fde_read_watcher);

				if (!(fde->fde_flags & FDE_ERROR)) {
					fde->fde_flags |= FDE_ERROR;
					net_call_error_handler(fd, EV_WRITE, EIO);
				}

				return -1;
			}
		}

		cq_remove_start(fde->fde_wbuf, n);
		fde->fde_flags &= ~FDE_SSL_WRITE_WANTS_READ;
		return 0;
	}
#endif

	if ((n = cq_write(fde->fde_wbuf, fd)) == -1) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			ev_io_start(loop, &fde->fde_write_watcher);
			return 0;
		}

		ev_io_stop(loop, &fde->fde_read_watcher);
		ev_io_stop(loop, &fde->fde_write_watcher);

		if (!(fde->fde_flags & FDE_ERROR)) {
			fde->fde_flags |= FDE_ERROR;
			net_call_error_handler(fd, EV_WRITE, errno);
		}

		return -1;
	}

	if (cq_len(fde->fde_wbuf) == 0) {
		ev_io_stop(loop, &fde->fde_write_watcher);
		if (fde->fde_flags & FDE_DRAIN) {
			fde->fde_flags |= FDE_DEAD;
			net_soon(net_close_impl, (void *) (uintptr_t) fd);
		}
	} else
		ev_io_start(loop, &fde->fde_write_watcher);

	return 0;
}

static void
net_write_handler(loop, w, revents)
	struct ev_loop	*loop;
	ev_io		*w;
	int		 revents;
{
fde_t	*fde = fd_table[w->fd];

	if (fde->fde_flags & FDE_SSL_ACCEPTING) {
		net_ssl_do_accept(w->fd);
		return;
	}

	if (fde->fde_flags & FDE_ERROR)
		return;

	if (fde->fde_flags & FDE_SSL_READ_WANTS_WRITE)
		net_call_read_handler(w->fd);
	DPRINTF(("net_write_handler fd=%d\n", w->fd));

	net_do_write(w->fd);
}

void
net_write(fd, data, dsz)
	int		 fd;
	void const	*data;
	size_t		 dsz;
{
fde_t	*fde = fd_table[fd];

	if (fde->fde_flags & FDE_ERROR)
		return;
	cq_append(fde->fde_wbuf, data, dsz);
	if (fde->fde_flags & FDE_PAUSED)
		return;

	net_do_write(fd);
}

void
net_free(fd)
	int	fd;
{
fde_t	*fde = fd_table[fd];
	DPRINTF(("net_free fd=%d\n", fd));
	ev_io_stop(loop, &fde->fde_read_watcher);
	ev_io_stop(loop, &fde->fde_write_watcher);
	cq_free(fde->fde_rbuf);
	cq_free(fde->fde_wbuf);
	if (fde->fde_ssl)
		SSL_free(fde->fde_ssl);
	close(fd);
	bfree(ba_fde, fd_table[fd]);
	fd_table[fd] = NULL;
}

int
net_run(void)
{
	ev_prepare_init(&soon_ev, net_run_soon);
	ev_prepare_start(loop, &soon_ev);
	ev_signal_init(&sigint, net_signal, SIGINT);
	ev_signal_start(loop, &sigint);
	ev_signal_init(&sigterm, net_signal, SIGTERM);
	ev_signal_start(loop, &sigterm);
	ev_run(loop, 0);
	return 0;
}

int
net_set_nonblocking(fd)
	int	fd;
{
int	fl;
	if ((fl = fcntl(fd, F_GETFL, 0)) == -1)
		return -1;
	if (fcntl(fd, F_SETFL, fl | O_NONBLOCK) == -1)
		return -1;
	return 0;
}

int
net_set_cloexec(fd)
	int	fd;
{
int	fl;
	if ((fl = fcntl(fd, F_GETFD, 0)) == -1)
		return -1;
	if (fcntl(fd, F_SETFD, fl | FD_CLOEXEC) == -1)
		return -1;
	return 0;
}

int
net_readline(fd, str)
	int	 fd;
	str_t	*str;
{
fde_t		*fde = fd_table[fd];
str_t		 line;

	if (fde->fde_flags & FDE_DEAD)
		return 0;

	if ((line = cq_read_line(fde->fde_rbuf)) != NULL) {
		*str = line;
		return 1;
	}

	switch (net_read_some(fd)) {
	case 0:	
		return 0;
	case -1:
		return -1;
	}

	if ((line = cq_read_line(fde->fde_rbuf)) == NULL)
		return 0;

	*str = line;

	return 1;
}

static void
net_close_impl(udata)
	void	*udata;
{
	net_free((int) (uintptr_t) udata);
}

void
net_close(fd)
	int	fd;
{
fde_t	*fde = fd_table[fd];
	DPRINTF(("net_close fd=%d\n", fd));
	ev_io_stop(loop, &fde->fde_read_watcher);

	if (cq_len(fde->fde_wbuf) == 0 || (fde->fde_flags & FDE_ERROR)) {
		ev_io_stop(loop, &fde->fde_write_watcher);
		DPRINTF(("fd is dead\n"));
		fde->fde_flags |= FDE_DEAD;
		net_soon(net_close_impl, (void *) (uintptr_t) fd);
	} else {
		DPRINTF(("draining wbuf\n"));
		fde->fde_flags |= FDE_DRAIN;
	}
}

typedef struct cron {
	int			 c_freq;
	ev_periodic		 c_p;
	net_cron_handler	 c_hdl;
	void			*c_udata;
} cron_t;

static void
cron_handler(loop, w, events)
	struct ev_loop	*loop;
	ev_periodic	*w;
{
cron_t	*cron = w->data;
	cron->c_hdl(cron->c_udata);
}

void
net_cron(freq, hdl, udata)
	int			 freq;
	net_cron_handler	 hdl;
	void			*udata;
{
cron_t	*cron = xcalloc(1, sizeof(*cron));
	cron->c_freq = freq;
	cron->c_udata = udata;
	cron->c_hdl = hdl;
	ev_periodic_init(&cron->c_p, cron_handler, 0, cron->c_freq, 0);
	cron->c_p.data = cron;
	ev_periodic_start(loop, &cron->c_p);
}

static void
net_run_soon(loop, w, revents)
	struct ev_loop	*loop;
	ev_prepare	*w;
	int		 revents;
{
soon_t	*soon;

	while (soon = SIMPLEQ_FIRST(&soon_list)) {
		soon->hdl(soon->udata);
		SIMPLEQ_REMOVE_HEAD(&soon_list, list);
		bfree(ba_soon, soon);
	}
}

void
net_soon(hdl, udata)
	net_cron_handler	 hdl;
	void			*udata;
{
soon_t	*soon;
	soon = balloc(ba_soon);
	soon->hdl = hdl;
	soon->udata = udata;
	SIMPLEQ_INSERT_TAIL(&soon_list, soon, list);
}

static void
net_call_handler_do(udata)
	void	*udata;
{
error_handler_data_t	*eh = udata;
fde_t			*fde = fd_table[eh->eh_fd];

	if ((fde->fde_flags & (FDE_ERROR | FDE_DEAD)) &&
	    (eh->eh_type != F_ERROR)) {
		bfree(ba_ehd, eh);
		return;
	}

	switch (eh->eh_type) {
	case F_READ:
		fde->fde_read_handler(eh->eh_fd, FDE_READ, fde->fde_udata);
		break;

	case F_WRITE:
		net_write_handler(loop, &fde->fde_write_watcher, EV_WRITE);
		break;

	case F_ERROR:
		fde->fde_error_handler(eh->eh_fd, eh->eh_what, eh->eh_error,
				       fde->fde_udata);
		break;

	case F_TLS_DONE:
		fde->fde_tls_done_handler(eh->eh_fd, fde->fde_ssl,
					  fde->fde_udata);
		break;
	}

	bfree(ba_ehd, eh);
}

void
net_call_error_handler(fd, what, err)
{
error_handler_data_t	*eh = bzalloc(ba_ehd);
	eh->eh_fd = fd;
	eh->eh_error = err;
	eh->eh_what = what;
	eh->eh_type = F_ERROR;
	net_soon(net_call_handler_do, eh);
}

void
net_call_read_handler(fd)
{
error_handler_data_t	*eh = bzalloc(ba_ehd);

	eh->eh_fd = fd;
	eh->eh_type = F_READ;
	net_soon(net_call_handler_do, eh);
}

void
net_call_write_handler(fd)
{
error_handler_data_t	*eh = bzalloc(ba_ehd);
	eh->eh_fd = fd;
	eh->eh_type = F_WRITE;
	net_soon(net_call_handler_do, eh);
}

void
net_call_tls_done_handler(fd)
{
error_handler_data_t	*eh = bzalloc(ba_ehd);
	eh->eh_fd = fd;
	eh->eh_type = F_TLS_DONE;
	net_soon(net_call_handler_do, eh);
}

void
net_connect(prio, addr, addrlen, bindaddr, bindlen, hdl, errhdl, rhdl, udata)
	struct sockaddr	*addr, *bindaddr;
	socklen_t	 addrlen, bindlen;
	net_handler	 hdl, rhdl;
	net_err_handler	 errhdl;
	void		*udata;
{
int	 fd;
fde_t	*fde;

	if ((fd = socket(addr->sa_family, SOCK_STREAM, 0)) == -1) {
		errhdl(-1, FDE_CONNECT, errno, udata);
		return;
	}

	if (net_set_cloexec(fd) == -1) {
		close(fd);
		errhdl(-1, FDE_CONNECT, errno, udata);
		return;
	}

	if (net_set_nonblocking(fd) == -1) {
		close(fd);
		errhdl(-1, FDE_CONNECT, errno, udata);
		return;
	}

	fd_table[fd] = bzalloc(ba_fde);
	fde = fd_table[fd];

	fde->fde_udata = udata;

	if (bindaddr)
		if (bind(fd, bindaddr, bindlen) == -1) {
			close(fd);
			errhdl(-1, FDE_CONNECT, errno, udata);
			return;
		}

	if (connect(fd, addr, addrlen) == 0) {
		hdl(fd, FDE_CONNECT, udata);
		return;
	}

	if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINPROGRESS) {
		bfree(ba_fde, fd_table[fd]);
		fd_table[fd] = NULL;
		close(fd);
		errhdl(-1, FDE_CONNECT, errno, udata);
		return;
	}

	fd_table[fd]->fde_connect_handler = hdl;
	fd_table[fd]->fde_error_handler = errhdl;
	fd_table[fd]->fde_read_handler = rhdl;
	ev_io_init(&fde->fde_write_watcher, net_connect_handler, fd, EV_WRITE);
	ev_set_priority(&fde->fde_write_watcher, prio);
	fde->fde_prio = prio;
	ev_io_start(loop, &fde->fde_write_watcher);
}

static void
net_connect_handler(loop, w, events)
	struct ev_loop	*loop;
	ev_io		*w;
{
fde_t		*fde = fd_table[w->fd];
int		 err;
socklen_t	 errlen = sizeof(err);

	ev_io_stop(loop, &fde->fde_write_watcher);

	if (getsockopt(w->fd, SOL_SOCKET, SO_ERROR, &err, &errlen) == -1) {
		close(w->fd);
		fde->fde_error_handler(-1, FDE_CONNECT, errno, fde->fde_udata);
		return;
	}

	if (err) {
		close(w->fd);
		fde->fde_error_handler(-1, FDE_CONNECT, err, fde->fde_udata);
		return;
	}

	fde->fde_rbuf = cq_new();
	fde->fde_wbuf = cq_new();

	ev_io_init(&fde->fde_write_watcher, net_write_handler, w->fd, EV_WRITE);
	ev_set_priority(&fde->fde_write_watcher, fde->fde_prio);
	ev_io_init(&fde->fde_read_watcher, net_read_handler, w->fd, EV_READ);
	ev_set_priority(&fde->fde_read_watcher, fde->fde_prio);
	ev_io_start(loop, &fde->fde_read_watcher);

	fde->fde_connect_handler(w->fd, FDE_CONNECT, fde->fde_udata);
}

static void
net_signal(loop, w, events)
	struct ev_loop	*loop;
	ev_signal	*w;
{
	nts_shutdown("received signal");
}

void
net_io_stop(fd)
{
fde_t	*fde = fd_table[fd];
	ev_io_stop(loop, &fde->fde_read_watcher);
}

void
net_io_start(fd)
{
fde_t	*fde = fd_table[fd];
	ev_io_start(loop, &fde->fde_read_watcher);
}
