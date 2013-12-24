/* RT/NTS -- a lightweight, high performance news transit server. */
/* 
 * Copyright (c) 2011-2013 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */

#include	<sys/socket.h>
#include	<netinet/in.h>
#include	<arpa/inet.h>

#include	<stdio.h>
#include	<errno.h>
#include	<strings.h>
#include	<unistd.h>
#include	<stdlib.h>
#include	<inttypes.h>

#include	<ev.h>

#include	"nts.h"
#include	"log.h"
#include	"queue.h"
#include	"dns.h"
#include	"net.h"

#define		DNS_FL_RESPONSE		0x80
#define		DNS_FL_AA		0x04
#define		DNS_FL_TC		0x02
#define		DNS_FL_RD		0x01
#define		DNS_FL_RA		0x80
#define		DNS_QTYPE_A		0x01
#define		DNS_QTYPE_AAAA		0x1C
#define		DNS_QTYPE_ANY		0xFF
#define		DNS_QCLASS_IN		0x01

#define		DNS_RCODE_NOERR		1
#define		DNS_RCODE_FORMERR	2
#define		DNS_RCODE_SERVFAIL	3
#define		DNS_RCODE_NXDOMAIN	4
#define		DNS_RCODE_NOTIMP	5
#define		DNS_RCODE_REFUSED	6

typedef struct dns_server {
	struct sockaddr_storage		 ds_addr;
	size_t				 ds_addrlen;
	int				 ds_fd;
	ev_io				 ds_ev;
	SIMPLEQ_ENTRY(dns_server)	 ds_list;
} dns_server_t;

typedef SIMPLEQ_HEAD(dns_server_list, dns_server) dns_server_list_t;
static dns_server_list_t	 dns_servers;
static dns_server_t		*current_server;
static ev_periodic		 timeout_ev, pending_ev;
static struct ev_loop		*loop;

#define	DNS_TIMEOUT	30
#define	DNS_MAX_RETRIES	5

/* For TCP queries. */
typedef enum {
	DR_UDP = 0,
	DR_CONNECT,
	DR_RECEIVE
} request_state_t;

typedef struct dns_request {
	char		*dr_name;
	int		 dr_types;
	int		 dr_qtype;
	address_list_t	*dr_result;
	uint16_t	 dr_qid;
	dns_done_fn	 dr_fn;
	void		*dr_udata;
	uint16_t	 dr_port;
	int		 dr_retries;
	ev_tstamp	 dr_sent;
	request_state_t	 dr_state;
	int		 dr_fd;
	char		*dr_tcpdata;
	size_t		 dr_tcpdata_len;
#define	TCP_BUFSZ	65535

	TAILQ_ENTRY(dns_request)	 dr_list;
} dns_request_t;

typedef TAILQ_HEAD(dns_request_list, dns_request) dns_request_list_t;
static dns_request_list_t	active_requests;

typedef struct pending {
	char			*pe_data;
	size_t			 pe_len;
	SIMPLEQ_ENTRY(pending)	 pe_list;
} pending_t;

typedef SIMPLEQ_HEAD(pending_list, pending) pending_list_t;
static pending_list_t		pending_requests;

static char const *errs[] = {
	"no data in response",
	"network error",
	"timeout",
	"name not found",
	"query or response format error",
	"server failure",
	"query refused",
	"answer truncated",
	"service not found",
	"error in response packet",
	"name or component too long",
	"unspecified failure"
};

static int	encode_dns_name(unsigned char *buf, char const *name);
static int	dns_parse_answer(unsigned char *buf, size_t buflen,
				 address_list_t *addrlist, int *qid);
static int	dns_build_query(char const *name, unsigned char *buf,
				size_t *buflen, int qid, int qtype);
static void	dns_read_cb(struct ev_loop *, ev_io *, int);
static void	dns_handle_timeouts(struct ev_loop *, ev_periodic *, int);
static void	dns_send_pending(struct ev_loop *, ev_periodic *, int);
static void	request_free(dns_request_t *);
static int	dns_send_query(char const *name, int qid, int qtype);

static void	tcp_start(dns_request_t *);
static void	tcp_connect_done(int, int, void *);
static void	tcp_error(int, int, int, void *);
static void	tcp_read_ready(int, int, void *);

/*
 * Byte 0:	query id, high half
 * Byte 1:	query id, low half
 * Byte 2:	flags
 * 	Bit 0:		QR
 * 	Bits 1-4:	opcode
 * 	Bit 5:		AA
 * 	Bit 6:		TC
 * 	Bit 7:		RD
 * Byte 3:	flags
 * 	Bit 0:		RA
 * 	Bits 1-3:	reserved
 * 	Bits 4-7:	RCode
 * Bytes 4-5:	QDCount
 * Bytes 6-7:	ANCount
 * Bytes 8-9:	NSCount
 * Bytes 10-11:	ARCount
 */

char const *
dns_strerror(err)
{
	return errs[err - 1];
}

static void
request_free(req)
	dns_request_t	*req;
{
address_t	*addr;

	free(req->dr_name);

	if (req->dr_result) {
		while (addr = SIMPLEQ_FIRST(req->dr_result)) {
			SIMPLEQ_REMOVE_HEAD(req->dr_result, ad_list);
			free(addr);
		}
		free(req->dr_result);
	}
	free(req->dr_tcpdata);
	free(req);
}

static void
dns_send_pending(loop, w, revents)
	struct ev_loop	*loop;
	ev_periodic	*w;
{
pending_t	*pe;
ssize_t		 n;
	if (SIMPLEQ_EMPTY(&pending_requests)) {
		ev_periodic_stop(loop, w);
		return;
	}

	while (!SIMPLEQ_EMPTY(&pending_requests)) {
		pe = SIMPLEQ_FIRST(&pending_requests);
		SIMPLEQ_REMOVE_HEAD(&pending_requests, pe_list);

		n = write(current_server->ds_fd, pe->pe_data, pe->pe_len);
		free(pe->pe_data);
		free(pe);
		current_server = SIMPLEQ_NEXT(current_server, ds_list);
		if (!current_server)
			current_server = SIMPLEQ_FIRST(&dns_servers);

		if (n < 0)
			nts_log(LOG_WARNING, "dns: cannot send request: %s",
				strerror(errno));
	}
}

static void
dns_handle_timeouts(loop, w, revents)
	struct ev_loop	*loop;
	ev_periodic	*w;
{
dns_request_t	*req;

	if (TAILQ_EMPTY(&active_requests)) {
		ev_periodic_stop(loop, w);
		return;
	}

restart:
	TAILQ_FOREACH(req, &active_requests, dr_list) {
		if (req->dr_sent + DNS_TIMEOUT > ev_now(loop))
			continue;

		if (++req->dr_retries == DNS_MAX_RETRIES) {
			req->dr_fn(req->dr_name, DNS_ERR_TIMEOUT, NULL, req->dr_udata);
			TAILQ_REMOVE(&active_requests, req, dr_list);
			request_free(req);
			goto restart;
		}

		req->dr_sent = ev_now(loop);
		req->dr_qid = arc4random();
		dns_send_query(req->dr_name, req->dr_qid, req->dr_qtype);
	}
}

static int
encode_dns_name(buf, name)
	unsigned char	*buf;
	char const	*name;
{
unsigned char	*lastdot;
int		 nchars = 0;

	for (lastdot = buf++;; name++, buf++) {
		if (*name == 0) {
			if (nchars > 63)
				return DNS_ERR_LONGNAME;
			*lastdot = nchars;
			*buf = 0;
			return 0;
		}

		if (*name == '.') {
			if (nchars > 63)
				return DNS_ERR_LONGNAME;
			*lastdot = nchars;
			nchars = 0;
			lastdot = buf;
		} else {
			*buf = *name;
			nchars++;
		}
	}
}

int
dns_parse_answer(buf, buflen, addrs, qid)
	unsigned char	*buf;
	size_t		 buflen;
	address_list_t	*addrs;
	int		*qid;
{
unsigned char	*bufp = buf;
int		 rcode, qdcount, ancount, nscount, arcount;

	if (buflen < 12)
		return DNS_ERR_PKTERR;

	*qid = ((int)bufp[0] << 8) | ((int)bufp[1] & 0xFF);
	bufp += 2;
	if (!(*bufp & DNS_FL_RESPONSE))
		return DNS_ERR_PKTERR;
	if (*bufp & DNS_FL_TC)
		return DNS_ERR_TRUNCATED;
	bufp++;
	rcode = (*bufp & 0xFF00) >> 8;

	switch (rcode) {
	case 0:
		break;
	case DNS_RCODE_FORMERR:
		return DNS_ERR_FORMERR;
	case DNS_RCODE_SERVFAIL:
		return DNS_ERR_SERVFAIL;
	case DNS_RCODE_NXDOMAIN:
		return DNS_ERR_NXDOMAIN;
	case DNS_RCODE_REFUSED:
		return DNS_ERR_REFUSED;
	default:
		return DNS_ERR_OTHER;
	}

	bufp++;

	qdcount = ((int)bufp[0] << 8) | (bufp[1] & 0xFF);
	bufp += 2;
	ancount = ((int)bufp[0] << 8) | (bufp[1] & 0xFF);
	bufp += 2;
	nscount = ((int)bufp[0] << 8) | (bufp[1] & 0xFF);
	bufp += 2;
	arcount = ((int)bufp[0] << 8) | (bufp[1] & 0xFF);
	bufp += 2;

	buflen -= 12;

	/* Skip the question section */
	while (qdcount--) {
	int	type, class;
		if (!buflen)
			return DNS_ERR_PKTERR;

		for (;;) {
			if (*bufp & 0xC0) {
				if (buflen < 2)
					return DNS_ERR_PKTERR;
				bufp += 2;
				buflen -= 2;
				break;
			} else if (*bufp == 0) {
				if (buflen < 1)
					return DNS_ERR_PKTERR;
				bufp++;
				buflen--;
				break;
			} else {
				if (buflen < (*bufp + 1))
					return DNS_ERR_PKTERR;
				bufp += (*bufp + 1);
				buflen -= (*bufp + 1);
			}
		}

		if (buflen < 4)
			return DNS_ERR_TRUNCATED;

		type = ((int)bufp[0] << 8) | (bufp[1] & 0xFF);
		bufp += 2;
		class = ((int)bufp[0] << 8) | (bufp[1] & 0xFF);
		bufp += 2;
	}

	while (ancount--) {
	int			 type, class, ttl, len;
	address_t		*addr;
	struct sockaddr_in	*in;
	struct sockaddr_in6	*in6;

		/* Skip the name */
		for (;;) {
			if (*bufp & 0xC0) {
				if (buflen < 2)
					return DNS_ERR_PKTERR;
				bufp += 2;
				buflen -= 2;
				break;
			} else if (*bufp == 0) {
				if (buflen < 1)
					return DNS_ERR_PKTERR;
				bufp++;
				buflen--;
				break;
			} else {
				if (buflen < (*bufp + 1))
					return DNS_ERR_PKTERR;
				bufp += (*bufp + 1);
				buflen -= (*bufp + 1);
			}
		}

		if (buflen < 10)
			return DNS_ERR_PKTERR;

		type = ((int)bufp[0] << 8) | (bufp[1] & 0xFF);
		bufp += 2;
		class = ((int)bufp[0] << 8) | (bufp[1] & 0xFF);
		bufp += 2;
		ttl = ((int)bufp[0] << 24) | ((int)bufp[1] << 16) | 
			((int)bufp[2] << 8) | (bufp[3]);
		bufp += 4;
		len = ((int)bufp[0] << 8) | (bufp[1] & 0xFF);
		bufp += 2;

		buflen -= 10;
		if (buflen < len)
			return DNS_ERR_PKTERR;


		switch (type) {
		case DNS_QTYPE_A:
			if (len != 4)
				return DNS_ERR_FORMERR;

			addr = xcalloc(1, sizeof(*addr));
			in = (struct sockaddr_in *) &addr->ad_addr;
			bzero(in, sizeof(*in));
			in->sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
			in->sin_len = sizeof(*in);
#endif
			bcopy(bufp, &in->sin_addr, len);
			addr->ad_len = sizeof(*in);
			SIMPLEQ_INSERT_TAIL(addrs, addr, ad_list);
			break;

		case DNS_QTYPE_AAAA:
			if (len != 16)
				return DNS_ERR_FORMERR;

			addr = xcalloc(1, sizeof(*addr));
			in6 = (struct sockaddr_in6 *) &addr->ad_addr;
			bzero(in6, sizeof(*in6));
			in6->sin6_family = AF_INET6;
#ifdef HAVE_SIN_LEN
			in6->sin6_len = sizeof(*in6);
#endif
			bcopy(bufp, &in6->sin6_addr, len);
			addr->ad_len = sizeof(*in6);
			SIMPLEQ_INSERT_TAIL(addrs, addr, ad_list);
			break;
		}
		bufp += len;
	}

	return 0;
}

int
dns_build_query(name, buf, buflen, qid, qtype)
	char const	*name;
	unsigned char	*buf;
	size_t		*buflen;
{
unsigned char	*bufp;
int		 ret;

	bufp = buf;
	*bufp++ = (qid & 0xFF00) >> 8;
	*bufp++ = qid & 0xFF;
	*bufp++ = DNS_FL_RD;
	*bufp++ = 0;			/* rcode, 0 for query */
	*bufp++ = 0;			/* qdcount, high byte */
	*bufp++ = 1;			/* qdcount, low byte */
	bzero(&buf[6], 6);		/* ancount, nscount, arcount */
	bufp += 6;

	*buflen = 12 + (strlen(name) * 2) + 8;

	if (ret = encode_dns_name(bufp, name))
		return ret;

	bufp += strlen(name) + 2;
	*bufp++ = (qtype & 0xFF00) >> 8;
	*bufp++ = (qtype & 0xFF);
	*bufp++ = 0;			/* qclass, high byte */
	*bufp++ = DNS_QCLASS_IN;	/* qclass, low byte */

	*buflen = bufp - buf;
	return 0;
}

int
dns_send_query(name, qid, qtype)
	char const	*name;
{
static unsigned char	 buf[65535];
size_t			 buflen = sizeof(buf);
int			 ret;
pending_t		*pe;

	if (ret = dns_build_query(name, buf, &buflen, qid, qtype))
		return ret;

	pe = xcalloc(1, sizeof(*pe));
	pe->pe_data = xmalloc(buflen);
	bcopy(buf, pe->pe_data, buflen);
	pe->pe_len = buflen;
	SIMPLEQ_INSERT_TAIL(&pending_requests, pe, pe_list);
	ev_periodic_start(loop, &pending_ev);
	ev_periodic_start(loop, &timeout_ev);
	return 0;
}
	
void
dns_resolve(name, service, types, fn, udata)
	char const	*name, *service;
	int		 types;
	dns_done_fn	 fn;
	void		*udata;
{
dns_request_t	*dr;
int16_t		 qid;
int		 type, port, ret;
struct servent	*serv;
struct addrinfo	*res, *r, hints;

	bzero(&hints, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = AF_UNSPEC;
	hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV | AI_PASSIVE;

	if ((ret = getaddrinfo(name, service, &hints, &res)) == 0) {
	address_list_t	*list;
		list = xcalloc(1, sizeof(*list));
		SIMPLEQ_INIT(list);

		for (r = res; r; r = r->ai_next) {
		address_t	*addr;
			addr = xcalloc(1, sizeof(*addr));
			bcopy(r->ai_addr, &addr->ad_addr, r->ai_addrlen);
			addr->ad_len = r->ai_addrlen;
			SIMPLEQ_INSERT_TAIL(list, addr, ad_list);
		}

		fn(name, 0, list, udata);
		freeaddrinfo(res);
		return;
	}

	if (service) {
		if ((serv = getservbyname(service, "tcp")) == NULL) {
		char	*p;
			port = strtol(service, &p, 10);
			if (*p || (port < 1) || (port > 65535)) {
				fn(name, DNS_ERR_NO_SERVICE, NULL, udata);
				return;
			}
			port = htons(port);
		} else {
			port = serv->s_port;
		}
	} else {
		port = 0;
	}

	if (types & DNS_TYPE_IPV6)
		type = DNS_QTYPE_AAAA;
	else
		type = DNS_QTYPE_A;

	qid = arc4random();
	if (ret = dns_send_query(name, qid, type)) {
		nts_log(LOG_ERR, "error sending DNS request: %s",
				strerror(errno));
		fn(name, ret, NULL, udata);
		return;
	}

	dr = xcalloc(1, sizeof(*dr));
	dr->dr_fn = fn;
	dr->dr_udata = udata;
	dr->dr_name = xstrdup(name);
	dr->dr_types = types;
	dr->dr_qid = qid;
	dr->dr_result = xcalloc(1, sizeof(*dr->dr_result));
	dr->dr_port = port;
	dr->dr_qtype = (type == DNS_QTYPE_A) ? DNS_QTYPE_A : DNS_QTYPE_AAAA;
	SIMPLEQ_INIT(dr->dr_result);

	TAILQ_INSERT_TAIL(&active_requests, dr, dr_list);
	ev_periodic_start(loop, &timeout_ev);
	ev_periodic_start(loop, &pending_ev);
}

int
dns_init()
{
	TAILQ_INIT(&active_requests);
	SIMPLEQ_INIT(&pending_requests);
	return 0;
}

static void
dns_read_cb(loop, w, revents)
	struct ev_loop	*loop;
	ev_io		*w;
	int		 revents;
{
static unsigned char	 qbuf[65535];
int			 ret;
ssize_t			 n;
int			 qid;
dns_request_t		*req;
address_t		*addr;

	if ((n = recv(w->fd, qbuf, sizeof(qbuf), 0)) == -1) {
		nts_log(LOG_WARNING, "dns: cannot read packet: %s",
			strerror(errno));
		return;
	}

	if (n < 2) {
		nts_log(LOG_WARNING, "dns: received short packet");
		return;
	}
	qid = ((int)qbuf[0] << 8) | ((int)qbuf[1] & 0xFF);

	TAILQ_FOREACH(req, &active_requests, dr_list) {
		if (req->dr_qid == qid)
			break;
	}

	if (!req)
		return;

	if (ret = dns_parse_answer(qbuf, n, req->dr_result, &qid)) {
		if (ret == DNS_ERR_TRUNCATED) {
			nts_log(LOG_INFO, "dns: \"%s\": response truncated, "
				"retrying with TCP", req->dr_name);
			tcp_start(req);
			TAILQ_REMOVE(&active_requests, req, dr_list);
			return;
		}

		nts_log(LOG_WARNING, "dns: failed to parse answer");

		req->dr_fn(req->dr_name, DNS_ERR_FORMERR, NULL, req->dr_udata);

		TAILQ_REMOVE(&active_requests, req, dr_list);
		request_free(req);
		return;
	}
	
	if ((req->dr_types & DNS_TYPE_ANY) == DNS_TYPE_ANY) {
	uint16_t	qid = arc4random();
	int		ret;
		req->dr_types &= ~DNS_TYPE_IPV6;
		req->dr_qtype = DNS_QTYPE_AAAA;
		if (ret = dns_send_query(req->dr_name, qid, DNS_QTYPE_A)) {
			nts_log(LOG_ERR, "error sending DNS request: %s",
					strerror(errno));

			req->dr_fn(req->dr_name, DNS_ERR_NETWORK, NULL, req->dr_udata);

			TAILQ_REMOVE(&active_requests, req, dr_list);
			request_free(req);
			return;
		}
		req->dr_qid = qid;
		return;
	}

	TAILQ_REMOVE(&active_requests, req, dr_list);
	SIMPLEQ_FOREACH(addr, req->dr_result, ad_list) {
		switch (addr->ad_addr.ss_family) {
		case AF_INET:
			((struct sockaddr_in *)&addr->ad_addr)->sin_port = req->dr_port;
			break;
		case AF_INET6:
			((struct sockaddr_in6 *)&addr->ad_addr)->sin6_port = req->dr_port;
			break;
		}
	}

	if (SIMPLEQ_EMPTY(req->dr_result)) {
		req->dr_fn(req->dr_name, DNS_ERR_NODATA, NULL, req->dr_udata);
		free(req->dr_result);
		req->dr_result = NULL;
	} else {
		req->dr_fn(req->dr_name, 0, req->dr_result, req->dr_udata);
		req->dr_result = NULL;
	}
	free(req->dr_name);
	free(req);
}

int
dns_run()
{
FILE		*conf;
char		 line[1024], *p;
dns_server_t	*ds = NULL;

	if ((conf = fopen("/etc/resolv.conf", "r")) == NULL)
		panic("dns: cannot open /etc/resolv.conf: %s",
			strerror(errno));

	SIMPLEQ_INIT(&dns_servers);
	TAILQ_INIT(&active_requests);

	while (fgets(line, sizeof(line), conf)) {
	struct addrinfo	*r, *res, hints;
	int		 ret;

		line[strlen(line) - 1] = '\0';

		for (p = line; *p && !index(" \t", *p); p++)
			;
		if (!*p)
			continue;

		*p++ = '\0';
		if (strcmp(line, "nameserver"))
			continue;

		bzero(&hints, sizeof(hints));
		hints.ai_socktype = SOCK_DGRAM;
		hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;

		if (ret = getaddrinfo(p, "53", &hints, &res)) {
			nts_log(LOG_WARNING, "cannot resolve DNS "
				"server %s: %s", p, gai_strerror(ret));
			continue;
		}

		for (r = res; r; r = r->ai_next) {
			ds = xcalloc(1, sizeof(*ds));
			bcopy(r->ai_addr, &ds->ds_addr, r->ai_addrlen);
			ds->ds_addrlen = r->ai_addrlen;

			if ((ds->ds_fd = socket(ds->ds_addr.ss_family,
						SOCK_DGRAM, 0)) == -1) {
				nts_log(LOG_ERR, "dns: server \"%s\": cannot "
					"create socket: %s", p, strerror(errno));
				return -1;
			}

			if (connect(ds->ds_fd, (struct sockaddr *) &ds->ds_addr,
				    ds->ds_addrlen) == -1) {
				nts_log(LOG_ERR, "dns: server \"%s\": cannot "
					"connect socket: %s", p, strerror(errno));
				return -1;
			}

			ev_io_init(&ds->ds_ev, dns_read_cb, ds->ds_fd, EV_READ);
			ev_io_start(EV_DEFAULT, &ds->ds_ev);

			SIMPLEQ_INSERT_TAIL(&dns_servers, ds, ds_list);
		}

		freeaddrinfo(res);
	}

	if (SIMPLEQ_EMPTY(&dns_servers)) {
		nts_log(LOG_WARNING, "dns: no DNS servers found");
		return 0;
	}

	current_server = SIMPLEQ_FIRST(&dns_servers);

	loop = EV_DEFAULT;
	ev_periodic_init(&timeout_ev, dns_handle_timeouts, 0, 1, NULL);
	ev_periodic_init(&pending_ev, dns_send_pending, 0, .1, NULL);
	return 0;
}

static void
tcp_start(req)
	dns_request_t	*req;
{
	req->dr_tcpdata = xmalloc(TCP_BUFSZ);
	req->dr_tcpdata_len = 0;

	req->dr_state = DR_CONNECT;
	net_connect(NET_DEFPRIO, 
		    (struct sockaddr *)&current_server->ds_addr,
		    current_server->ds_addrlen, NULL, 0,
		    tcp_connect_done, tcp_error, tcp_read_ready,
		    req);
	TAILQ_REMOVE(&active_requests, req, dr_list);
	current_server = SIMPLEQ_NEXT(current_server, ds_list);
	if (!current_server)
		current_server = SIMPLEQ_FIRST(&dns_servers);
}

static void
tcp_error(fd, what, err, udata)
	void	*udata;
{
dns_request_t		*req = udata;
	req->dr_fn(req->dr_name, DNS_ERR_NETWORK, NULL, req->dr_udata);
	request_free(req);
}

static void
tcp_connect_done(fd, what, udata)
	void	*udata;
{
dns_request_t		*req = udata;
static unsigned char	 buf[65535];
size_t			 buflen = sizeof(buf);
int			 ret;
unsigned char		 lenbuf[2];
	req->dr_fd = fd;

	if (ret = dns_build_query(req->dr_name, buf, &buflen, req->dr_qid,
				  (req->dr_types & DNS_TYPE_IPV6) ?
				  	DNS_QTYPE_AAAA : DNS_QTYPE_A)) {
		req->dr_fn(req->dr_name, ret, NULL, req->dr_udata);
		request_free(req);
		return;
	}

	int16put(lenbuf, buflen);
	net_write(req->dr_fd, lenbuf, 2);
	net_write(req->dr_fd, buf, buflen);
	req->dr_state = DR_RECEIVE;
	return;
}

static void
tcp_read_ready(fd, what, udata)
	void	*udata;
{
dns_request_t	*req = udata;
static char	 buf[8192];
ssize_t		 n;

	n = net_read(fd, buf, sizeof(buf));
	if (n == 0)
		return;

	if (n == -1) {
		nts_log(LOG_ERR, "error reading response from DNS server: %s",
				strerror(errno));
		req->dr_fn(req->dr_name, DNS_ERR_NETWORK, NULL, req->dr_udata);
		request_free(req);
		return;
	}

	if ((req->dr_tcpdata_len + n) > TCP_BUFSZ) {
		nts_log(LOG_WARNING, "dns: answer too long");
		req->dr_fn(req->dr_name, DNS_ERR_FORMERR, NULL, req->dr_udata);
		request_free(req);
		return;
	}

	bcopy(buf, req->dr_tcpdata + req->dr_tcpdata_len, n);

	if (req->dr_tcpdata_len > 2) {
	uint16_t	len = int16get(req->dr_tcpdata);

		if ((req->dr_tcpdata_len - 2) >= len) {
		int	ret, qid;
			net_close(req->dr_fd);

			if (ret = dns_parse_answer((unsigned char *)req->dr_tcpdata + 2,
						   req->dr_tcpdata_len - 2,
						   req->dr_result, &qid)) {
				nts_log(LOG_WARNING, "dns: failed to parse answer");
				req->dr_fn(req->dr_name, DNS_ERR_FORMERR, NULL, req->dr_udata);
				request_free(req);
				return;
			}

			free(req->dr_tcpdata);
			req->dr_tcpdata = NULL;

			if (req->dr_types == DNS_TYPE_ANY) {
				req->dr_types &= ~DNS_TYPE_IPV6;
				tcp_start(req);
				return;
			}

			req->dr_fn(req->dr_name, 0, req->dr_result, req->dr_udata);
			req->dr_result = NULL;
			request_free(req);
		}
	}
}

#ifdef TEST_DNS
int
main(argc, argv)
	char **argv;
{
int			 sock;
struct sockaddr_in	 addr;
int32_t			 qid;
char			 answer[65535];
ssize_t			 anslen;
char			 addrs[65535], *ap;
size_t			 addrslen = sizeof(addrs) / sizeof(struct sockaddr_storage);

	printf("Looking up %s on the DNS server %s\n", argv[2], argv[1]);

	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		perror("socket");
		return 1;
	}

	bzero(&addr, sizeof(addr));
	addr.sin_addr.s_addr = inet_addr(argv[1]);
	addr.sin_port = htons(53);
	addr.sin_family = AF_INET;

	if (connect(sock, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
		perror("connect");
		return 1;
	}

	if ((qid = dns_send_query(sock, argv[2], DNS_QTYPE_A)) == -1) {
		perror("dns_send_query");
		return 1;
	}

	if ((anslen = read(sock, answer, sizeof(answer))) < 0) {
		perror("read");
		return 1;
	}

	if (dns_parse_answer(answer, anslen, &addrs, &addrslen, &qid, DNS_QTYPE_A)) {
		printf("failed to parse answer\n");
		return 1;
	}

	ap = addrs;
	while (addrslen) {
	char	addr[64];
		inet_ntop(AF_INET, ap, addr, sizeof(addr));
		printf("addr = [%s]\n", addr);
		ap += 4;
		addrslen -= 4;
	}

	if ((qid = dns_send_query(sock, argv[2], DNS_QTYPE_AAAA)) == -1) {
		perror("dns_send_query");
		return 1;
	}

	if ((anslen = read(sock, answer, sizeof(answer))) < 0) {
		perror("read");
		return 1;
	}

	if (dns_parse_answer(answer, anslen, &addrs, &addrslen, &qid, DNS_QTYPE_AAAA)) {
		printf("failed to parse answer\n");
		return 1;
	}

	ap = addrs;
	while (addrslen) {
	char	addr[64];
		inet_ntop(AF_INET6, ap, addr, sizeof(addr));
		printf("addr = [%s]\n", addr);
		ap += 16;
		addrslen -= 16;
	}
	return 0;
}
#endif
