/* RT/NTS -- a lightweight, high performance news transit server. */
/* 
 * Copyright (c) 2011, 2012 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */
/* $Header: /cvsroot/nts/dns.h,v 1.2 2012/01/09 18:18:47 river Exp $ */

#ifndef	NTS_DNS_H
#define	NTS_DNS_H

#define	DNS_ERR_NODATA		1
#define	DNS_ERR_NETWORK		2
#define	DNS_ERR_TIMEOUT		3
#define	DNS_ERR_NXDOMAIN	4
#define	DNS_ERR_FORMERR		5
#define	DNS_ERR_SERVFAIL	6
#define	DNS_ERR_REFUSED		7
#define	DNS_ERR_TRUNCATED	8
#define DNS_ERR_NO_SERVICE	9
#define DNS_ERR_PKTERR		10
#define	DNS_ERR_LONGNAME	11
#define	DNS_ERR_OTHER		12

#define	DNS_TYPE_IPV4		0x1
#define	DNS_TYPE_IPV6		0x2
#define	DNS_TYPE_ANY		0x3

char const	*dns_strerror(int);

typedef void (*dns_done_fn) (
		char const	*name,
		int		 err,
		address_list_t	*addrlist,
		void		*udata
	);
void	dns_resolve(char const *name, char const *port, int types,
		    dns_done_fn done, void *udata);

int	dns_init(void);
int	dns_run(void);

#endif	/* !NTS_DNS_H */
