/* RT/NTS -- a lightweight, high performance news transit server. */
/* 
 * Copyright (c) 2011, 2012 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */
/* $Header: /cvsroot/nts/server.c,v 1.43 2012/01/10 01:03:06 river Exp $ */

#include	<sys/types.h>
#include	<sys/socket.h>
#include	<netinet/in.h>

#include	<netdb.h>
#include	<stdlib.h>
#include	<string.h>
#include	<stdio.h>
#include	<assert.h>

#include	"server.h"
#include	"config.h"
#include	"log.h"
#include	"nts.h"
#include	"net.h"
#include	"dns.h"

static void	*peer_stanza_start(conf_stanza_t *, void *);
static void	 peer_stanza_end(conf_stanza_t *, void *);
static void	 peer_set_port(conf_stanza_t *, conf_option_t *, void *, void *);
static void	 peer_set_accept_from(conf_stanza_t *, conf_option_t *, void *, void *);
static void	 peer_set_send_to(conf_stanza_t *, conf_option_t *, void *, void *);
static void	 peer_set_exclude(conf_stanza_t *, conf_option_t *, void *, void *);
static void	 peer_set_offer_filter(conf_stanza_t *, conf_option_t *, void *, void *);
static void	 peer_set_incoming_filters(conf_stanza_t *, conf_option_t *, void *, void *);
static void	 peer_set_outgoing_filters(conf_stanza_t *, conf_option_t *, void *, void *);
static void	 peer_set_maxconns(conf_stanza_t *, conf_option_t *, void *, void *);
static void	 peer_set_max_size(conf_stanza_t *, conf_option_t *, void *, void *);
static void	 peer_set_host(conf_stanza_t *, conf_option_t *, void *, void *);
static void	 peer_set_bind_address(conf_stanza_t *, conf_option_t *, void *, void *);
static void	 peer_set_bind_address_v4(conf_stanza_t *, conf_option_t *, void *, void *);
static void	 peer_set_bind_address_v6(conf_stanza_t *, conf_option_t *, void *, void *);
static void	 peer_set_adaptive(conf_stanza_t *, conf_option_t *, void *, void *);
static void	 peer_set_incoming_username(conf_stanza_t *, conf_option_t *, void *, void *);
static void	 peer_set_outgoing_username(conf_stanza_t *, conf_option_t *, void *, void *);

static void	 server_add_exclude(server_t *, char const *);
static void	 server_resolve_done(char const *name, int err, address_list_t *, void *);
static void	 rebuild_server_map(void);
static void	 server_update_dns(void *);

static void	 do_stats(void *);

static config_schema_opt_t peer_opts[] = {
	{ "port",			OPT_TYPE_NUMBER | OPT_TYPE_STRING,	peer_set_port },
	{ "accept-from",		OPT_TYPE_STRING | OPT_LIST,		peer_set_accept_from },
	{ "send-to",			OPT_TYPE_STRING,			peer_set_send_to },
	{ "exclude",			OPT_TYPE_STRING | OPT_LIST,		peer_set_exclude },
	{ "incoming-filters",		OPT_TYPE_STRING | OPT_LIST,		peer_set_incoming_filters },
	{ "outgoing-filters",		OPT_TYPE_STRING | OPT_LIST,		peer_set_outgoing_filters },
	{ "max-incoming-connections",	OPT_TYPE_NUMBER,			peer_set_maxconns },
	{ "max-size",			OPT_TYPE_QUANTITY,			peer_set_max_size },
	{ "host",			OPT_TYPE_STRING,			peer_set_host },
	{ "offer-filter",		OPT_TYPE_STRING,			peer_set_offer_filter },
	{ "bind-address",		OPT_TYPE_STRING,			peer_set_bind_address },
	{ "bind-address-v4",		OPT_TYPE_STRING,			peer_set_bind_address_v4 },
	{ "bind-address-v6",		OPT_TYPE_STRING,			peer_set_bind_address_v6 },
	{ "adaptive",			OPT_TYPE_NUMBER | OPT_LIST,		peer_set_adaptive },
	{ "incoming-username",		OPT_TYPE_STRING,			peer_set_incoming_username },
	{ "outgoing-username",		OPT_TYPE_STRING,			peer_set_outgoing_username },
	{ }
};

static config_schema_stanza_t peer_stanza = {
	"peer", SC_MANY, peer_opts, peer_stanza_start, peer_stanza_end
};

typedef struct server_map {
	struct sockaddr_storage	 sm_addr;
	server_t		*sm_server;
} server_map_t;

server_list_t		 servers;
static server_map_t	*server_map;
static size_t		 smapsize;
server_t		*default_server;
balloc_t		*ba_sbe;

int
server_map_compare(a, b)
	void const	*a, *b;
{
struct sockaddr_storage	const	*key = a,
				*value = &((server_map_t *) b)->sm_addr;
	if (key->ss_family != value->ss_family)
		return value->ss_family - key->ss_family;
	switch (key->ss_family) {

	case AF_INET: {
	struct sockaddr_in const	*s1 = (struct sockaddr_in *)key,
			 		*s2 = (struct sockaddr_in *)value;
		return memcmp(&s1->sin_addr, &s2->sin_addr, sizeof(s1->sin_addr));
	}

	case AF_INET6: {
	struct sockaddr_in6 const	*s1 = (struct sockaddr_in6 *)key,
					*s2 = (struct sockaddr_in6 *)value;
		return memcmp(&s1->sin6_addr, &s2->sin6_addr, sizeof(s1->sin6_addr));
	}

	default:
		abort();
	}
}

server_t *
server_find_by_address(addr)
	struct sockaddr_storage *addr;
{
server_map_t	*match;
	if ((match = bsearch(addr, &server_map[0], smapsize, sizeof(server_map_t),
			server_map_compare)) == NULL)
		return NULL;
	return match->sm_server;
}

int
server_init()
{
	ba_sbe = balloc_new(sizeof(server_backlog_entry_t), 128, "sbe");
	config_add_stanza(&peer_stanza);
	return 0;
}

int
backlog_compare(db, a, b)
	DB		*db;
	DBT const	*a, *b;
{
uint32_t	aid, bid;
uint64_t	apos, bpos;
	aid = int32get(a->data);
	apos = int64get(a->data + sizeof(uint32_t));
	bid = int32get(b->data);
	bpos = int64get(b->data + sizeof(uint32_t));

	if (aid != bid)
		return aid - bid;
	return apos - bpos;
}

int
server_run()
{
char		 dbname[128];
server_t	*se;
int		 ret;

	SLIST_FOREACH(se, &servers, se_list) {
	hostlist_entry_t	*addr;

		SLIST_FOREACH(addr, &se->se_accept_from, hl_list)
			++se->se_resolving;

		SLIST_FOREACH(addr, &se->se_accept_from, hl_list)
			dns_resolve(addr->hl_host, NULL, DNS_TYPE_ANY,
				    server_resolve_done, se);

		snprintf(dbname, sizeof(dbname), "backlog.%s.db", se->se_name);

		if (ret = db_create(&se->se_backlog_db, db_env, 0))
			panic("server: cannot create backlog database: %s",
					db_strerror(ret));

		if (ret = se->se_backlog_db->set_bt_compare(se->se_backlog_db,
					backlog_compare))
			panic("server: cannot set backlog compare function: %s",
					db_strerror(ret));

		if (ret = se->se_backlog_db->open(se->se_backlog_db, NULL, dbname,
					NULL, DB_BTREE, DB_CREATE | DB_AUTO_COMMIT, 0))
			panic("server: cannot open backlog database: %s",
					db_strerror(ret));
	}

	rebuild_server_map();

	net_cron(stats_interval, do_stats, NULL);
	net_cron(3600, server_update_dns, NULL);
	return 0;
}

static void
server_update_dns(udata)
	void	*udata;
{
server_t		*se;
hostlist_entry_t	*addr;
	SLIST_FOREACH(se, &servers, se_list) {
		SLIST_FOREACH(addr, &se->se_accept_from, hl_list)
			++se->se_resolving;

		SLIST_FOREACH(addr, &se->se_accept_from, hl_list)
			dns_resolve(addr->hl_host, NULL, DNS_TYPE_ANY,
				    server_resolve_done, se);
	}
}

static void *
peer_stanza_start(stz, udata)
	conf_stanza_t	*stz;
	void		*udata;
{
server_t	*server;
	server = xcalloc(1, sizeof(*server));

	if (stz->cs_title) {
		server->se_name = xstrdup(stz->cs_title);
	} else if (default_server) {
		nts_log(LOG_ERR, "\"%s\", line %d: default peer already "
				"specified", stz->cs_file, stz->cs_lineno);
	} else
		default_server = server;

	server->se_adp_hi = -1;
	SIMPLEQ_INIT(&server->se_filters_in);
	SIMPLEQ_INIT(&server->se_filters_out);
	SLIST_INIT(&server->se_accept_from);
	SIMPLEQ_INIT(&server->se_accept_addrs);
	SIMPLEQ_INIT(&server->se_resolvelist);
	SIMPLEQ_INIT(&server->se_offer_filters);

	return server;
}

static void
peer_stanza_end(stz, udata)
	conf_stanza_t	*stz;
	void		*udata;
{
server_t	*server = udata;

	if (server == default_server)
		return;

	if (!server->se_port)
		if (default_server && default_server->se_port)
			server->se_port = default_server->se_port;
		else
			server->se_port = xstrdup("119");

	if (!server->se_maxconns)
		if (default_server && default_server->se_maxconns)
			server->se_maxconns = default_server->se_maxconns;
		else
			server->se_maxconns = SERVER_MAXCONNS_DEFAULT;

	if (!server->se_max_size && default_server && default_server->se_max_size)
		server->se_max_size = default_server->se_max_size;

	if (SIMPLEQ_EMPTY(&server->se_filters_in) && default_server &&
	    !SIMPLEQ_EMPTY(&default_server->se_filters_in))
		bcopy(&default_server->se_filters_in,
			&server->se_filters_in, sizeof(server->se_filters_in));

	if (SIMPLEQ_EMPTY(&server->se_filters_out) && default_server &&
	    !SIMPLEQ_EMPTY(&default_server->se_filters_out))
		bcopy(&default_server->se_filters_out,
			&server->se_filters_out, sizeof(server->se_filters_out));

	if (server->se_bind_v4.sin_family == 0 && default_server &&
	    default_server->se_bind_v4.sin_family != 0)
		bcopy(&default_server->se_bind_v4, &server->se_bind_v4,
			sizeof(server->se_bind_v4));

	if (server->se_bind_v6.sin6_family == 0 && default_server &&
	    default_server->se_bind_v6.sin6_family != 0)
		bcopy(&default_server->se_bind_v6, &server->se_bind_v6,
			sizeof(server->se_bind_v6));

	if (server->se_adp_hi == -1 && default_server && default_server->se_adp_hi) {
		server->se_adp_hi = default_server->se_adp_hi;
		server->se_adp_lo = default_server->se_adp_lo;
	}

	if (server->se_host) {
		if (SLIST_EMPTY(&server->se_accept_from)) {
		hostlist_entry_t	*he = xcalloc(1, sizeof(*he));
			he->hl_host = xstrdup(server->se_host);
			SLIST_INSERT_HEAD(&server->se_accept_from, he, hl_list);
		}
		if (server->se_send_to == NULL)
			server->se_send_to = xstrdup(server->se_host);
		if (SLIST_EMPTY(&server->se_exclude))
			server_add_exclude(server, server->se_host);
	}

	if (SLIST_EMPTY(&server->se_exclude)) {
	hostlist_entry_t	*hl = xcalloc(1, sizeof(*hl));
		hl->hl_host = xstrdup(server->se_name);
		SLIST_INSERT_HEAD(&server->se_exclude, hl, hl_list);
	}

	SLIST_INSERT_HEAD(&servers, server, se_list);
}

static void
server_resolve_done(name, err, list, udata)
	char const	*name;
	address_list_t	*list;
	void		*udata;
{
server_t	*se = udata;
address_t	*addr;

	assert(se->se_resolving);

	if (err) {
		nts_log(LOG_ERR, "error resolving accept-from address \"%s\" for "
			"\"%s\": %s", name, se->se_name, dns_strerror(err));
		return;
	}

	while (addr = SIMPLEQ_FIRST(list)) {
		SIMPLEQ_REMOVE_HEAD(list, ad_list);
		SIMPLEQ_INSERT_TAIL(&se->se_resolvelist, addr, ad_list);
	}

	if (--se->se_resolving)
		return;

	free(list);

	while (addr = SIMPLEQ_FIRST(&se->se_accept_addrs)) {
		SIMPLEQ_REMOVE_HEAD(&se->se_accept_addrs, ad_list);
		free(addr);
	}

	while (addr = SIMPLEQ_FIRST(&se->se_resolvelist)) {
		SIMPLEQ_REMOVE_HEAD(&se->se_resolvelist, ad_list);
		SIMPLEQ_INSERT_TAIL(&se->se_accept_addrs, addr, ad_list);
	}

	rebuild_server_map();
}

static void
rebuild_server_map()
{
server_t	*se;
address_t	*a;
size_t		 i = 0;
	
	smapsize = 0;
	SLIST_FOREACH(se, &servers, se_list)
		SIMPLEQ_FOREACH(a, &se->se_accept_addrs, ad_list) 
			smapsize++;
	
	server_map = xrealloc(server_map, sizeof(*server_map) * smapsize);

	SLIST_FOREACH(se, &servers, se_list) {
		SIMPLEQ_FOREACH(a, &se->se_accept_addrs, ad_list) {
			server_map[i].sm_server = se;
			bcopy(&a->ad_addr, &server_map[i].sm_addr, sizeof(a->ad_addr));
			i++;
		}
	}

	qsort(&server_map[0], smapsize, sizeof(*server_map), server_map_compare);
}

static void
peer_set_port(stz, opt, udata, arg)
	conf_stanza_t	*stz;
	conf_option_t	*opt;
	void		*udata, *arg;
{
server_t	*server = udata;
conf_val_t	*v = opt->co_value;

	free(server->se_port);

	if (v->cv_type == CV_STRING)
		server->se_port = xstrdup(v->cv_string);
	else {
		server->se_port = xmalloc(64);
		snprintf(server->se_port, 64, "%ld", (long int) v->cv_number);
	}
}

static void
peer_set_incoming_username(stz, opt, udata, arg)
	conf_stanza_t	*stz;
	conf_option_t	*opt;
	void		*udata, *arg;
{
server_t	*server = udata;
	free(server->se_username_in);
	server->se_username_in = xstrdup(opt->co_value->cv_string);
}

static void
peer_set_outgoing_username(stz, opt, udata, arg)
	conf_stanza_t	*stz;
	conf_option_t	*opt;
	void		*udata, *arg;
{
server_t	*server = udata;
	free(server->se_username_out);
	server->se_username_out = xstrdup(opt->co_value->cv_string);
}

static void
peer_set_incoming_filters(stz, opt, udata, arg)
	conf_stanza_t	*stz;
	conf_option_t	*opt;
	void		*udata, *arg;
{
server_t	*server = udata;
conf_val_t	*val;

	for (val = opt->co_value; val; val = val->cv_next) {
	filter_t	*filter;
	filter_group_t	*filter_group;

		if (filter = filter_find_by_name(val->cv_string)) {
		filter_list_entry_t	*fle = xcalloc(1, sizeof(*fle));
			fle->fle_filter = filter;
			SIMPLEQ_INSERT_TAIL(&server->se_filters_in, fle, fle_list);
			filter->fi_flags |= FILTER_USED;
		} else if (filter_group = filter_group_find_by_name(val->cv_string)) {
		filter_list_entry_t	*fle;
			SIMPLEQ_FOREACH(fle, &filter_group->fg_filters, fle_list) {
			filter_list_entry_t	*sfl = xcalloc(1, sizeof(*sfl));
				sfl->fle_filter = fle->fle_filter;
				SIMPLEQ_INSERT_TAIL(&server->se_filters_in, sfl, fle_list);
				fle->fle_filter->fi_flags |= FILTER_USED;
			}
		} else {
			nts_log(LOG_ERR, "\"%s\", line %d: undefined filter \"%s\"",
					opt->co_file, opt->co_lineno, val->cv_string);
		}
	}
}

static void
peer_set_offer_filter(stz, opt, udata, arg)
	conf_stanza_t	*stz;
	conf_option_t	*opt;
	void		*udata, *arg;
{
server_t	*se = udata;
conf_val_t	*val;

	for (val = opt->co_value; val; val = val->cv_next) {
	strlist_entry_t	*sle;
		sle = bzalloc(ba_strlist);
		sle->sl_str = str_new_c(val->cv_string);
		SIMPLEQ_INSERT_TAIL(&se->se_offer_filters, sle, sl_list);
	}
}

static void
peer_set_outgoing_filters(stz, opt, udata, arg)
	conf_stanza_t	*stz;
	conf_option_t	*opt;
	void		*udata, *arg;
{
server_t	*server = udata;
conf_val_t	*val;

	for (val = opt->co_value; val; val = val->cv_next) {
	filter_t	*filter;
	filter_group_t	*filter_group;

		if (filter = filter_find_by_name(val->cv_string)) {
		filter_list_entry_t	*fle = xcalloc(1, sizeof(*fle));
			fle->fle_filter = filter;
			filter->fi_flags |= FILTER_USED;
			SIMPLEQ_INSERT_TAIL(&server->se_filters_out, fle, fle_list);
		} else if (filter_group = filter_group_find_by_name(val->cv_string)) {
		filter_list_entry_t	*fle;
			SIMPLEQ_FOREACH(fle, &filter_group->fg_filters, fle_list) {
			filter_list_entry_t	*sfl = xcalloc(1, sizeof(*sfl));
				sfl->fle_filter = fle->fle_filter;
				SIMPLEQ_INSERT_TAIL(&server->se_filters_out, sfl, fle_list);
				fle->fle_filter->fi_flags |= FILTER_USED;
			}
		} else {
			nts_log(LOG_ERR, "\"%s\", line %d: undefined filter \"%s\"",
					opt->co_file, opt->co_lineno, val->cv_string);
		}
	}
}

static void
peer_set_host(stz, opt, udata, arg)
	conf_stanza_t	*stz;
	conf_option_t	*opt;
	void		*udata, *arg;
{
server_t	*se = udata;
	if (se == default_server) {
		nts_log(LOG_ERR, "\"%s\", line %d: \"host\" cannot be "
			"specified for the default peer",
			opt->co_file, opt->co_lineno);
		return;
	}
	se->se_host = xstrdup(opt->co_value->cv_string);
}

static void
peer_set_send_to(stz, opt, udata, arg)
	conf_stanza_t	*stz;
	conf_option_t	*opt;
	void		*udata, *arg;
{
server_t	*server = udata;

	if (server == default_server) {
		nts_log(LOG_ERR, "\"%s\", line %d: \"send-to\" cannot be "
			"specified for the default peer",
			opt->co_file, opt->co_lineno);
		return;
	}

	server->se_send_to = xstrdup(opt->co_value->cv_string);
}

static void
peer_set_accept_from(stz, opt, udata, arg)
	conf_stanza_t	*stz;
	conf_option_t	*opt;
	void		*udata, *arg;
{
server_t	*server = udata;
conf_val_t	*val;

	if (server == default_server) {
		nts_log(LOG_ERR, "\"%s\", line %d: \"accept-from\" cannot be "
			"specified for the default peer",
			opt->co_file, opt->co_lineno);
		return;
	}

	for (val = opt->co_value; val; val = val->cv_next) {
	hostlist_entry_t	*hl = xcalloc(1, sizeof(*hl));
		hl->hl_host = xstrdup(val->cv_string);
		SLIST_INSERT_HEAD(&server->se_accept_from, hl, hl_list);
	}
}

static void
peer_set_maxconns(stz, opt, udata, arg)
	conf_stanza_t	*stz;
	conf_option_t	*opt;
	void		*udata, *arg;
{
server_t	*se = udata;
	se->se_maxconns = opt->co_value->cv_number;
}

static void
peer_set_max_size(stz, opt, udata, arg)
	conf_stanza_t	*stz;
	conf_option_t	*opt;
	void		*udata, *arg;
{
server_t	*se = udata;
	se->se_max_size = opt->co_value->cv_number;
}

static void
peer_set_exclude(stz, opt, udata, arg)
	conf_stanza_t	*stz;
	conf_option_t	*opt;
	void		*udata, *arg;
{
conf_val_t	*val;
server_t	*se = udata;

	if (se == default_server) {
		nts_log(LOG_ERR, "\"%s\", line %d: \"exclude\" cannot be "
			"specified for the default peer",
			opt->co_file, opt->co_lineno);
		return;
	}

	for (val = opt->co_value; val; val = val->cv_next)
		server_add_exclude(se, val->cv_string);
}

static void
peer_set_bind_address(stz, opt, udata, arg)
	conf_stanza_t	*stz;
	conf_option_t	*opt;
	void		*udata, *arg;
{
struct addrinfo	 hints, *res, *r;
conf_val_t	*val;
server_t	*se = udata;

	bzero(&hints, sizeof(hints));
	hints.ai_flags = AI_PASSIVE;
	hints.ai_socktype = SOCK_STREAM;

	for (val = opt->co_value; val; val = val->cv_next) {
	int	ret;
		if (ret = getaddrinfo(val->cv_string, NULL, &hints, &res)) {
			nts_log(LOG_ERR, "\"%s\", line %d: cannot resolve: %s",
					opt->co_file, opt->co_lineno,
					gai_strerror(ret));
			return;
		}

		/* Find the first v4 and v6 address, if present */
		for (r = res; r; r = r->ai_next)
			if (r->ai_family == AF_INET)
				break;
		if (r)
			bcopy(r->ai_addr, &se->se_bind_v4, r->ai_addrlen);

		for (r = res; r; r = r->ai_next)
			if (r->ai_family == AF_INET6)
				break;
		if (r)
			bcopy(r->ai_addr, &se->se_bind_v6, r->ai_addrlen);

		freeaddrinfo(res);
	}
}

static void
peer_set_bind_address_v4(stz, opt, udata, arg)
	conf_stanza_t	*stz;
	conf_option_t	*opt;
	void		*udata, *arg;
{
struct addrinfo	 hints, *res;
server_t	*se = udata;
int		 ret;

	bzero(&hints, sizeof(hints));
	hints.ai_flags = AI_PASSIVE;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = AF_INET;

	if (ret = getaddrinfo(opt->co_value->cv_string, NULL, &hints, &res)) {
		nts_log(LOG_ERR, "\"%s\", line %d: cannot resolve: %s",
				opt->co_file, opt->co_lineno,
				gai_strerror(ret));
		return;
	}

	bcopy(res->ai_addr, &se->se_bind_v4, res->ai_addrlen);
	freeaddrinfo(res);
}

static void
peer_set_bind_address_v6(stz, opt, udata, arg)
	conf_stanza_t	*stz;
	conf_option_t	*opt;
	void		*udata, *arg;
{
struct addrinfo	 hints, *res;
server_t	*se = udata;
int		 ret;

	bzero(&hints, sizeof(hints));
	hints.ai_flags = AI_PASSIVE;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = AF_INET6;

	if (ret = getaddrinfo(opt->co_value->cv_string, NULL, &hints, &res)) {
		nts_log(LOG_ERR, "\"%s\", line %d: cannot resolve: %s",
				opt->co_file, opt->co_lineno,
				gai_strerror(ret));
		return;
	}

	bcopy(res->ai_addr, &se->se_bind_v6, res->ai_addrlen);
	freeaddrinfo(res);
}

static void
peer_set_adaptive(stz, opt, udata, arg)
	conf_stanza_t	*stz;
	conf_option_t	*opt;
	void		*udata, *arg;
{
server_t	*se = udata;
	se->se_adp_hi = opt->co_value->cv_number;
	if (opt->co_value->cv_next)
		se->se_adp_lo = opt->co_value->cv_next->cv_number;
}

static void
server_add_exclude(se, path)
	server_t	*se;
	char const	*path;
{
hostlist_entry_t	*hl = xcalloc(1, sizeof(*hl));
	hl->hl_host = xstrdup(path);
	SLIST_INSERT_HEAD(&se->se_exclude, hl, hl_list);
}

static str_t
next_path(str)
	str_t	str;
{
ssize_t end;
str_t	line;

	if (str_length(str) == 0)
		return NULL;

	if ((end = str_find(str, "!")) == -1) {
	str_t	ret = str_copy(str);
		str_remove_start(str, str_length(str));
		return ret;
	}

	line = str_copy_len(str, end);
	str_remove_start(str, end + 1);
	return line;
}

int
server_wants_article(se, art)
	server_t	*se;
	article_t	*art;
{
hostlist_entry_t	*hl;

	if (se->se_max_size && (str_length(art->art_content) > se->se_max_size))
		return 0;

	SLIST_FOREACH(hl, &se->se_exclude, hl_list) {
	str_t	path = str_copy(art->art_path), ent;

		while (ent = next_path(path)) {
			if (str_equal_c(ent, hl->hl_host)) {
				str_free(path);
				str_free(ent);
				return 0;
			}

			str_free(ent);
		}
		str_free(path);
	}

	if (filter_article(art, NULL, &se->se_filters_out, NULL) == FILTER_RESULT_DENY)
		return 0;

	return 1;
}

void
server_add_backlog(se, art, txn)
	server_t	*se;
	article_t	*art;
	DB_TXN		*txn;
{
DBT	 key, data;
int	 ret;
char	 dbuf[sizeof(uint32_t) + sizeof(uint64_t)];

	bzero(&key, sizeof(key));
	bzero(&data, sizeof(data));

	int32put(dbuf, art->art_spool_pos.sp_id);
	int64put(dbuf + sizeof(uint32_t), art->art_spool_pos.sp_offset);
	key.data = dbuf;
	key.size = sizeof(dbuf);

	if (ret = se->se_backlog_db->put(se->se_backlog_db,
			txn, &key, &data, 0))
		panic("server: cannot write to backlog db: %s",
			db_strerror(ret));
}

void
server_shutdown()
{
server_t	*se;

	SLIST_FOREACH(se, &servers, se_list) {
		if (se->se_backlog_db)
			se->se_backlog_db->close(se->se_backlog_db, 0);
	}
}

int
server_accept_offer(se, msgid)
	server_t	*se;
	str_t		 msgid;
{
strlist_entry_t	*sle;
	SIMPLEQ_FOREACH(sle, &se->se_offer_filters, sl_list) {
		if (str_match(msgid, sle->sl_str))
			return 0;
	}
	return 1;
}

static void
do_stats(udata)
	void	*udata;
{
server_t	*se;
	SLIST_FOREACH(se, &servers, se_list) {
		se->se_in_accepted_persec = ((double) se->se_in_accepted - 
				se->se_in_accepted_last) / stats_interval;
		se->se_in_rejected_persec = ((double) se->se_in_rejected -
				se->se_in_rejected_last) / stats_interval;
		se->se_in_refused_persec = ((double) se->se_in_refused - 
				se->se_in_refused_last) / stats_interval;
		se->se_in_deferred_persec = ((double) se->se_in_deferred - 
				se->se_in_deferred_last) / stats_interval;
		se->se_out_accepted_persec = ((double) se->se_out_accepted - 
				se->se_out_accepted_last) / stats_interval;
		se->se_out_rejected_persec = ((double) se->se_out_rejected - 
				se->se_out_rejected_last) / stats_interval;
		se->se_out_refused_persec = ((double) se->se_out_refused - 
				se->se_out_refused_last) / stats_interval;
		se->se_out_deferred_persec = ((double) se->se_out_deferred - 
				se->se_out_deferred_last) / stats_interval;

		se->se_in_accepted_last = se->se_in_accepted;
		se->se_in_rejected_last = se->se_in_rejected;
		se->se_in_refused_last = se->se_in_refused;
		se->se_in_deferred_last = se->se_in_deferred;
		se->se_out_accepted_last = se->se_out_accepted;
		se->se_out_rejected_last = se->se_out_rejected;
		se->se_out_refused_last = se->se_out_refused;
		se->se_out_deferred_last = se->se_out_deferred;
	}
}

int
server_has_backlog(se)
	server_t	*se;
{
DBT	 key, data;
DBC	*curs;
DB	*db = se->se_backlog_db;
char	 kbuf[sizeof(uint32_t) + sizeof(uint64_t)];
int	 ret;

	bzero(&key, sizeof(key));
	bzero(&data, sizeof(data));
	key.ulen = sizeof(kbuf);
	key.flags = DB_DBT_USERMEM;
	key.data = kbuf;

	if (ret = db->cursor(db, NULL, &curs, 0))
		panic("cannot create cursor to backlog database: %s",
		      db_strerror(ret));

	if (ret = curs->get(curs, &key, &data, DB_FIRST)) {
		if (ret == DB_NOTFOUND) {
			curs->close(curs);
			return 0;
		}
		panic("cannot read from backlog database: %s",
		      db_strerror(ret));
	}

	curs->close(curs);
	return 1;
}
