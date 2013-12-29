/* RT/NTS -- a lightweight, high performance news transit server. */
/* 
 * Copyright (c) 2011-2013 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */

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
#include	"feeder.h"

static void	*peer_stanza_start(conf_stanza_t *, void *);
static void	 peer_stanza_end(conf_stanza_t *, void *);
static void	 peer_set_port(conf_stanza_t *, conf_option_t *, void *, void *);
static void	 peer_set_accept_from(conf_stanza_t *, conf_option_t *, void *, void *);
static void	 peer_set_send_to(conf_stanza_t *, conf_option_t *, void *, void *);
static void	 peer_set_exclude(conf_stanza_t *, conf_option_t *, void *, void *);
static void	 peer_set_offer_filter(conf_stanza_t *, conf_option_t *, void *, void *);
static void	 peer_set_incoming_filters(conf_stanza_t *, conf_option_t *, void *, void *);
static void	 peer_set_outgoing_filters(conf_stanza_t *, conf_option_t *, void *, void *);
static void	 peer_set_maxconns_in(conf_stanza_t *, conf_option_t *, void *, void *);
static void	 peer_set_maxconns_out(conf_stanza_t *, conf_option_t *, void *, void *);
static void	 peer_set_max_size(conf_stanza_t *, conf_option_t *, void *, void *);
static void	 peer_set_host(conf_stanza_t *, conf_option_t *, void *, void *);
static void	 peer_set_bind_address(conf_stanza_t *, conf_option_t *, void *, void *);
static void	 peer_set_bind_address_v4(conf_stanza_t *, conf_option_t *, void *, void *);
static void	 peer_set_bind_address_v6(conf_stanza_t *, conf_option_t *, void *, void *);
static void	 peer_set_adaptive(conf_stanza_t *, conf_option_t *, void *, void *);
static void	 peer_set_incoming_username(conf_stanza_t *, conf_option_t *, void *, void *);
static void	 peer_set_outgoing_username(conf_stanza_t *, conf_option_t *, void *, void *);
static void	 peer_set_article_buffer(conf_stanza_t *, conf_option_t *, void *, void *);

static void	 server_add_exclude(server_t *, char const *);
static void	 on_server_dns_done(uv_getaddrinfo_t *, int, struct addrinfo *);
static void	 rebuild_server_map(void);
static void	 server_update_dns(uv_timer_t *, int);

static void	 do_stats(uv_timer_t *, int);

static uv_timer_t	stats_timer,
			dns_timer;

static config_schema_opt_t peer_opts[] = {
	{ "port",			OPT_TYPE_NUMBER | OPT_TYPE_STRING,	peer_set_port },
	{ "accept-from",		OPT_TYPE_STRING | OPT_LIST,		peer_set_accept_from },
	{ "send-to",			OPT_TYPE_STRING,			peer_set_send_to },
	{ "exclude",			OPT_TYPE_STRING | OPT_LIST,		peer_set_exclude },
	{ "incoming-filters",		OPT_TYPE_STRING | OPT_LIST,		peer_set_incoming_filters },
	{ "outgoing-filters",		OPT_TYPE_STRING | OPT_LIST,		peer_set_outgoing_filters },
	{ "max-incoming-connections",	OPT_TYPE_NUMBER,			peer_set_maxconns_in },
	{ "max-outgoing-connections",	OPT_TYPE_NUMBER,			peer_set_maxconns_out },
	{ "max-size",			OPT_TYPE_QUANTITY,			peer_set_max_size },
	{ "host",			OPT_TYPE_STRING,			peer_set_host },
	{ "offer-filter",		OPT_TYPE_STRING,			peer_set_offer_filter },
	{ "bind-address",		OPT_TYPE_STRING,			peer_set_bind_address },
	{ "bind-address-v4",		OPT_TYPE_STRING,			peer_set_bind_address_v4 },
	{ "bind-address-v6",		OPT_TYPE_STRING,			peer_set_bind_address_v6 },
	{ "adaptive",			OPT_TYPE_NUMBER | OPT_LIST,		peer_set_adaptive },
	{ "incoming-username",		OPT_TYPE_STRING,			peer_set_incoming_username },
	{ "outgoing-username",		OPT_TYPE_STRING,			peer_set_outgoing_username },
	{ "article-buffer",		OPT_TYPE_NUMBER,			peer_set_article_buffer },
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

		SLIST_FOREACH(addr, &se->se_accept_from, hl_list) {
		uv_getaddrinfo_t	*req;
		struct addrinfo		 hints;
		int			 ret;

			bzero(&hints, sizeof(hints));
			hints.ai_socktype = SOCK_STREAM;
			hints.ai_family = PF_UNSPEC;
			hints.ai_flags = AI_PASSIVE;

			req = xcalloc(1, sizeof(*req));
			req->data = se;

			if (ret = uv_getaddrinfo(loop, req, on_server_dns_done,
						 addr->hl_host, NULL, &hints)) {
				nts_log("peer \"%s\": cannot resolve \"%s\": %s",
					se->se_name, addr->hl_host, uv_strerror(ret));
				free(req);
				continue;
			}
			++se->se_resolving;
		}

		snprintf(dbname, sizeof(dbname), "queue.%s.db", se->se_name);

		if (ret = db_create(&se->se_q, db_env, 0))
			panic("server: cannot create queue database: %s",
				db_strerror(ret));

		if (ret = se->se_q->set_bt_compare(se->se_q,
					backlog_compare))
			panic("server: cannot set queue compare function: %s",
				db_strerror(ret));

		if (ret = se->se_q->open(se->se_q, NULL, dbname,
					NULL, DB_BTREE, DB_CREATE | DB_AUTO_COMMIT, 0))
			panic("server: cannot open queue database: %s",
				db_strerror(ret));

		snprintf(dbname, sizeof(dbname), "defer.%s.db", se->se_name);

		if (ret = db_create(&se->se_deferred, db_env, 0))
			panic("server: cannot create defer database: %s",
				db_strerror(ret));

		if (ret = se->se_deferred->set_bt_compare(se->se_deferred,
					backlog_compare))
			panic("server: cannot set defer compare function: %s",
				db_strerror(ret));

		if (ret = se->se_deferred->open(se->se_deferred, NULL, dbname,
					NULL, DB_BTREE, DB_CREATE | DB_AUTO_COMMIT, 0))
			panic("server: cannot open defer database: %s",
				db_strerror(ret));
	}

	rebuild_server_map();

	uv_timer_init(loop, &stats_timer);
	uv_timer_start(&stats_timer, do_stats, stats_interval * 1000,
		       stats_interval * 1000);

	uv_timer_init(loop, &dns_timer);
	uv_timer_start(&dns_timer, server_update_dns,
		       3600 * 1000, 3600 * 1000);
	return 0;
}

static void
server_update_dns(timer, status)
	uv_timer_t	*timer;
{
server_t		*se;
hostlist_entry_t	*addr;
	SLIST_FOREACH(se, &servers, se_list) {
		SLIST_FOREACH(addr, &se->se_accept_from, hl_list) {
		uv_getaddrinfo_t	*req;
		struct addrinfo		 hints;
		int			 ret;

			bzero(&hints, sizeof(hints));
			hints.ai_socktype = SOCK_STREAM;
			hints.ai_family = PF_UNSPEC;
			hints.ai_flags = AI_PASSIVE;

			req = xcalloc(1, sizeof(*req));
			req->data = se;

			if (ret = uv_getaddrinfo(loop, req, on_server_dns_done,
						 addr->hl_host, NULL, &hints)) {
				nts_log("peer \"%s\": cannot resolve \"%s\": %s",
					se->se_name, addr->hl_host, uv_strerror(ret));
				free(req);
				continue;
			}

			++se->se_resolving;
		}
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
		nts_log("\"%s\", line %d: default peer already "
			"specified", stz->cs_file, stz->cs_lineno);
	} else
		default_server = server;

	server->se_adp_hi = -1;
	server->se_buffer = -1;

	SIMPLEQ_INIT(&server->se_clients);
	SIMPLEQ_INIT(&server->se_filters_in);
	SIMPLEQ_INIT(&server->se_filters_out);
	SLIST_INIT(&server->se_accept_from);
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

	if (!server->se_maxconns_in)
		if (default_server && default_server->se_maxconns_in)
			server->se_maxconns_in = default_server->se_maxconns_in;
		else
			server->se_maxconns_in = SERVER_MAXCONNS_DEFAULT;

	if (!server->se_maxconns_out)
		if (default_server && default_server->se_maxconns_out)
			server->se_maxconns_out = default_server->se_maxconns_out;
		else
			server->se_maxconns_out = SERVER_MAXCONNS_DEFAULT;

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

	if (server->se_adp_hi == -1 && default_server && default_server->se_adp_hi > 0) {
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

	if (server->se_buffer == -1 && default_server && default_server->se_buffer > 0)
		server->se_buffer = default_server->se_buffer;
	else
		server->se_buffer = 1;

	if (SLIST_EMPTY(&server->se_exclude)) {
	hostlist_entry_t	*hl = xcalloc(1, sizeof(*hl));
		hl->hl_host = xstrdup(server->se_name);
		SLIST_INSERT_HEAD(&server->se_exclude, hl, hl_list);
	}

	SLIST_INSERT_HEAD(&servers, server, se_list);
}

static void
on_server_dns_done(req, status, res)
	uv_getaddrinfo_t	*req;
	struct addrinfo		*res;
{
server_t	*se = req->data;

	assert(se->se_resolving);

	if (status) {
		nts_log("error resolving accept-from address for "
			"\"%s\": %s", se->se_name, uv_strerror(status));
		return;
	}

	res->ai_next = se->se_resolvelist;
	se->se_resolvelist = res;

	if (--se->se_resolving)
		return;

	se->se_accept_addrs = se->se_resolvelist;
	rebuild_server_map();
}

static void
rebuild_server_map()
{
server_t	*se;
struct addrinfo	*r;
size_t		 i = 0;
	
	smapsize = 0;
	SLIST_FOREACH(se, &servers, se_list)
		for (r = se->se_accept_addrs; r; r = r->ai_next)
			smapsize++;
	
	server_map = xrealloc(server_map, sizeof(*server_map) * smapsize);

	SLIST_FOREACH(se, &servers, se_list) {
		for (r = se->se_accept_addrs; r; r = r->ai_next) {
			server_map[i].sm_server = se;
			bcopy(r->ai_addr, &server_map[i].sm_addr, r->ai_addrlen);
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
	server->se_port = NULL;

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
			nts_log("\"%s\", line %d: undefined filter \"%s\"",
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
		sle = xcalloc(1, sizeof(*sle));
		sle->sl_str = xstrdup(val->cv_string);
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
			nts_log("\"%s\", line %d: undefined filter \"%s\"",
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
		nts_log("\"%s\", line %d: \"host\" cannot be "
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
		nts_log("\"%s\", line %d: \"send-to\" cannot be "
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
		nts_log("\"%s\", line %d: \"accept-from\" cannot be "
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
peer_set_maxconns_in(stz, opt, udata, arg)
	conf_stanza_t	*stz;
	conf_option_t	*opt;
	void		*udata, *arg;
{
server_t	*se = udata;
	se->se_maxconns_in = opt->co_value->cv_number;
}

static void
peer_set_maxconns_out(stz, opt, udata, arg)
	conf_stanza_t	*stz;
	conf_option_t	*opt;
	void		*udata, *arg;
{
server_t	*se = udata;
	se->se_maxconns_out = opt->co_value->cv_number;
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
		nts_log("\"%s\", line %d: \"exclude\" cannot be "
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
			nts_log("\"%s\", line %d: cannot resolve: %s",
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
		nts_log("\"%s\", line %d: cannot resolve: %s",
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
		nts_log("\"%s\", line %d: cannot resolve: %s",
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
peer_set_article_buffer(stz, opt, udata, arg)
	conf_stanza_t	*stz;
	conf_option_t	*opt;
	void		*udata, *arg;
{
server_t	*se = udata;
	se->se_buffer = opt->co_value->cv_number;
	if (se->se_buffer == 0)
		se->se_buffer = 1;
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

int
server_wants_article(se, art)
	server_t	*se;
	article_t	*art;
{
hostlist_entry_t	*hl;

	if (se->se_max_size && (strlen(art->art_content) > se->se_max_size))
		return 0;

	SLIST_FOREACH(hl, &se->se_exclude, hl_list) {
	char	*path_ = xstrdup(art->art_path), *path = path_, *ent;

		while (ent = next_any(&path, "!")) {
			if (strcasecmp(ent, hl->hl_host) == 0) {
				free(path_);
				path = path_ = NULL;
				return 0;
			}
		}
		free(path_);
		path = path_ = NULL;
	}

	if (filter_article(art, NULL, &se->se_filters_out, NULL) == FILTER_RESULT_DENY)
		return 0;

	return 1;
}

void
server_shutdown()
{
server_t	*se;

	SLIST_FOREACH(se, &servers, se_list) {
	}
}

int
server_accept_offer(se, msgid)
	server_t	*se;
	const char	*msgid;
{
strlist_entry_t	*sle;
	SIMPLEQ_FOREACH(sle, &se->se_offer_filters, sl_list) {
		if (strmatch(msgid, sle->sl_str))
			return 0;
	}
	return 1;
}

static void
do_stats(timer, status)
	uv_timer_t	*timer;
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

void
server_notify_article(art)
	article_t	*art;
{
server_t	*se;
DB_TXN		*txn;
int		 ret;
	
	art->art_refs = 0;

	txn = db_new_txn(spool_do_sync ? 0 : DB_TXN_WRITE_NOSYNC);

	SLIST_FOREACH(se, &servers, se_list) {
		if (!se->se_send_to || !server_wants_article(se, art))
			continue;

		server_addq(se, art, txn);
	}

	if (ret = txn->commit(txn, 0))
		panic("server: cannot commit backlog txn: %s", db_strerror(ret));

	SLIST_FOREACH(se, &servers, se_list) {
		if (!se->se_send_to || !server_wants_article(se, art))
			continue;
		feeder_notify(se->se_feeder);
	}
}

void
server_addq(server_t *se, article_t *art, DB_TXN *txn)
{
DBT              key, data;
int              ret;
unsigned char    dbuf[4 + 8];

        bzero(&key, sizeof(key));
        pack(dbuf, "uU", art->art_spool_pos.sp_id,
                         art->art_spool_pos.sp_offset);
        key.size = sizeof(dbuf);
        key.data = dbuf;

        bzero(&data, sizeof(data));
	data.size = strlen(art->art_msgid);
	data.data = art->art_msgid;

        if (ret = se->se_q->put(se->se_q, txn, &key, &data, 0))
                panic("server: cannot write to q db: %s",
                        db_strerror(ret));
}

qent_t *
qealloc()
{
qent_t	*qe = xcalloc(1, sizeof(*qe));
	return qe;
}               

void
qefree(qe)
	qent_t	*qe;
{
	free(qe->qe_msgid);
	free(qe);
}

void
server_remove_q(se, qe)
	server_t	*se;
	qent_t		*qe;
{
DBT              key;
int              ret;
DB_TXN          *txn;
unsigned char    dbuf[4 + 8];
DB              *db;

        bzero(&key, sizeof(key));
        pack(dbuf, "uU", qe->qe_pos.sp_id, qe->qe_pos.sp_offset);
        key.data = dbuf;
        key.size = sizeof(dbuf);

        db = (qe->qe_type == QT_Q) ?
                  se->se_q
                : se->se_deferred;

        txn = db_new_txn(DB_TXN_WRITE_NOSYNC);

        if (ret = db->del(db, txn, &key, 0))
        /*      if (ret != DB_NOTFOUND)*/
        /*              panic("cannot remove backlog entry: %s",
                                        db_strerror(ret));*/
                nts_log("cannot remove backlog entry %.8lX,%lu: %s",
			(long unsigned) qe->qe_pos.sp_id,
			(long unsigned) qe->qe_pos.sp_offset,
			db_strerror(ret));
        txn->commit(txn, 0);
}

void
server_defer(se, qe)
	server_t	*se;
	qent_t		*qe;
{
DBT              key, data;
int              ret;
unsigned char    dbuf[4 + 8];
DB_TXN          *txn;

        bzero(&key, sizeof(key));
        bzero(&data, sizeof(data));

	data.size = strlen(qe->qe_msgid);
	data.data = qe->qe_msgid;

        pack(dbuf, "uU", qe->qe_pos.sp_id, qe->qe_pos.sp_offset);
        key.size = sizeof(dbuf);
        key.data = dbuf;

        txn = db_new_txn(DB_TXN_WRITE_NOSYNC);

        if (ret = se->se_q->del(se->se_q, txn, &key, 0))
                if (ret != DB_NOTFOUND)
                        panic("server: cannot write to q db: %s",
                                db_strerror(ret));
        if (ret = se->se_deferred->put(se->se_deferred, txn, &key, &data, 0))
                panic("server: cannot write to deferred db: %s",
                        db_strerror(ret));

        txn->commit(txn, 0);
        qefree(qe);
	qe = NULL;
}
