/* RT/NTS -- a lightweight, high performance news transit server. */
/* 
 * Copyright (c) 2011-2013 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */

#include	<string.h>
#include	<math.h>
#include	<assert.h>

#include	"filter.h"
#include	"config.h"
#include	"wildmat.h"
#include	"nts.h"
#include	"log.h"
#include	"database.h"
#include	"crc.h"
#include	"hash.h"
#include	"emp.h"

filter_list_t		filter_list;
filter_group_list_t	filter_group_list;
int			nfilters;

static void	filter_set_groups(conf_stanza_t *, conf_option_t *, void *, void *);
static void	filter_set_action(conf_stanza_t *, conf_option_t *, void *, void *);
static void	filter_set_types(conf_stanza_t *, conf_option_t *, void *, void *);
static void	filter_set_log_rejected(conf_stanza_t *, conf_option_t *, void *, void *);
static void	filter_set_max_crosspost(conf_stanza_t *, conf_option_t *, void *, void *);
static void	filter_set_path(conf_stanza_t *, conf_option_t *, void *, void *);
static void	filter_set_emp_limit(conf_stanza_t *, conf_option_t *, void *, void *);
static void	filter_set_phl_limit(conf_stanza_t *, conf_option_t *, void *, void *);

static void	*filter_start(conf_stanza_t *, void *);
static void	 filter_end(conf_stanza_t *, void *);

static void	 filter_group_set_filters(conf_stanza_t *, conf_option_t *, void *, void *);

static void	*filter_group_start(conf_stanza_t *, void *);
static void	 filter_group_end(conf_stanza_t *, void *);

static config_schema_opt_t filter_opts[] = {
	{ "groups",		OPT_TYPE_STRING | OPT_LIST,	filter_set_groups },
	{ "action",		OPT_TYPE_STRING,		filter_set_action },
	{ "article-types",	OPT_TYPE_STRING | OPT_LIST,	filter_set_types },
	{ "emp-limit",		OPT_TYPE_NUMBER,		filter_set_emp_limit },
	{ "phl-limit",		OPT_TYPE_NUMBER,		filter_set_phl_limit },
	{ "max-crosspost",	OPT_TYPE_NUMBER,		filter_set_max_crosspost },
	{ "log-rejected",	OPT_TYPE_BOOLEAN,		filter_set_log_rejected },
	{ "path",		OPT_TYPE_STRING | OPT_LIST,	filter_set_path },
	{ }
};

static config_schema_opt_t filter_group_opts[] = {
	{ "filters",		OPT_TYPE_STRING | OPT_LIST,	filter_group_set_filters },
	{ }
};

static config_schema_stanza_t
	filter_stanza =		{ "filter",		SC_REQTITLE,	
				  filter_opts,		filter_start,
				  filter_end },

	filter_group_stanza =	{ "filter-group",	SC_REQTITLE,	
				  filter_group_opts,	filter_group_start,
				  filter_group_end };

int
filter_init()
{
	config_add_stanza(&filter_stanza);
	config_add_stanza(&filter_group_stanza);

	if (emp_init() == -1)
		return -1;

	SIMPLEQ_INIT(&filter_list);
	SIMPLEQ_INIT(&filter_group_list);

	return 0;
}

int
filter_run()
{
	return emp_run();
}

void *
filter_group_start(stz, udata)
	conf_stanza_t	*stz;
	void		*udata;
{
filter_group_t	*fg = xcalloc(1, sizeof(*fg));
	fg->fg_name = xstrdup(stz->cs_title);
	SIMPLEQ_INIT(&fg->fg_filters);
	return fg;
}

void
filter_group_end(stz, udata)
	conf_stanza_t	*stz;
	void		*udata;
{
filter_group_t	*fg = udata;
	SIMPLEQ_INSERT_TAIL(&filter_group_list, fg, fg_list);
}

void
filter_group_set_filters(stz, opt, udata, arg)
	conf_stanza_t	*stz;
	conf_option_t	*opt;
	void		*udata, *arg;
{
filter_group_t	*fg = udata;
conf_val_t	*val;

	for (val = opt->co_value; val; val = val->cv_next) {
	filter_t		*fi;
	filter_group_t		*fg2;
	filter_list_entry_t	*fle;

		if (fi = filter_find_by_name(val->cv_string)) {
			fle = xcalloc(1, sizeof(*fle));
			fle->fle_filter = fi;
			SIMPLEQ_INSERT_TAIL(&fg->fg_filters, fle, fle_list);
		} else if (fg2 = filter_group_find_by_name(val->cv_string)) {
			SIMPLEQ_FOREACH(fle, &fg2->fg_filters, fle_list) {
			filter_list_entry_t	*fle2 = xcalloc(1, sizeof(*fle));
				fle2->fle_filter = fle->fle_filter;
				SIMPLEQ_INSERT_TAIL(&fg->fg_filters, fle2, fle_list);
			}
		} else
			nts_log("\"%s\", line %d: undefined filter \"%s\"",
				opt->co_file, opt->co_lineno, val->cv_string);

	}
}

void *
filter_start(stz, udata)
	conf_stanza_t	*stz;
	void		*udata;
{
filter_t	*filter = xcalloc(1, sizeof(*filter));
	filter->fi_name = xstrdup(stz->cs_title);
	filter->fi_flags |= FILTER_ACT_DUNNO;
	SIMPLEQ_INIT(&filter->fi_paths);
	return filter;
}

void
filter_end(stz, udata)
	conf_stanza_t	*stz;
	void		*udata;
{
filter_t		*fi = udata;
filter_list_entry_t	*fle = xcalloc(1, sizeof(*fle));
	fle->fle_filter = fi;
	fi->fi_bit = nfilters;
	SIMPLEQ_INSERT_TAIL(&filter_list, fle, fle_list);
	nfilters++;
}

void
filter_set_groups(stz, opt, udata, arg)
	conf_stanza_t	*stz;
	conf_option_t	*opt;
	void		*udata, *arg;
{
filter_t	*fi = udata;
	fi->fi_groups = wildmat_from_value(opt->co_value);
}

void
filter_set_action(stz, opt, udata, arg)
	conf_stanza_t	*stz;
	conf_option_t	*opt;
	void		*udata, *arg;
{
filter_t	*fi = udata;
char		*s = opt->co_value->cv_string;

	fi->fi_flags &= ~FILTER_ACT_MASK;

	if (strcmp(s, "deny") == 0)
		fi->fi_flags |= FILTER_ACT_DENY;
	else if (strcmp(s, "permit") == 0)
		fi->fi_flags |= FILTER_ACT_PERMIT;
	else
		nts_log("\"%s\", line %d: unknown filter action \"%s\"",
			opt->co_file, opt->co_lineno, s);
}

void
filter_set_types(stz, opt, udata, arg)
	conf_stanza_t	*stz;
	conf_option_t	*opt;
	void		*udata, *arg;
{
filter_t	*fi = udata;
conf_val_t	*val;

	for (val = opt->co_value; val; val = val->cv_next) {
	char	*s = val->cv_string;
		if (strcmp(s, "mime-binary") == 0)
			fi->fi_art_types |= ART_TYPE_MIME_BINARY;
		else if (strcmp(s, "uuencode") == 0)
			fi->fi_art_types |= ART_TYPE_UUE;
		else if (strcmp(s, "yenc") == 0)
			fi->fi_art_types |= ART_TYPE_YENC;
		else if (strcmp(s, "binary") == 0)
			fi->fi_art_types |= ART_TYPE_BINARY;
		else if (strcmp(s, "mime-text") == 0)
			fi->fi_art_types |= ART_TYPE_MIME_TEXT;
		else if (strcmp(s, "html") == 0)
			fi->fi_art_types |= ART_TYPE_HTML;
		else
			nts_log("\"%s\", line %d: unknown article type \"%s\"",
				opt->co_file, opt->co_lineno, s);
	}
}

void
filter_set_max_crosspost(stz, opt, udata, arg)
	conf_stanza_t	*stz;
	conf_option_t	*opt;
	void		*udata, *arg;
{
filter_t	*fi = udata;
	fi->fi_max_crosspost = opt->co_value->cv_number;
	fi->fi_flags &= ~FILTER_ACT_MASK;
	fi->fi_flags |= FILTER_ACT_DENY;
}

void
filter_set_emp_limit(stz, opt, udata, arg)
	conf_stanza_t	*stz;
	conf_option_t	*opt;
	void		*udata, *arg;
{
filter_t	*fi = udata;
	do_emp_tracking = 1;
	fi->fi_emp_limit = opt->co_value->cv_number;
	fi->fi_flags &= ~FILTER_ACT_MASK;
	fi->fi_flags |= FILTER_ACT_DENY;
}

void
filter_set_log_rejected(stz, opt, udata, arg)
	conf_stanza_t	*stz;
	conf_option_t	*opt;
	void		*udata, *arg;
{
filter_t	*fi = udata;
	if (opt->co_value->cv_boolean)
		fi->fi_flags |= FILTER_LOG_REJECTED;
	else
		fi->fi_flags &= ~FILTER_LOG_REJECTED;
}

void
filter_set_phl_limit(stz, opt, udata, arg)
	conf_stanza_t	*stz;
	conf_option_t	*opt;
	void		*udata, *arg;
{
filter_t	*fi = udata;
	do_phl_tracking = 1;
	fi->fi_phl_limit = opt->co_value->cv_number;
	fi->fi_flags &= ~FILTER_ACT_MASK;
	fi->fi_flags |= FILTER_ACT_DENY;
}

static void
filter_set_path(stz, opt, udata, arg)
	conf_stanza_t	*stz;
	conf_option_t	*opt;
	void		*udata, *arg;
{
conf_val_t	*val;
filter_t	*fi = udata;

	for (val = opt->co_value; val; val = val->cv_next) {
	strlist_entry_t	*sle;
		sle = xcalloc(1, sizeof(*sle));
		sle->sl_str = xstrdup(val->cv_string);
		SIMPLEQ_INSERT_TAIL(&fi->fi_paths, sle, sl_list);
	}
}

filter_t *
filter_find_by_name(name)
	char const	*name;
{
filter_list_entry_t	*fle;
	SIMPLEQ_FOREACH(fle, &filter_list, fle_list) {
		if (strcmp(fle->fle_filter->fi_name, name) == 0)
			return fle->fle_filter;
	}
	return NULL;
}

filter_group_t *
filter_group_find_by_name(name)
	char const	*name;
{
filter_group_t	*fg;
	SIMPLEQ_FOREACH(fg, &filter_group_list, fg_list) {
		if (strcmp(fg->fg_name, name) == 0)
			return fg;
	}
	return NULL;
}

static int
filter_match_path(art, paths)
	article_t	*art;
	strlist_t	*paths;
{
strlist_entry_t	*pe;
char		*ent, *pc = xstrdup(art->art_path);

	while (ent = next_any(&pc, "!")) {
		SIMPLEQ_FOREACH(pe, paths, sl_list) {
			if (strcasecmp(ent, pe->sl_str) == 0) {
				free(pc);
				return 1;
			}
		}
	}

	free(pc);
	return 0;
}

static int
filter_match_groups(art, mat)
	article_t	*art;
	wildmat_t	*mat;
{
strlist_entry_t	*ge;
	SIMPLEQ_FOREACH(ge, &art->art_groups, sl_list) {
		if (wildmat_match(mat, ge->sl_str))
			return 1;
	}

	return 0;
}

int
filter_match(art, fi)
	article_t	*art;
	filter_t	*fi;
{
	if (fi->fi_art_types)
		if ((fi->fi_art_types & art->art_flags) == 0)
			return 0;

	if (fi->fi_groups) {
		if (filter_match_groups(art, fi->fi_groups) == 0)
			return 0;
	}

	if (!SIMPLEQ_EMPTY(&fi->fi_paths))
		if (filter_match_path(art, &fi->fi_paths) == 0)
			return 0;

	if (fi->fi_max_crosspost)
		if (art->art_ngroups > fi->fi_max_crosspost)
			return 1;
		else
			return 0;

	/*
	 * Don't apply the EMP filter to control messages, they tend to have
	 * very similar bodies.
	 */

	if (fi->fi_emp_limit)
		if (!(art->art_flags & ART_CONTROL) &&
		     (art->art_emp_score > fi->fi_emp_limit))
			return 1;
		else
			return 0;

	if (fi->fi_phl_limit)
		if (!(art->art_flags & ART_CONTROL) &&
		     (art->art_phl_score > fi->fi_phl_limit))
			     return 1;
		else
			return 0;

	return 1;
}

filter_result_t
filter_article(art, client, fl, fname)
	article_t	*art;
	filter_list_t	*fl;
	char		**fname;
	char const	*client;
{
filter_list_entry_t	*fle;

	if (!(art->art_flags & ART_FILTERED)) {
		SIMPLEQ_FOREACH(fle, &filter_list, fle_list) {
			if (!(fle->fle_filter->fi_flags & FILTER_USED))
				continue;
			if (filter_match(art, fle->fle_filter))
				bs_set(art->art_filters, fle->fle_filter->fi_bit);
		}

		art->art_flags |= ART_FILTERED;
	}

	SIMPLEQ_FOREACH(fle, fl, fle_list) {
	filter_t	*fi = fle->fle_filter;
		if (!bs_test(art->art_filters, fi->fi_bit))
			continue;

		switch (fi->fi_flags & FILTER_ACT_MASK) {
		case FILTER_ACT_DUNNO:
			++fle->fle_filter->fi_num_dunno;
			break;

		case FILTER_ACT_PERMIT:
			++fle->fle_filter->fi_num_permit;
			return FILTER_RESULT_PERMIT;

		case FILTER_ACT_DENY:
			if (fname) {
				if (fi->fi_flags & FILTER_LOG_REJECTED)
					nts_log("%s: article %s rejected by filter/%s",
						client, art->art_msgid, fi->fi_name);
				*fname = fi->fi_name;
			}

			++fle->fle_filter->fi_num_deny;
			return FILTER_RESULT_DENY;

		default:
			abort();
		}
	}

	return FILTER_RESULT_PERMIT;
}

void
filter_shutdown()
{
	emp_shutdown();
}
