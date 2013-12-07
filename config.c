/* RT/NTS -- a lightweight, high performance news transit server. */
/* 
 * Copyright (c) 2011 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */
/* $Header: /cvsroot/nts/config.c,v 1.4 2011/12/30 18:08:57 river Exp $ */

#include	<stdlib.h>
#include	<string.h>
#include	<stdio.h>
#include	<setjmp.h>
#include	<errno.h>
#include	<assert.h>

#include	"config.h"
#include	"nts.h"
#include	"log.h"

static int conf_handle_stanza(conf_stanza_t *stz);

static config_schema_stanza_t **stanzas;
static int nstanzas;

int		 config_lineno;
conf_stanza_t	*config;

conf_val_t *
cv_new_number(n)
	int64_t	n;
{
conf_val_t	*v = xcalloc(1, sizeof(*v));
	v->cv_type = CV_NUMBER;
	v->cv_number = n;
	return v;
}

conf_val_t *
cv_new_boolean(n)
	int64_t	n;
{
conf_val_t	*v = xcalloc(1, sizeof(*v));
	v->cv_type = CV_BOOLEAN;
	v->cv_number = n;
	return v;
}

conf_val_t *
cv_new_quantity(n)
	int64_t	n;
{
conf_val_t	*v = xcalloc(1, sizeof(*v));
	v->cv_type = CV_QUANTITY;
	v->cv_quantity = n;
	return v;
}

conf_val_t *
cv_new_duration(n)
	int64_t	n;
{
conf_val_t	*v = xcalloc(1, sizeof(*v));
	v->cv_type = CV_DURATION;
	v->cv_duration = n;
	return v;
}

conf_val_t *
cv_new_string(s)
	char const	*s;
{
conf_val_t	*v = xcalloc(1, sizeof(*v));
	v->cv_type = CV_STRING;
	v->cv_string = xstrdup(s);
	return v;
}


int
yywrap()
{
	return 1;
}

static jmp_buf errjmp;
char const *config_curfile;

int
config_load(fname)
	char const	*fname;
{
extern FILE	*yyin;
extern int	 yyparse(void);
conf_stanza_t	*stanza;

	if ((yyin = fopen(fname, "r")) == NULL) {
		nts_log(LOG_CRIT, "cannot open configuration file \"%s\": %s",
				fname, strerror(errno));
		return -1;
	}

	config_curfile = fname;
	config_lineno = 1;

	if (setjmp(errjmp))
		return 1;

	yyparse();

	for (stanza = config; stanza; stanza = stanza->cs_next) {
		if (conf_handle_stanza(stanza) == -1)
			return -1;
	}

	return 0;
}

config_schema_stanza_t *
config_find_schema_stanza(name)
	char const	*name;
{
int			 n;
	for (n = 0; n < nstanzas; n++) {
		if (strcmp(name, stanzas[n]->sc_stanza) == 0)
			return stanzas[n];
	}

	return NULL;
}

config_schema_opt_t *
config_find_schema_opt(sstz, name)
	config_schema_stanza_t	*sstz;
	char const		*name;
{
config_schema_opt_t	*opt;
	for (opt = sstz->sc_opts; opt->opt_name; opt++) {
		if (strcmp(opt->opt_name, name) == 0)
			return opt;
	}

	return NULL;
}

int
conf_handle_stanza(stz)
	conf_stanza_t	*stz;
{
config_schema_stanza_t	*sstz;
conf_option_t		*opt;
void			*udata = NULL;

	if ((sstz = config_find_schema_stanza(stz->cs_name)) == NULL) {
		nts_log(LOG_ERR, "\"%s\", line %d: unknown stanza \"%s\"",
				stz->cs_file, stz->cs_lineno, stz->cs_name);
		return -1;
	}

	if (sstz->sc_start)
		udata = sstz->sc_start(stz, NULL);

	for (opt = stz->cs_options; opt; opt = opt->co_next) {
	config_schema_opt_t	*sopt;
		if ((sopt = config_find_schema_opt(sstz, opt->co_name)) == NULL) {
			nts_log(LOG_ERR, "\"%s\", line %d: unknown option \"%s::%s\"",
					opt->co_file, opt->co_lineno,
					stz->cs_name, opt->co_name);
			return -1;
		}
		sopt->opt_handler(stz, opt, udata, sopt->opt_arg);
	}

	if (sstz->sc_end)
		sstz->sc_end(stz, udata);
	return 0;
}

void
yyerror(err)
	char const	*err;
{
	nts_log(LOG_ERR, "\"%s\", line %d: %s", config_curfile, config_lineno, err);
	longjmp(errjmp, 1);
}

void
config_parser_add_stanza(st)
	conf_stanza_t	*st;
{
	st->cs_next = config;
	config = st;
}

conf_stanza_t *
config_find_stanza(name, title)
	char const	*name, *title;
{
conf_stanza_t	*l;
	for (l = config; l; l = l->cs_next) {
		if (strcmp(name, l->cs_name))
			continue;
		if (title && strcmp(title, l->cs_title))
			continue;
		return l;
	}
	return NULL;
}

conf_option_t *
config_find_option(stz, name)
	conf_stanza_t	*stz;
	char const	*name;
{
conf_option_t	*l;
	for (l = stz->cs_options; l; l = l->co_next) {
		if (strcmp(name, l->co_name))
			continue;
		return l;
	}
	return NULL;
}

int
config_add_stanza(sstz)
	config_schema_stanza_t	*sstz;
{
	stanzas = xrealloc(stanzas, sizeof(*stanzas) * (nstanzas + 1));
	stanzas[nstanzas] = sstz;
	nstanzas++;
	return 0;
}

void
config_simple_string(stz, opt, udata, arg)
	conf_stanza_t	*stz;
	conf_option_t	*opt;
	void		*udata, *arg;
{
	assert(opt->co_value->cv_type == CV_STRING);
	*(char **)arg = xstrdup(opt->co_value->cv_string);
}

void
config_simple_boolean(stz, opt, udata, arg)
	conf_stanza_t	*stz;
	conf_option_t	*opt;
	void		*udata, *arg;
{
	assert(opt->co_value->cv_type == CV_BOOLEAN);
	*(int *)arg = opt->co_value->cv_boolean;
}

void
config_simple_number(stz, opt, udata, arg)
	conf_stanza_t	*stz;
	conf_option_t	*opt;
	void		*udata, *arg;
{
	assert(opt->co_value->cv_type == CV_NUMBER);
	*(int64_t *)arg = opt->co_value->cv_number;
}

void
config_simple_duration(stz, opt, udata, arg)
	conf_stanza_t	*stz;
	conf_option_t	*opt;
	void		*udata, *arg;
{
	assert(opt->co_value->cv_type == CV_DURATION);
	*(uint64_t *)arg = opt->co_value->cv_duration;
}

void
config_simple_quantity(stz, opt, udata, arg)
	conf_stanza_t	*stz;
	conf_option_t	*opt;
	void		*udata, *arg;
{
	assert(opt->co_value->cv_type == CV_QUANTITY);
	*(uint64_t *)arg = opt->co_value->cv_quantity;
}
