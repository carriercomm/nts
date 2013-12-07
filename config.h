/* RT/NTS -- a lightweight, high performance news transit server. */
/* 
 * Copyright (c) 2011 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */
/* $Header: /cvsroot/nts/config.h,v 1.4 2011/12/30 18:08:57 river Exp $ */

#ifndef NTS_CONFIG_H
#define NTS_CONFIG_H

#include	<inttypes.h>

#include	"nts.h"

#define	CONF_NAME	SYSCONFDIR "/nts.conf"
int	config_load(char const *fname);

/* An item in the configuration. */
typedef enum conf_val_type {
	CV_STRING,
	CV_NUMBER,
	CV_QUANTITY,
	CV_DURATION,
	CV_BOOLEAN
} conf_val_type_t;

typedef struct conf_val {
	conf_val_type_t	cv_type;
	union {
		int64_t	 cv_int;
		char	*cv_char;
	} cv_val_u;
#define cv_number cv_val_u.cv_int
#define cv_quantity cv_val_u.cv_int
#define cv_duration cv_val_u.cv_int
#define cv_boolean cv_val_u.cv_int
#define cv_string cv_val_u.cv_char

	struct conf_val	*cv_next;
} conf_val_t;

typedef struct conf_option {
	char			*co_name;
	conf_val_t		*co_value;
	int			 co_lineno;
	char const		*co_file;
	struct conf_option	*co_next;
} conf_option_t;

/* A configuration block */
typedef struct conf_stanza {
	char			*cs_name;
	char			*cs_title;
	conf_option_t		*cs_options;
	int			 cs_lineno;
	char const		*cs_file;
	struct conf_stanza	*cs_next;
} conf_stanza_t;

/* The actual config, an slist of config_stanzas */
extern conf_stanza_t	*config;

conf_stanza_t	*config_find_stanza(char const *name, char const *title);
conf_option_t	*config_find_option(conf_stanza_t *, char const *name);

/* Functions used by the parser */
conf_val_t	*cv_new_number(int64_t);
conf_val_t	*cv_new_quantity(int64_t);
conf_val_t	*cv_new_duration(int64_t);
conf_val_t	*cv_new_boolean(int64_t);
conf_val_t	*cv_new_string(char const *);

void		 config_parser_add_stanza(conf_stanza_t *);

extern int		 config_lineno;
extern char const	*config_curfile;

void		config_error(char const *, ...) attr_printf(1, 2);
void		yyerror(char const *);

/* Config schema handling */

#define SC_MANY			0x1
#define SC_DUPTITLE		0x2
#define SC_REQTITLE		0x4

#define	OPT_MANY		0x01
#define OPT_LIST		0x02
#define OPT_TYPE_STRING		0x04
#define OPT_TYPE_NUMBER		0x08
#define OPT_TYPE_QUANTITY	0x10
#define OPT_TYPE_DURATION	0x20
#define OPT_TYPE_BOOLEAN	0x40

typedef void * (*config_stanza_start_handler) (conf_stanza_t *, void *);
typedef void (*config_stanza_end_handler) (conf_stanza_t *, void *);
typedef void (*config_option_handler) (conf_stanza_t *, conf_option_t *, void *, void *);

typedef struct config_schema_opt {
	char const			*opt_name;
	int				 opt_flags;
	config_option_handler		 opt_handler;
	void				*opt_arg;
} config_schema_opt_t;

void	config_simple_string(conf_stanza_t *, conf_option_t *, void *, void *);
void	config_simple_boolean(conf_stanza_t *, conf_option_t *, void *, void *);
void	config_simple_number(conf_stanza_t *, conf_option_t *, void *, void *);
void	config_simple_quantity(conf_stanza_t *, conf_option_t *, void *, void *);
void	config_simple_duration(conf_stanza_t *, conf_option_t *, void *, void *);

typedef struct config_schema_stanza {
	char const			*sc_stanza;
	int				 sc_flags;
	config_schema_opt_t		*sc_opts;
	config_stanza_start_handler	 sc_start;
	config_stanza_end_handler	 sc_end;
} config_schema_stanza_t;

int	config_add_stanza(config_schema_stanza_t *);

#endif	/* !NTS_CONFIG_H */
