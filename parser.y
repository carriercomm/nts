/* RT/NTS -- a lightweight, high performance news transit server. */
/* 
 * Copyright (c) 2011 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */
/* $Header: /cvsroot/nts/parser.y,v 1.4 2012/01/01 01:27:02 river Exp $ */

%{

#include	<stdio.h>
#include	<inttypes.h>

#include	"config.h"
#include	"nts.h"

int yylex(void);

%}

%union {
	int64_t		 integer;
	char		*string;
	conf_val_t	*cval;
	conf_option_t	*option;
	conf_stanza_t	*stanza;
};

%token WORD NUMBER STRING
%token WEEK DAY HOUR MINUTE SECOND
%token KB MB GB TB B
%token YES NO

%type<integer> NUMBER duration quantity boolean
%type<string> WORD STRING
%type<cval> value value_list
%type<stanza> stanza config
%type<string> maybe_title
%type<option> maybe_opts opts opt

%start config

%%

config:		  stanza config	{ config_parser_add_stanza($1); }
      		|
		;

stanza:
	      	  WORD maybe_title maybe_opts semicolon
		{ $$ = xcalloc(1, sizeof(*$$));
		  $$->cs_name = $1;
		  $$->cs_title = $2;
		  $$->cs_options = $3;
		  $$->cs_lineno = config_lineno;
		  $$->cs_file = config_curfile;
		}
		;

maybe_title:	  STRING	{ $$ = $1; }
	   	|		{ $$ = NULL; }
		;

maybe_opts:	  '{' opts '}'	{ $$ = $2; }
	  	|		{ $$ = NULL; }
		;

opts:		  opts opt
    		{ $$ = $2; $2->co_next = $1; }
		| { $$ = NULL; }
    		;

opt:
   		  WORD colon value_list semicolon
		{ $$ = xcalloc(1, sizeof(*$$));
		  $$->co_name = $1;
		  $$->co_value = $3;
		  $$->co_lineno = config_lineno;
		  $$->co_file = config_curfile;
		}
		;

semicolon:	  ';'
	 	/*| { yyerror("missing semicolon at end of previous statement"); }*/
		;

colon:		  ':'
/*     		| { yyerror("expected colon after option name"); }*/
		;

value_list:
	  	  value_list ',' value	{
			conf_val_t	*v;
			v = $$ = $1;
			while (v->cv_next)
				v = v->cv_next;
			v->cv_next = $3;
		 }
		| value 		{ $$ = $1; }
		;

value:		  WORD		{ $$ = cv_new_string($1); }
     		| STRING	{ $$ = cv_new_string($1); }
		| NUMBER	{ $$ = cv_new_number($1); }
		| quantity	{ $$ = cv_new_quantity($1); }
		| duration	{ $$ = cv_new_duration($1); }
		| boolean	{ $$ = cv_new_boolean($1); }
		| 		{ yyerror("invalid value"); }
		;

duration:
		  NUMBER WEEK	{ $$ = $1 * 60 * 60 * 24 * 7; }
		| NUMBER DAY	{ $$ = $1 * 60 * 60 * 24; }
		| NUMBER HOUR	{ $$ = $1 * 60 * 60; }
		| NUMBER MINUTE	{ $$ = $1 * 60; }
		| NUMBER SECOND	{ $$ = $1; }
		;

quantity:
		  NUMBER B	{ $$ = $1; }
		| NUMBER KB	{ $$ = $1 * 1024; }
		| NUMBER MB	{ $$ = $1 * 1024 * 1024; }
		| NUMBER GB	{ $$ = $1 * 1024 * 1024 * 1024; }
		| NUMBER TB	{ $$ = $1 * 1024 * 1024 * 1024 * 1024; }
		;

boolean:
       		  YES		{ $$ = 1; }
		| NO		{ $$ = 0; }
		;
