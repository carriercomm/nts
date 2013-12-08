/* RT/NTS -- a lightweight, high performance news transit server. */
/* 
 * Copyright (c) 2011 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */
/* $Header: /cvsroot/nts/lexer.l,v 1.4 2012/01/01 01:27:02 river Exp $ */

%{

#include	<inttypes.h>
#include	<stdlib.h>
#include	<string.h>

#include	"config.h"
#include	"y.tab.h"

static int commlevel;

%}

%x COMMENT
%x HASHCOMMENT

%%

weeks?				{ return WEEK; }
days?				{ return DAY; }
hours?				{ return HOUR; }
minutes?			{ return MINUTE; }
seconds?			{ return SECOND; }
yes|true			{ return YES; }
no|false			{ return NO; }
(bytes?|B)			{ return B; }
(kilobytes?|KB)			{ return KB; }
(megabytes?|MB)			{ return MB; }
(gigabytes?|GB)			{ return GB; }
(terabytes?|TB)			{ return TB; }
\/\*				{ BEGIN(COMMENT); commlevel = 1;}
<COMMENT>\/\*			{ commlevel++;}
<COMMENT>\*\/			{ if (--commlevel == 0) { BEGIN(0); } }
<COMMENT>.			;
<COMMENT>\n			config_lineno++;
#                               { BEGIN(HASHCOMMENT); }
<HASHCOMMENT>.                  ;
<HASHCOMMENT>\n                 { BEGIN(0); config_lineno++; }
[a-zA-Z][a-zA-Z0-9\.\\_@-]*	{ yylval.string = strdup(yytext); return WORD; }
[0-9]+				{ yylval.integer = atoi(yytext); return NUMBER; }
\"[^"]*\"			{ yylval.string = strdup(yytext + 1);
				  yylval.string[strlen(yylval.string) - 1] = '\0';
				  return STRING;
				}
[ \t]+				;
\n				config_lineno++;
.				{ return yytext[0]; }

