/* RT/NTS -- a lightweight, high performance news transit server. */
/* 
 * Copyright (c) 2011-2013 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */

#ifndef	NTS_LOG_H
#define	NTS_LOG_H

#include	<syslog.h>
#include	<stdarg.h>

#include	"article.h"
#include	"server.h"
#include	"nts.h"
#include	"msg.h"

int	log_init(void);
int	log_run(void);
void	log_shutdown(void);

void	nts_log(int sev, char const *fmt, ...) attr_printf(2, 3);
void	nts_vlog(int sev, char const *fmt, va_list ap);

void	nts_logm(msg_t fac[], int msg, ...);
void	nts_vlogm(msg_t fac[], int msg, va_list ap);


void	log_article(char const *msgid, char const *path, server_t *, char status, 
		char const *reason, ...) attr_printf(5, 6);

#endif	/* !NTS_LOG_H */
