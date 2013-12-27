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
#include	<sys/stat.h>

#include	<string.h>
#include	<stdio.h>
#include	<errno.h>
#include	<stdarg.h>
#include	<stdlib.h>
#include	<time.h>

#include	"log.h"
#include	"config.h"
#include	"nts.h"
#include	"rfile.h"

static enum {
	L_STDOUT,
	L_FILE,
	L_SYSLOG
} log_target = L_STDOUT;

static rfile_t	*logfile;
static char	*logfile_name;
static rfile_t	*incoming_log;
static char	*incoming_log_name;
static rfile_t	*path_log;
static char	*path_log_name;

static void	logging_set_target(conf_stanza_t *, conf_option_t *, void *, void *);

static config_schema_opt_t logging_opts[] = {
	{ "target",		OPT_TYPE_STRING,	logging_set_target },
	{ "incoming-log",	OPT_TYPE_STRING,	config_simple_string,
							&incoming_log_name },
	{ "path-log",		OPT_TYPE_STRING,	config_simple_string,	
							&path_log_name },
	{ }
};

static config_schema_stanza_t logging_stanza = {
	"logging", 0, logging_opts, NULL, NULL
};

int
log_init(void)
{
	config_add_stanza(&logging_stanza);
	return 0;
}

static void
logging_set_target(stz, opt, udata, arg)
	conf_stanza_t	*stz;
	conf_option_t	*opt;
	void		*udata, *arg;
{
char const	*target = opt->co_value->cv_string;
	if (strcmp(target, "syslog") == 0)
		log_target = L_SYSLOG;
	else if (strcmp(target, "stdout") == 0)
		log_target = L_STDOUT;
	else {
		log_target = L_FILE;
		logfile_name = xstrdup(target);
	}
}

int
log_run(void)
{
	switch (log_target) {
	case L_STDOUT:
		logfile = NULL;
		break;

	case L_SYSLOG:
		openlog("RT/NTS", LOG_PID, LOG_NEWS);
		break;

	case L_FILE:
		if ((logfile = rfopen(logfile_name, "a")) == NULL)
			panic("log: %s: cannot open: %s",
					logfile_name, strerror(errno));
		break;
	}

	if (incoming_log_name) {
		if ((incoming_log = rfopen(incoming_log_name, "a")) == NULL) {
			nts_log(LOG_CRIT, "cannot open incoming log %s: %s",
					incoming_log_name, strerror(errno));
			return -1;
		}
	}

	if (path_log_name) {
		if ((path_log = rfopen(path_log_name, "a")) == NULL) {
			nts_log(LOG_CRIT, "cannot open path log %s: %s",
					path_log_name, strerror(errno));
			return -1;
		}
	}

	return 0;
}

void
nts_log(int sev, char const *fmt, ...)
{
va_list	ap;
	va_start(ap, fmt);
	nts_vlog(sev, fmt, ap);
	va_end(ap);
}

void
nts_logm(msg_t fac[], int msg, ...)
{
va_list	ap;
	va_start(ap, msg);
	nts_vlogm(fac, msg, ap);
	va_end(ap);
}

void
nts_vlog(sev, fmt, ap)
	char const	*fmt;
	va_list		 ap;
{
char	 buf[8192];
char	*r = buf;
int	 len;

	len = vsnprintf(buf, sizeof(buf), fmt, ap);
	if ((unsigned int) len >= sizeof (buf)) {
		r = xmalloc(len + 1);
		vsnprintf(r, len + 1, fmt, ap);
	}

	switch (log_target) {
	case L_SYSLOG:
		syslog(sev, "%s", r);
		break;

	case L_STDOUT:
	case L_FILE:
	{
	time_t		 now;
	struct tm	*tm;
	char		 tbuf[128];
	char const	*sevs;

		time(&now);
		tm = localtime(&now);
		strftime(tbuf, sizeof(tbuf), "%b %d %H:%M:%S", tm);

		switch (sev) {
		case LOG_EMERG:		sevs = " EMERG:    "; break;
		case LOG_ALERT:		sevs = " ALERT:    "; break;
		case LOG_CRIT:		sevs = " CRITICAL: "; break;
		case LOG_ERR:		sevs = " ERROR:    "; break;
		case LOG_WARNING:	sevs = " WARNING:  "; break;
		case LOG_NOTICE:	sevs = " NOTICE:   "; break;
		case LOG_INFO:		sevs = " INFO:     "; break;
		case LOG_DEBUG:		sevs = " DEBUG:    "; break;
		}

		if (logfile) {
			rfcheck(logfile);
			rfprintf(logfile, "%s%s%s\n", tbuf, sevs, r);
			rfflush(logfile);
		} else {
			printf("%s%s%s\n", tbuf, sevs, r);
		}
		break;
	}
	}

	if (r != buf)
		free(r);
}

void
nts_vlogm(fac, msg, ap)
	msg_t	fac[];
	va_list	ap;
{
char	 buf[8192];
char	*r = buf;
int	 len;
int	 sev;

	len = vsnprintf(buf, sizeof(buf), fac[msg].m_text, ap);
	if ((unsigned int) len >= sizeof (buf)) {
		r = xmalloc(len + 1);
		vsnprintf(r, len + 1, fac[msg].m_text, ap);
	}

	switch (log_target) {
	case L_SYSLOG:
		switch (fac[msg].m_sev) {
		case 'F':
		case 'E':
			sev = LOG_ERR;
			break;
		case 'W':
			sev = LOG_WARNING;
			break;
		case 'I':
			sev = LOG_INFO;
			break;
		}

		syslog(sev, "%%%s-%c-%s, %s\n", 
		       fac[msg].m_subsys, fac[msg].m_sev,
		       fac[msg].m_code, r);
		break;

	case L_STDOUT:
	case L_FILE:
	{
	time_t		 now;
	struct tm	*tm;
	char		 tbuf[128];

		time(&now);
		tm = localtime(&now);
		strftime(tbuf, sizeof(tbuf), "%b %d %H:%M:%S", tm);

		if (logfile) {
			rfcheck(logfile);
			rfprintf(logfile, "%s %%%s-%c-%s, %s\n", tbuf, 
				 fac[msg].m_subsys, fac[msg].m_sev,
				 fac[msg].m_code, r);
			rfflush(logfile);
		} else {
			printf("%s %%%s-%c-%s, %s\n", tbuf, 
			       fac[msg].m_subsys, fac[msg].m_sev,
			       fac[msg].m_code, r);
		}
		break;
	}
	}

	if (r != buf)
		free(r);
}
void
log_article(char const *msgid, char const *path, server_t *server, char status, char const *reason, ...)
{
char		 rbuf[128] = {};
time_t		 now;
struct tm	*tm;
char		 tbuf[128];

	time(&now);
	tm = localtime(&now);
	strftime(tbuf, sizeof(tbuf), "%b %d %H:%M:%S", tm);

	if (reason) {
	va_list	ap;
		va_start(ap, reason);
		vsnprintf(rbuf, sizeof(rbuf), reason, ap);
		va_end(ap);
	}

	if (incoming_log) {
		rfcheck(incoming_log);
		rfprintf(incoming_log, "%s %s %c %s %s\n",
				tbuf, server->se_name, status,
				msgid, rbuf);
	}

	if (path && path_log) {
		rfcheck(path_log);
		rfprintf(path_log, "Path: %s\n", path);
	}
}	

void
log_shutdown()
{
	if (incoming_log)
		rfclose(incoming_log);
	if (logfile)
		rfclose(logfile);
	if (path_log)
		rfclose(path_log);
}
