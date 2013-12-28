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
#include	<sys/un.h>
#include	<sys/resource.h>

#include	<stdio.h>
#include	<string.h>
#include	<stdlib.h>
#include	<signal.h>
#include	<errno.h>
#include	<pwd.h>
#include	<grp.h>
#include	<fcntl.h>
#include	<ctype.h>

#include	"setup.h"

#ifdef HAVE_OPENSSL
# include	<openssl/ssl.h>
# include	<openssl/crypto.h>
#endif

#include	"config.h"
#include	"server.h"
#include	"client.h"
#include	"spool.h"
#include	"log.h"
#include	"database.h"
#include	"history.h"
#include	"filter.h"
#include	"nts.h"
#include	"feeder.h"
#include	"charq.h"
#include	"auth.h"
#include	"article.h"
#include	"ctl.h"

#include	"ntsmsg.h"
#include	"dbmsg.h"
#include	"clientmsg.h"
#include	"authmsg.h"
#include	"dbmsg.h"
#include	"configmsg.h"
#include	"spoolmsg.h"
#include	"historymsg.h"
#include	"logmsg.h"

static void	*server_stanza_start(conf_stanza_t *, void *);
static void	 server_set_common_paths(conf_stanza_t *, conf_option_t *, void *, void *);

uint64_t	 max_article_size = 1024 * 1024;
uint64_t	 history_remember = 60 * 60 * 24 * 10; /* 10 days */
int		 defer_pending = 1;
char		*contact_address = "nowhere@example.com";
char		*pathhost;
path_list_t	 common_paths;
char		*pid_file;
char		*control_path;
static char	*runas_user, *runas_group;
char		*reader_user, *reader_group;
int		 log_incoming_connections = 1;
char		*reader_handler;
static char	*chroot_dir;
uint64_t	 stats_interval = 30;
uint64_t	 worker_threads = 0;
uv_loop_t	*loop;

#ifndef	NDEBUG
int		 nts_debug_flags;
#endif

static void	 usage(char const *);
static void	 explain_msg(char const *);
static void	 explain_msg_fac(msg_t[], char const *);

static config_schema_opt_t server_opts[] = {
	{ "contact",		OPT_TYPE_STRING,
				config_simple_string, &contact_address },
	{ "common-paths",	OPT_TYPE_STRING | OPT_LIST,
				server_set_common_paths },
	{ "max-size",		OPT_TYPE_QUANTITY,
				config_simple_quantity, &max_article_size },
	{ "defer-pending",	OPT_TYPE_BOOLEAN,
				config_simple_boolean, &defer_pending },
	{ "history-remember",	OPT_TYPE_DURATION,
				config_simple_duration, &history_remember },
	{ "pid-file",		OPT_TYPE_STRING,
				config_simple_string, &pid_file },
	{ "control-socket",	OPT_TYPE_STRING,
				config_simple_string, &control_path },
	{ "user",		OPT_TYPE_STRING,
				config_simple_string, &runas_user },
	{ "group",		OPT_TYPE_STRING,
				config_simple_string, &runas_group },
	{ "log-incoming-connections", OPT_TYPE_BOOLEAN,
				config_simple_boolean, &log_incoming_connections },
	{ "reader-handler",	OPT_TYPE_STRING,
				config_simple_string, &reader_handler },
	{ "reader-user",	OPT_TYPE_STRING,
				config_simple_string, &reader_user },
	{ "reader-group",	OPT_TYPE_STRING,
				config_simple_string, &reader_group },
	{ "chroot",		OPT_TYPE_STRING,
				config_simple_string, &chroot_dir },
	{ "stats-interval",	OPT_TYPE_NUMBER,
				config_simple_number, &stats_interval },
	{ "worker-threads",	OPT_TYPE_NUMBER,
				config_simple_number, &worker_threads },
	{}
};

static config_schema_stanza_t server_stanza = {
	"server", SC_REQTITLE, server_opts, server_stanza_start
};

static void
usage(pname)
	char const	*pname;
{
	fprintf(stderr,
"usage: %1$s [-Vny] [-x <command>] [-c <conffile>] [-p <pidfile>]\n"
"usage: %1$s -M <msgid>\n"
"\n"
"    -h                 print this message\n"
"    -V                 print version and exit\n"
"    -n                 run in the foreground\n"
"    -x <command>       send a control command to a running NTS\n"
"    -p <pidfile>       specify the pid file location\n"
"    -c <conffile>      specify the configuration file\n"
"    -y                 check spool files and exit\n"
"\n"
"    -M <msgid>         print detailed explanation for given message\n"
, pname);
}

int
main(argc, argv)
	char	**argv;
{
char const	*conf_name = CONF_NAME;
int		 c;
FILE		*pidf = NULL;
int		 nflag = 0, yflag = 0;
char		*control_command = NULL;
struct group	*grp = NULL;
struct passwd	*pwd = NULL;
int		 devnull;
char		*s;

	/* Initialise the rng before we chroot */
	arc4random();

	while ((c = getopt(argc, argv, "M:Vc:p:nx:yD:")) != -1) {
		switch (c) {
			case 'V':
				printf("RT/NTS %s\n", PACKAGE_VERSION);
				printf("\t%s\n", db_version(NULL, NULL, NULL));
				printf("\tlibuv %s\n", uv_version_string());
#ifdef HAVE_OPENSSL
				printf("\t%s\n", SSLeay_version(SSLEAY_VERSION));
#endif
				return 0;

			case 'c':
				conf_name = optarg;
				break;

			case 'p':
				pid_file = optarg;
				break;

			case 'n':
				nflag++;
				break;

			case 'x':
				control_command = optarg;
				break;

			case 'h':
				usage(argv[0]);
				return 0;

			case 'y':
				++yflag;
				break;

			case 'M':
				explain_msg(optarg);
				return 0;

			case 'D':
#ifndef	NDEBUG
				while (s = next_any(&optarg, ",")) {
					if (strcmp(s, "cio") == 0)
						nts_debug_flags |= DEBUG_CIO;
					else {
						fprintf(stderr, "%s: unknown debug flag: %s\n",
							argv[0], s);
						return 1;
					}
				}
				break;
#else	/* NDEBUG */
				fprintf(stderr, "%s: debugging code disabled at build time\n",
					argv[0]);
				return 1;
#endif	/* NDEBUG */

			default:
				usage(argv[0]);
				return 1;
		}
	}

	signal(SIGPIPE, SIG_IGN);

	if ((loop = uv_loop_new()) == NULL)
		panic("nts: failed to create uv_loop: %s", strerror(errno));

	if (db_init() == -1 ||
	    history_init() == -1 ||
	    server_init() == -1 ||
	    client_init() == -1 ||
	    spool_init() == -1 ||
	    log_init() == -1 ||
	    auth_init() == -1 ||
	    feeder_init() == -1 ||
	    filter_init() == -1)
		panic("nts: failed to initialise (see above messages)");

	config_add_stanza(&server_stanza);

	if (config_load(conf_name) == -1)
		panic("cannot load configuration");

	if (control_command)
		return execute_control_command(control_command);

	if (yflag)
		return spool_check();

	if (runas_group) {
		if ((grp = getgrnam(runas_group)) == NULL)
			panic("unknown group: %s", runas_group);
	}

	if (runas_user) {
		if ((pwd = getpwnam(runas_user)) == NULL)
			panic("unknown user: %s", runas_user);
	}

	if (ctl_init(control_path) == -1)
			panic("nts: cannot create control socket");

	if (!nflag && (devnull = open("/dev/null", O_RDWR, 0)) == -1)
		panic("/dev/null: %s", strerror(errno));

	if (chroot_dir) {
		if (chroot(chroot_dir) == -1)
			panic("\"%s\": chroot: %s", chroot_dir,
					strerror(errno));
		chdir("/");
	}

	if (pid_file) {
		if (pidf = fopen(pid_file, "r")) {
		char	 pidline[64];
			if (fgets(pidline, sizeof(pidline), pidf)) {
				if (atoi(pidline) && kill(atoi(pidline), 0) == 0) {
					nts_logm(NTS_fac, M_NTS_ALDYRUNNING, atoi(pidline));
					return 1;
				}
			}

			fclose(pidf);
		}

		if ((pidf = fopen(pid_file, "w")) == NULL)
			panic("%s: %s", pid_file, strerror(errno));
	}

	/*
	 * Put log_run last, so messages continue to go to stderr until
	 * we're done starting.  client_run goes first, because we need
	 * to set up listen sockets because switching uid.
	 */

	if (client_run() == -1)
		panic("nts: failed to start (see above messages)");

	if (grp) {
		if (setgid(grp->gr_gid) == -1)
			panic("cannot setgid to %s (%d): %s",
				runas_group, grp->gr_gid, strerror(errno));
	}

	if (pwd) {
		if (!runas_group)
			if (setgid(pwd->pw_gid) == -1)
				panic("cannot setgid to %d: %s",
					pwd->pw_gid, strerror(errno));

		if (setuid(pwd->pw_uid) == -1)
			panic("cannot setuid to %s (%d): %s",
				runas_user, pwd->pw_uid, strerror(errno));
	}

	if (db_run() == -1 ||
	    history_run() == -1 ||
	    auth_run() == -1 ||
	    spool_run() == -1 ||
	    server_run() == -1 ||
	    filter_run() == -1 ||
	    feeder_run() == -1 ||
	    log_run() == -1)
		panic("nts: failed to start (see above messages)");

	if (!nflag) {
		switch (fork()) {
		case -1:
			panic("fork: %s", strerror(errno));
			return 1;
		case 0:
			break;
		default:
			_exit(0);
		}

		if (setsid() == -1)
			panic("nts: setsid: %s", strerror(errno));

		dup2(devnull, STDIN_FILENO);
		dup2(devnull, STDOUT_FILENO);
		dup2(devnull, STDERR_FILENO);
		close(devnull);
	}

	if (pidf) {
		fprintf(pidf, "%d\n", (int) getpid());
		fclose(pidf);
	}

	nts_logm(NTS_fac, M_NTS_RUNNING, PACKAGE_VERSION, pathhost);

	uv_run(loop, UV_RUN_DEFAULT);
	return 0;
}

static void *
server_stanza_start(stz, udata)
	conf_stanza_t	*stz;
	void		*udata;
{
	SIMPLEQ_INIT(&common_paths);

	if (!stz->cs_title)
		panic("server name not specified");
	pathhost = xstrdup(stz->cs_title);
	return NULL;
}

static void
server_set_common_paths(stz, opt, udata, arg)
	conf_stanza_t	*stz;
	conf_option_t	*opt;
	void		*udata, *arg;
{
conf_val_t	*val;

	for (val = opt->co_value; val; val = val->cv_next) {
	path_ent_t	*pe = xcalloc(1, sizeof(*pe));
		pe->pe_path = xstrdup(val->cv_string);
		SIMPLEQ_INSERT_TAIL(&common_paths, pe, pe_list);
	}
}

void
vpanic(fmt, ap)
	char const	*fmt;
	va_list		 ap;
{
	nts_vlog(fmt, ap);
	log_shutdown();
	abort();
	exit(1);
}

void
panic(char const *fmt, ...)
{
va_list	ap;
	va_start(ap, fmt);
	vpanic(fmt, ap);
}

void *
xmalloc(n)
	size_t	n;
{
void	*ret;
	if ((ret = malloc(n)) == NULL && n)
		panic("out of memory");
	return ret;
}

void *
xcalloc(n, s)
	size_t	n, s;
{
void	*ret;
	if ((ret = calloc(n, s)) == NULL && n && s)
		panic("out of memory");
	return ret;
}

void *
xrealloc(p, s)
	void	*p;
	size_t	 s;
{
void	*ret;
	if ((ret = realloc(p, s)) == NULL && s)
		panic("out of memory");
	return ret;
}

char *
xstrdup(s)
	char const	*s;
{
char	*ret;
	if ((ret = strdup(s)) == NULL)
		panic("out of memory");
	return ret;
}

char *
xstrndup(s, n)
	char const	*s;
	size_t		 n;
{
char	*ret;
	if ((ret = strndup(s, n)) == NULL)
		panic("out of memory");
	return ret;
}

void
nts_shutdown(reason)
	char const	*reason;
{
	nts_logm(NTS_fac, M_NTS_SHUTDWN, reason);
	spool_shutdown();
	server_shutdown();
	filter_shutdown();
	history_shutdown();
	db_shutdown();

	if (pid_file && unlink(pid_file) == -1)
		nts_logm(NTS_fac, M_NTS_RMPID, pid_file, strerror(errno));

	log_shutdown();
	exit(0);
}

void
pack(unsigned char *buf, char const *fmt, ...)
{
va_list		 ap;
char const	*s;
size_t		 len;
uint32_t	 u32;
uint64_t	 u64;
uint8_t		 u8;

	va_start(ap, fmt);

	while (*fmt) {
		switch (*fmt++) {
		case 'b':
			u8 = va_arg(ap, int);
			int8put(buf, u8);
			buf += 1;
			break;

		case 'u':
		case 'i':
			u32 = va_arg(ap, uint32_t);
			int32put(buf, u32);
			buf += 4;
			break;

		case 'U':
		case 'I':
			u64 = va_arg(ap, uint64_t);
			int64put(buf, u64);
			buf += 8;
			break;

		case 'f':
			u64 = (uint64_t) va_arg(ap, double) * 1000;
			int64put(buf, u64);
			buf += 8;
			break;

		case 's':
			s = va_arg(ap, char const *);
			len = strlen(s);
			bcopy(s, buf, len);
			buf[len] = '\0';
			buf += len + 1;
			break;

		default:
			abort();
		}
	}

	va_end(ap);
}

void
unpack(unsigned char const *buf, char const *fmt, ...)
{
va_list		  ap;
char		**s;
size_t		  len;
uint32_t	*u32;
uint64_t	*u64;
double		*d;
uint8_t		*u8;

	va_start(ap, fmt);

	while (*fmt) {
		switch (*fmt++) {
		case 'b':
			u8 = va_arg(ap, uint8_t *);
			*u8 = int8get(buf);
			buf++;
			break;

		case 'u':
		case 'i':
			u32 = va_arg(ap, uint32_t *);
			*u32 = int32get(buf);
			buf += 4;
			break;

		case 'U':
		case 'I':
			u64 = va_arg(ap, uint64_t *);
			*u64 = int64get(buf);
			buf += 8;
			break;

		case 'f':
			d = va_arg(ap, double *);
			*d = (double) int64get(buf) / 1000;
			buf += 8;
			break;

		case 's':
			s = va_arg(ap, char **);
			len = strlen((char *) buf);
			*s = (char *) xmalloc(len);
			strcpy(*s, (char *) buf);
			buf += len + 1;
			break;

		default:
			abort();
		}
	}
	va_end(ap);
}

#ifndef HAVE_PWRITEV
ssize_t
pwritev(d, iov, iovcnt, offset)
	const struct iovec	*iov;
	off_t			 offset;
{
const struct iovec	*v;
ssize_t			 nwrt = 0;
	for (v = iov; v < (iov + iovcnt); v++) {
	ssize_t	n;
		n = pwrite(d, v->iov_base, v->iov_len, offset);
		if (n < 0)
			return n;

		if (n < v->iov_len)
			return nwrt;

		nwrt += n;
		offset += v->iov_len;
	}

	return nwrt;
}
#endif

char *
next_any(str, chrs)
	char		**str;
	char const	*chrs;
{
char	*start, *end;

	while (**str && index(chrs, **str))
		(*str)++;

	if (!**str)
		return NULL;

	start = *str;
	end = strpbrk(start, chrs);

	if (!end) {
		*str += strlen(*str);
		return start;
	}

	*end = 0;
	*str += (end - start) + 1;
	return start;
}

char *
next_line(str)
	char	**str;
{
char	*ret;
size_t	 len;
	if ((ret = next_any(str, "\n")) == NULL)
		return NULL;

	len = strlen(ret);
	if (ret[len - 1] == '\r')
		ret[len - 1] = 0;
	return ret;
}

static int strmatch_impl(char const *, char const *, char const *, char const *);

int
strmatch(str, pattern)
	char const	*str, *pattern;
{
	return strmatch_impl(str, str + strlen(str),
			pattern, pattern + strlen(pattern));
}

/*      $NetBSD: fnmatch.c,v 1.21 2005/12/24 21:11:16 perry Exp $       */

/*
 * Copyright (c) 1989, 1993, 1994
 *      The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Guido van Rossum.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

static char const	*strrangematch(char const *, char const *, int);

static int
strmatch_impl(str, strend, pattern, patend)
	char const	*str, *strend, *pattern, *patend;
{
char	c;
	for (;;) {
		if (pattern == patend) {
			if (str == strend)
				return 1;
			else
				return 0;
		}

		switch (c = tolower(*pattern++)) {
		case '?':
			if (str == strend)
				return 0;
			str++;
			break;

		case '*':
			if (pattern == patend)
				return 1;
			c = tolower(*pattern);

			while (c == '*')
				c = tolower(*++pattern);

			if (pattern == patend)
				return 1;

			while (str < strend) {
				if (strmatch_impl(str, strend, pattern, patend))
					return 1;
				str++;
			}

		case '[':
			if (str == strend)
				return 0;
			if ((pattern = strrangematch(pattern, patend, tolower(*str))) == NULL)
				return 0;
			++str;
			break;

		case '\\':
			c = tolower(*pattern++);
			if (pattern == patend) {
				c = '\\';
				--pattern;
			}

		default:
			if (c != tolower(*str++))
				return 0;
			break;
		}
	}
}

static char const *
strrangematch(pattern, patend, test)
	char const	*pattern, *patend;
{
int	negate, ok;
char	c, c2;

	/*
	 * A bracket expression starting with an unquoted circumflex
	 * character produces unspecified results (IEEE 1003.2-1992,
	 * 3.13.2).  This implementation treats it like '!', for
	 * consistency with the regular expression syntax.
	 * J.T. Conklin (conklin@ngai.kaleida.com)
	 */
	if ((negate = (*pattern == '!' || *pattern == '^')) != 0)
		++pattern;

	for (ok = 0; (c = tolower(*pattern++)) != ']';) {
		if (c == '\\')
			c = tolower(*pattern++);
		if (pattern == patend)
			return NULL;
		if (*pattern == '-') {
			c2 = tolower(*(pattern + 1));
			if (pattern != patend && c2 != ']')
				pattern += 2;
			if (c2 == '\\')
				c2 = tolower(*pattern++);
			if (pattern == patend)
				return NULL;
			if (c <= test && test <= c2)
				ok = 1;
		} else if (c == test)
			ok = 1;
	}

	return ok == negate ? NULL : pattern;
}

void
uv_alloc(handle, sz, buf)
	uv_handle_t	*handle;
	size_t		 sz;
	uv_buf_t	*buf;
{
	buf->base = xmalloc(sz);
	buf->len = sz;
}

static void
explain_msg(msgid)
	char const	*msgid;
{
char	sev, subsys[32] = {}, mid[32] = {};

	if (sscanf(msgid, "%31[A-Z]-%c-%31[A-Z]", subsys, &sev, mid) != 3) {
		subsys[0] = 0;

		if (sscanf(msgid, "%c-%31s", &sev, mid) != 2)
			strlcpy(mid, msgid, sizeof(mid));
	}

	/* Perhaps we should have a list of message facilities? */
	if (!*subsys || strcmp(subsys, "NTS") == 0)
		explain_msg_fac(NTS_fac, mid);
	if (!*subsys || strcmp(subsys, "AUTH") == 0)
		explain_msg_fac(AUTH_fac, mid);
	if (!*subsys || strcmp(subsys, "CLIENT") == 0)
		explain_msg_fac(CLIENT_fac, mid);
	if (!*subsys || strcmp(subsys, "CONFIG") == 0)
		explain_msg_fac(CONFIG_fac, mid);
	if (!*subsys || strcmp(subsys, "DB") == 0)
		explain_msg_fac(DB_fac, mid);
	if (!*subsys || strcmp(subsys, "HISTORY") == 0)
		explain_msg_fac(HISTORY_fac, mid);
	if (!*subsys || strcmp(subsys, "LOG") == 0)
		explain_msg_fac(LOG_fac, mid);
	if (!*subsys || strcmp(subsys, "SPOOL") == 0)
		explain_msg_fac(SPOOL_fac, mid);
}

static void
explain_msg_fac(fac, msgid)
	msg_t		 fac[];
	char const	*msgid;
{
msg_t	*m;
	for (m = &fac[0]; m->m_subsys; m++) {
		if (strcmp(msgid, m->m_code))
			continue;
		printf("Message: %%%s-%c-%s, %s\n\n",
		       m->m_subsys, m->m_sev, m->m_code,
		       m->m_text);
		printf("Explanation:\n\n");
		printf("%s\n", m->m_help);
	}
}
	

