/* RT/NTS -- a lightweight, high performance news transit server. */
/*
 * Copyright (c) 2011 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */
/* $Header: /cvsroot/nts/nts.c,v 1.59 2012/01/10 02:14:08 river Exp $ */

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

#include	<ev.h>

#include	"setup.h"

#ifdef HAVE_OPENSSL
# include	<openssl/ssl.h>
# include	<openssl/crypto.h>
#endif

#include	"config.h"
#include	"server.h"
#include	"client.h"
#include	"net.h"
#include	"spool.h"
#include	"log.h"
#include	"database.h"
#include	"history.h"
#include	"filter.h"
#include	"nts.h"
#include	"feeder.h"
#include	"charq.h"
#include	"balloc.h"
#include	"auth.h"
#include	"article.h"
#include	"thread.h"
#include	"dns.h"

static void	*server_stanza_start(conf_stanza_t *, void *);
static void	 server_set_common_paths(conf_stanza_t *, conf_option_t *, void *, void *);

uint64_t	 max_article_size = 1024 * 1024;
uint64_t	 history_remember = 60 * 60 * 24 * 10; /* 10 days */
int		 defer_pending = 1;
char		*contact_address = "nowhere@example.com";
char		*pathhost;
path_list_t	 common_paths;
static char	*pid_file;
static char	*control_path;
static int	 ctlsock;
static char	*runas_user, *runas_group;
static char	*reader_user, *reader_group;
int		 log_incoming_connections = 1;
char		*reader_handler;
static int	 reader_handoff_socket;
static char	*chroot_dir;
static time_t	 start_time;
uint64_t	 stats_interval = 30;
uint64_t	 worker_threads = 0;

static int	 start_reader_helper(void);
static char	*get_uptime(void);
static void	 usage(char const *);

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

typedef struct ctl_client {
	int	ctl_fd;
} ctl_client_t;

static balloc_t	*ba_ctl;

static void	 ctl_accept(int, struct sockaddr *, socklen_t, SSL *, void *);
static void	 ctl_read(int, int, void *);
static void	 ctl_error(int, int, int, void *);
static void	 ctl_printf(ctl_client_t *, char const *, ...) attr_printf(2, 3);
static void	 ctl_vprintf(ctl_client_t *, char const *, va_list);
static void	 ctl_close(ctl_client_t *);

static void	 ctl_do_peer_stats(ctl_client_t *);
static void	 ctl_do_filter_stats(ctl_client_t *);
static void	 ctl_do_client_stats(ctl_client_t *);
static void	 ctl_do_feeder_stats(ctl_client_t *);
static void	 ctl_do_balloc_stats(ctl_client_t *);

static int	 execute_control_command(char const *);

static void
usage(pname)
	char const	*pname;
{
	fprintf(stderr,
"usage: %s [-Vny] [-x <command>] [-c <conffile>] [-p <pidfile>]\n"
"\n"
"    -h                 print this message\n"
"    -V                 print version and exit\n"
"    -n                 run in the foreground\n"
"    -x <command>       send a control command to a running NTS\n"
"    -p <pidfile>       specify the pid file location\n"
"    -c <conffile>      specify the configuration file\n"
"    -y                 check spool files and exit\n"
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

	/* Initialise the rng before we chroot */
	arc4random();

	start_time = time(NULL);
	ba_ctl = balloc_new(sizeof(ctl_client_t), 8, "ctl_client");

	str_init();
	article_init();
	cq_init();

	while ((c = getopt(argc, argv, "Vc:p:nx:y")) != -1) {
		switch (c) {
			case 'V':
				printf("RT/NTS %s #%d\n", PACKAGE_VERSION,
						build_number);
				printf("\t%s\n", db_version(NULL, NULL, NULL));
				printf("\tlibev %d.%d\n",
						ev_version_major(),
						ev_version_minor());
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

			default:
				usage(argv[0]);
				return 1;
		}
	}

	signal(SIGPIPE, SIG_IGN);

	if (db_init() == -1 ||
	    thr_init() == -1 ||
	    history_init() == -1 ||
	    net_init() == -1 ||
	    dns_init() == -1 ||
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

	if (reader_handler)
		if ((reader_handoff_socket = start_reader_helper()) == -1)
			panic("nts: cannot start reader handoff helper: %s",
					strerror(errno));

	if (runas_group) {
		if ((grp = getgrnam(runas_group)) == NULL)
			panic("unknown group: %s", runas_group);
	}

	if (runas_user) {
		if ((pwd = getpwnam(runas_user)) == NULL)
			panic("unknown user: %s", runas_user);
	}

	if (control_path)
		if ((ctlsock = net_listen_unix(control_path, NET_HIPRIO,
						ctl_accept, NULL)) == -1)
			panic("nts: cannot create control socket");

	if (!nflag && (devnull = open("/dev/null", O_RDWR, 0)) == -1)
		panic("/dev/null: %s", strerror(errno));

	/* dns_run() needs to go before chroot for /etc/resolv.conf */
	if (dns_run() == -1)
		panic("nts: cannot start (see above messages)");

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
					nts_log(LOG_CRIT, "RT/NTS already running (pid %d)",
							atoi(pidline));
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

	article_run();

	if (thr_run() == -1 ||
	    db_run() == -1 ||
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

	nts_log(LOG_NOTICE, "RT/NTS [%s] running", pathhost);

	net_run();
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
		pe->pe_path = str_new_c(val->cv_string);
		SIMPLEQ_INSERT_TAIL(&common_paths, pe, pe_list);
	}
}

void
vpanic(fmt, ap)
	char const	*fmt;
	va_list		 ap;
{
	nts_vlog(LOG_CRIT, fmt, ap);
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

static void
ctl_accept(fd, addr, len, ssl, udata)
	struct sockaddr	*addr;
	socklen_t	 len;
	SSL		*ssl;
	void		*udata;
{
ctl_client_t	*ctl;
	ctl = bzalloc(ba_ctl);
	ctl->ctl_fd = fd;
	net_open(fd, ssl, NET_HIPRIO, ctl_read, ctl_error, ctl);
}

static void
ctl_read(fd, what, udata)
	void	*udata;
{
ctl_client_t	*ctl = udata;
str_t		 cmd;
int		 n;

	switch (n = net_readline(ctl->ctl_fd, &cmd)) {
	case 0:
		return;
	case -1:
		ctl_close(ctl);
		return;
	}

	if (str_equal_c(cmd, "version")) {
		ctl_printf(ctl, "OK\n%s #%d\n", PACKAGE_VERSION, build_number);
	} else if (str_equal_c(cmd, "peers")) {
		ctl_printf(ctl, "OK\n");
		ctl_do_peer_stats(ctl);
	} else if (str_equal_c(cmd, "filters")) {
		ctl_printf(ctl, "OK\n");
		ctl_do_filter_stats(ctl);
	} else if (str_equal_c(cmd, "clients")) {
		ctl_printf(ctl, "OK\n");
		ctl_do_client_stats(ctl);
	} else if (str_equal_c(cmd, "feeder")) {
		ctl_printf(ctl, "OK\n");
		ctl_do_feeder_stats(ctl);
	} else if (str_equal_c(cmd, "uptime")) {
		ctl_printf(ctl, "OK\n%s\n", get_uptime());
	} else if (str_equal_c(cmd, "shutdown")) {
		nts_shutdown("control socket");
	} else if (str_equal_c(cmd, "balloc")) {
#if BALLOC_STATS
		ctl_printf(ctl, "OK\n");
		ctl_do_balloc_stats(ctl);
#else
		ctl_printf(ctl, "ERR Allocator statistics not available.\n");
#endif
	} else if (str_equal_c(cmd, "stats")) {
	time_t	now = time(NULL);
		ctl_printf(ctl, "OK\n");
		ctl_printf(ctl, "RT/NTS %s #%d statistics as of %s",
				PACKAGE_VERSION, build_number, ctime(&now));
		ctl_printf(ctl, "=========================================="
				"==================\n");
		ctl_printf(ctl, "\n%s\n\n", get_uptime());
		ctl_do_peer_stats(ctl);
		ctl_printf(ctl, "\n");
		ctl_do_feeder_stats(ctl);
		ctl_printf(ctl, "\n");
		ctl_do_client_stats(ctl);
		ctl_printf(ctl, "\n");
		ctl_do_filter_stats(ctl);
#if BALLOC_STATS
		ctl_printf(ctl, "\nAllocator:\n");
		ctl_do_balloc_stats(ctl);
#endif
	} else
		ctl_printf(ctl, "ERR Unknown control command\n");

	str_free(cmd);
	ctl_close(ctl);
}

static void
ctl_error(fd, what, err, udata)
	void	*udata;
{
ctl_client_t	*ctl = udata;
	ctl_close(ctl);
}

static void
ctl_vprintf(ctl, fmt, ap)
	ctl_client_t	*ctl;
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

	net_write(ctl->ctl_fd, r, len);

	if (r != buf)
		free(r);
}

static void
ctl_printf(ctl_client_t *ctl, char const *fmt, ...)
{
va_list	ap;
	va_start(ap, fmt);
	ctl_vprintf(ctl, fmt, ap);
	va_end(ap);
}

static void
ctl_close(ctl)
	ctl_client_t	*ctl;
{
	net_close(ctl->ctl_fd);
	bfree(ba_ctl, ctl);
}

void
ctl_timeout(sig)
{
	fprintf(stderr, "timeout executing control command\n");
	_exit(0);
}

static int
execute_control_command(cmd)
	char const	*cmd;
{
struct sockaddr_un	 sun;
int			 fd;
FILE			*fw, *fr;
char			 line[1024];

	if (strcmp(cmd, "stop") == 0) {
	FILE	*pidf;
	char	 pid_line[64];
	pid_t	 pid;

		if (!pid_file) {
			fprintf(stderr, "pid-file not configured\n");
			return 1;
		}

		if ((pidf = fopen(pid_file, "r")) == NULL) {
			perror(pid_file);
			return 1;
		}

		if (fgets(pid_line, sizeof(pid_line), pidf) == NULL
		    || (pid = atoi(pid_line)) == 0) {
			fprintf(stderr, "cannot read pid from %s\n",
					pid_file);
			return 1;
		}

		if (kill(pid, SIGTERM) == -1) {
			fprintf(stderr, "kill(%d, SIGTERM): %s",
					(int) pid, strerror(errno));
			return 1;
		}

		return 0;
	} else if (strcmp(cmd, "hashpw") == 0) {
	char	*pw = getpass("Password: ");
	str_t	 spw = str_new_c(pw);
	str_t	 hash = auth_hash_password(spw);
		printf("%.*s\n", str_printf(hash));
		return 0;
	}

	if (!control_path) {
		fprintf(stderr, "control-path not specified in configuration\n");
		return 1;
	}

	bzero(&sun, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strncpy(sun.sun_path, control_path, sizeof(sun.sun_path));

	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		perror("socket");
		return 1;
	}

	signal(SIGALRM, ctl_timeout);
	alarm(60);
	if (connect(fd, (struct sockaddr *) &sun, sizeof(sun)) == -1) {
		perror(control_path);
		return 1;
	}

	if ((fr = fdopen(fd, "r")) == NULL || (fw = fdopen(fd, "w")) == NULL) {
		perror("fdopen");
		return 1;
	}

	alarm(60);
	fprintf(fw, "%s\r\n", cmd);
	fflush(fw);

	alarm(60);
	if (fgets(line, sizeof(line), fr) == NULL) {
		if (strcmp(cmd, "shutdown") == 0)
			return 0;
		fprintf(stderr, "no data returned from control socket\n");
		return 1;
	}

	if (strcmp(line, "OK\n") == 0) {
		while (fgets(line, sizeof(line), fr)) {
			alarm(60);
			fputs(line, stdout);
		}
		return 0;
	} else if (strlen(line) > 4 && memcmp(line, "ERR ", 4) == 0) {
		fprintf(stderr, "Error: %s", line + 4);
		return 1;
	} else {
		fprintf(stderr, "Unknown response from control socket\n");
		return 1;
	}
}

void
nts_shutdown(reason)
	char const	*reason;
{
	nts_log(LOG_NOTICE, "shutting down: %s", reason);
	spool_shutdown();
	server_shutdown();
	filter_shutdown();
	history_shutdown();
	db_shutdown();

	if (pid_file && unlink(pid_file) == -1)
		nts_log(LOG_ERR, "cannot unlink pid file %s: %s",
			pid_file, strerror(errno));

	log_shutdown();
	exit(0);
}

void
ctl_do_peer_stats(ctl)
	ctl_client_t	*ctl;
{
server_t	*se;
uint64_t	 t_in_a = 0, t_in_d = 0, t_in_ref = 0, t_in_rej = 0,
		 t_out_a = 0, t_out_d = 0, t_out_ref = 0, t_out_rej = 0;
double		 t_in_a_persec = 0, t_in_d_persec = 0, t_in_ref_persec = 0, t_in_rej_persec = 0,
		 t_out_a_persec = 0, t_out_d_persec = 0, t_out_ref_persec = 0, t_out_rej_persec = 0;
int		 nservers = 0;

	ctl_printf(ctl, "stats average interval: %d seconds\n\n", (int) stats_interval);

	SLIST_FOREACH(se, &servers, se_list) {
		ctl_printf(ctl, "%s\n", se->se_name);
		ctl_printf(ctl, "   in: accept %"PRIu64" (%.2f/sec) "
				"defer %"PRIu64" (%.2f/sec) "
				"refuse %"PRIu64" (%.2f/sec) "
				"reject %"PRIu64" (%.2f/sec)\n",
				se->se_in_accepted, se->se_in_accepted_persec,
				se->se_in_deferred, se->se_in_deferred_persec,
				se->se_in_refused, se->se_in_refused_persec,
				se->se_in_rejected, se->se_in_rejected_persec);
		ctl_printf(ctl, "  out: accept %"PRIu64" (%.2f/sec) "
				"defer %"PRIu64" (%.2f/sec) "
				"refuse %"PRIu64" (%.2f/sec) "
				"reject %"PRIu64" (%.2f/sec)\n",
				se->se_out_accepted, se->se_out_accepted_persec,
				se->se_out_deferred, se->se_out_deferred_persec,
				se->se_out_refused, se->se_out_refused_persec,
				se->se_out_rejected, se->se_out_rejected_persec);
		ctl_printf(ctl, "\n");

		t_in_a += se->se_in_accepted;
		t_in_d += se->se_in_deferred;
		t_in_ref += se->se_in_refused;
		t_in_rej += se->se_in_rejected;
		t_out_a += se->se_out_accepted;
		t_out_d += se->se_out_deferred;
		t_out_ref += se->se_out_refused;
		t_out_rej += se->se_out_rejected;

		t_in_a_persec += se->se_in_accepted_persec;
		t_in_d_persec += se->se_in_deferred_persec;
		t_in_ref_persec += se->se_in_refused_persec;
		t_in_rej_persec += se->se_in_rejected_persec;
		t_out_a_persec += se->se_out_accepted_persec;
		t_out_d_persec += se->se_out_deferred_persec;
		t_out_ref_persec += se->se_out_refused_persec;
		t_out_rej_persec += se->se_out_rejected_persec;

		++nservers;
	}

	ctl_printf(ctl, "TOTAL\n");
	ctl_printf(ctl, "   in: accept %"PRIu64" (%.2f/sec) "
			"defer %"PRIu64" (%.2f/sec) "
			"refuse %"PRIu64" (%.2f/sec) "
			"reject %"PRIu64" (%.2f/sec)\n",
		t_in_a, t_in_a_persec / nservers,
		t_in_d, t_in_d_persec / nservers,
		t_in_ref, t_in_ref_persec / nservers,
		t_in_rej, t_in_rej_persec /nservers);

	ctl_printf(ctl, "  out: accept %"PRIu64" (%.2f/sec) "
			"defer %"PRIu64" (%.2f/sec) "
			"refuse %"PRIu64" (%.2f/sec) "
			"reject %"PRIu64" (%.2f/sec)\n",
		t_out_a, t_out_a_persec / nservers,
		t_out_d, t_out_d_persec / nservers,
		t_out_ref, t_out_ref_persec / nservers,
		t_out_rej, t_out_rej_persec /nservers);
}

void
ctl_do_filter_stats(ctl)
	ctl_client_t	*ctl;
{
filter_list_entry_t	*fle;
	ctl_printf(ctl, "%-22s   %12s %12s %12s\n",
			"Filter name", "permit", "deny", "dunno");

	SIMPLEQ_FOREACH(fle, &filter_list, fle_list) {
	filter_t	*fi = fle->fle_filter;
		ctl_printf(ctl, "%-22.*s   %12"PRIu64" %12"PRIu64" %12"PRIu64"\n",
			str_printf(fi->fi_name), fi->fi_num_permit,
			fi->fi_num_deny, fi->fi_num_dunno);
	}
}

void
ctl_do_feeder_stats(ctl)
	ctl_client_t	*ctl;
{
server_t	*se;

	ctl_printf(ctl, "%-20s  %3s %3s %-3s %-8s %-8s %s\n",
			"peer", "sdq", "wt", "adp", "state", "mode", "addr");

	SLIST_FOREACH(se, &servers, se_list) {
	feeder_t	*fe = se->se_feeder;
	static char const *const states[] = {
		"dns",
		"connect",
		"grwait",
		"capwait",
		"rdcap",
		"strmwait",
		"running",
	};

		if (fe == NULL)
			ctl_printf(ctl, "%-20s  %3s %3s %3s %-8s %-8s %s\n",
				se->se_name, "-", "-", "-", "stopped", "-", "-");
		else
			ctl_printf(ctl, "%-20s  %3d %3d %3s %-8s %-8s %s\n",
				se->se_name, fe->fe_send_queue_size,
				fe->fe_waiting_size,
				(fe->fe_flags & FE_ADP) ? "yes" : "no",
				states[fe->fe_state],
				(fe->fe_mode == FM_IHAVE) ? "ihave" : "stream",
				fe->fe_strname);
	}
}

void
ctl_do_client_stats(ctl)
	ctl_client_t	*ctl;
{
struct server	*se;

	ctl_printf(ctl, "%-40s %-4s %s\n", "client", "ssl", "state");

	SLIST_FOREACH(se, &servers, se_list) {
	struct client	*client;

		SIMPLEQ_FOREACH(client, &se->se_clients, cl_list) {
		char	s[64] = {};
			if (client->cl_flags & CL_PAUSED)
				strcat(s, "paused,");
			if (client->cl_flags & CL_DEAD)
				strcat(s, "dead,");
			if (client->cl_flags & CL_FREE)
				strcat(s, "free,");
			if (s[0])
				s[strlen(s) - 2] = 0;
			else
				strcpy(s, "-");

			ctl_printf(ctl, "%-40s %-4s %s\n",
					client->cl_strname,
					client->cl_flags & CL_SSL ? "y" : "-",
					s);
		}
	}
}

#if BALLOC_STATS
void
ctl_do_balloc_stats(ctl)
	ctl_client_t	*ctl;
{
balloc_t	*ba;
	ctl_printf(ctl, "%-20s %8s %8s %8s   %8s %8s\n",
			"pool", "alloc", "free", "diff", "", "max");

	SLIST_FOREACH(ba, &balloc_list, ba_slist) {
		ctl_printf(ctl, "%-20s %8lu %8lu %8lu %8luKB %8lu %8luKB\n",
				ba->ba_name, (long unsigned) ba->ba_alloc,
				(long unsigned) ba->ba_free,
				(long unsigned) (ba->ba_alloc - ba->ba_free),
				(long unsigned) (ba->ba_alloc - ba->ba_free)
					* ba->ba_size / 1024,
				(long unsigned) (ba->ba_max),
				(long unsigned) (ba->ba_max * ba->ba_size) / 1024);
	}
}
#endif

static int
start_reader_helper()
{
pid_t		 pid;
int		 socks[2];
uid_t		 ruid = 0;
gid_t		 rgid = 0;
struct group	*grp;
struct passwd	*pwd;

	if (reader_group) {
		if ((grp = getgrnam(reader_group)) == NULL)
			panic("unknown group: %s", reader_group);
		rgid = grp->gr_gid;
	}

	if (reader_user) {
		if ((pwd = getpwnam(reader_user)) == NULL)
			panic("unknown user: %s", reader_user);
	}

	if (socketpair(PF_UNIX, SOCK_DGRAM, 0, socks) == -1)
		return -1;

	switch (pid = fork()) {
	case 0:		break;
	case -1:	return -1;
	default:
		close(socks[1]);
		return socks[0];
	}

	close(socks[0]);

#ifdef HAVE_SETPROCTITLE
	setproctitle("reader helper");
#endif

	for (;;) {
	struct msghdr	 msg;
	struct cmsghdr	*cmsg;
	struct iovec	 iov;
	char		 data[1024], control[1024];
	int		 fd;
	
		bzero(&msg, sizeof(msg));
		iov.iov_base = data;
		iov.iov_len = sizeof(data);
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = control;
		msg.msg_controllen = sizeof(control);

		if (recvmsg(socks[1], &msg, 0) < 0) {
			perror("recvmsg");
			exit(0);
		}

		for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
			if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS)
				continue;
			fd = *(int *) CMSG_DATA(cmsg);
			break;
		}

		switch (pid = fork()) {
		case -1:	
#define INT_ERR "400 Internal error.\r\n"
			write(fd, INT_ERR, sizeof(INT_ERR) - 1);
			close(fd);
			continue;
		case 0:
			break;
		default:
			close(fd);
			continue;
		}

		dup2(fd, STDIN_FILENO);
		dup2(fd, STDOUT_FILENO);
		dup2(fd, STDERR_FILENO);
		close(fd);

		if (rgid)
			if (setgid(rgid) == -1) {
				write(STDOUT_FILENO, INT_ERR, sizeof(INT_ERR) - 1);
				_exit(1);
			}

		if (ruid) {
			if (initgroups(reader_user, pwd->pw_gid) == -1) {
				write(STDOUT_FILENO, INT_ERR, sizeof(INT_ERR) - 1);
				_exit(1);
			}

			if (setuid(ruid) == -1) {
				write(STDOUT_FILENO, INT_ERR, sizeof(INT_ERR) - 1);
				_exit(1);
			}
		}

		execl(reader_handler, reader_handler, NULL);
		write(STDOUT_FILENO, INT_ERR, sizeof(INT_ERR) - 1);
		_exit(1);
	}

	exit(0);
}

int
reader_handoff(fd)
{
char		 control[sizeof(struct cmsghdr)];
struct msghdr	 msg;
struct cmsghdr	*cmsg;
struct iovec	 iov;

	bzero(&iov, sizeof(iov));
	bzero(&msg, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(fd));
	*(int *) CMSG_DATA(cmsg) = fd;
	msg.msg_controllen = cmsg->cmsg_len;

	if (sendmsg(reader_handoff_socket, &msg, 0) < 0)
		return -1;
	return 0;
}

static char *
get_uptime()
{
static char	str[64];
time_t		upt = time(NULL) - start_time;
uint64_t	ct;
int		d, h, m, s,
		cd, ch, cm, cs, cms;
struct rusage	rus;

	getrusage(RUSAGE_SELF, &rus);
	ct = (rus.ru_utime.tv_sec * 1000) + (rus.ru_utime.tv_usec / 1000)
	   + (rus.ru_stime.tv_sec * 1000) + (rus.ru_stime.tv_usec / 1000);

	d = upt / (60 * 60 * 24);
	upt %= (60 * 60 * 24);
	h = upt / (60 * 60);
	upt %= (60 * 60);
	m = upt / 60;
	upt %= 60;
	s = upt;

	cd = ct / (1000 * 60 * 60 * 24);
	ct %= (1000 * 60 * 60 * 24);
	ch = ct / (1000 * 60 * 60);
	ct %= (1000 * 60 * 60);
	cm = ct / (1000 * 60);
	ct %= (1000 * 60);
	cs = ct / 1000;
	ct %= 1000;
	cms = ct;

	snprintf(str, sizeof(str), "up %d+%02d:%02d:%02d, "
			"cpu used %d+%02d:%02d:%02d.%03d, av %.2f%%",
			d, h, m, s, cd, ch, cm, cs, cms,
			(((double)ct / 1000) / upt) * 100);
	return str;
}
