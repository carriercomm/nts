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

#include	<unistd.h>

#include	<uv.h>

#include	"nts.h"
#include	"ctl.h"
#include	"server.h"
#include	"feeder.h"
#include	"auth.h"
#include	"charq.h"
#include	"log.h"

typedef struct ctl_client {
	uv_pipe_t	*ctl_stream;
	charq_t		*ctl_rdbuf;
} ctl_client_t;

static void	 on_ctl_connect(uv_stream_t *, int);
static void	 on_ctl_read(uv_stream_t *, ssize_t, uv_buf_t const *);
static void	 on_ctl_write_done(uv_write_t *, int);
static void	 on_ctl_shutdown_done(uv_shutdown_t *, int);
static void	 on_ctl_close_done(uv_handle_t *);

static void	 ctl_close(ctl_client_t *, int drain);
static void	 ctl_printf(ctl_client_t *, char const *, ...) attr_printf(2, 3);
static void	 ctl_vprintf(ctl_client_t *, char const *, va_list);

static void	 ctl_do_peer_stats(ctl_client_t *);
static void	 ctl_do_filter_stats(ctl_client_t *);
static void	 ctl_do_client_stats(ctl_client_t *);
static void	 ctl_do_feeder_stats(ctl_client_t *);

static char	*get_uptime(void);

static uv_pipe_t	ctl_sock;
static time_t		start_time;

int
ctl_init(path)
	char const	*path;
{
int	err;

	time(&start_time);

	if (err = uv_pipe_init(loop, &ctl_sock, 0)) {
		nts_log("ctl: \"%s\": %s", path, uv_strerror(err));
		return -1;
	}

	(void) unlink(path);
	if (err = uv_pipe_bind(&ctl_sock, path)) {
		nts_log("ctl: \"%s\": %s", path, uv_strerror(err));
		return -1;
	}

	if (err = uv_listen((uv_stream_t *) &ctl_sock, 16, on_ctl_connect)) {
		nts_log("ctl: \"%s\": %s", path, uv_strerror(err));
		return -1;
	}

	return 0;
}

static void
on_ctl_connect(server, status)
	uv_stream_t	*server;
{
ctl_client_t	*ctl;
uv_pipe_t	*sock;
int		 err;

	sock = xcalloc(1, sizeof(*sock));
	if (err = uv_pipe_init(loop, sock, 0)) {
		nts_log("ctl: accept: %s", uv_strerror(err));
		free(sock);
		return;
	}

	if (err = uv_accept(server, (uv_stream_t *) sock)) {
		nts_log("ctl: accept: %s", uv_strerror(err));
		free(sock);
		return;
	}

	ctl = xcalloc(1, sizeof(*ctl));
	ctl->ctl_stream = sock;
	sock->data = ctl;

	uv_read_start((uv_stream_t *) sock, uv_alloc, on_ctl_read);
}

static void
on_ctl_write_done(wr, status)
	uv_write_t	*wr;
{
ctl_client_t	*ctl = wr->data;

	free(wr->bufs[0].base);
	free(wr);

	if (status == 0)
		ctl_close(ctl, 0);
}

static void
on_ctl_read(stream, nread, buf)
	uv_stream_t	*stream;
	ssize_t		 nread;
	const uv_buf_t	*buf;
{
ctl_client_t	*ctl = stream->data;
char		*cmd;

	if (nread <= 0) {
		free(buf->base);
		ctl_close(ctl, 0);
		return;
	}

	cq_append(ctl->ctl_rdbuf, buf->base, nread);
	free(buf->base);

	if ((cmd = cq_read_line(ctl->ctl_rdbuf)) == NULL)
		return;

	if (strcmp(cmd, "version") == 0) {
		ctl_printf(ctl, "OK\n%s\n", version_string);
	} else if (strcmp(cmd, "peers") == 0) {
		ctl_printf(ctl, "OK\n");
		ctl_do_peer_stats(ctl);
	} else if (strcmp(cmd, "filters") == 0) {
		ctl_printf(ctl, "OK\n");
		ctl_do_filter_stats(ctl);
	} else if (strcmp(cmd, "clients") == 0) {
		ctl_printf(ctl, "OK\n");
		ctl_do_client_stats(ctl);
	} else if (strcmp(cmd, "feeder") == 0) {
		ctl_printf(ctl, "OK\n");
		ctl_do_feeder_stats(ctl);
	} else if (strcmp(cmd, "uptime") == 0) {
		ctl_printf(ctl, "OK\n%s\n", get_uptime());
	} else if (strcmp(cmd, "shutdown") == 0) {
		nts_shutdown("control socket");
	} else if (strcmp(cmd, "stats") == 0) {
	time_t	now = time(NULL);
		ctl_printf(ctl, "OK\n");
		ctl_printf(ctl, "%s statistics as of %s",
				version_string, ctime(&now));
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
	} else
		ctl_printf(ctl, "ERR Unknown control command\n");

	free(cmd);
	ctl_close(ctl, 1);
}

static void
ctl_vprintf(ctl, fmt, ap)
	ctl_client_t	*ctl;
	char const	*fmt;
	va_list		 ap;
{
char            *buf;
int              len;
uv_write_t      *wr;
uv_buf_t         ubuf;

#define PRINTF_BUFSZ    1024

	buf = malloc(PRINTF_BUFSZ);
	len = vsnprintf(buf, PRINTF_BUFSZ, fmt, ap);
	if ((unsigned int) len >= PRINTF_BUFSZ) {
		buf = realloc(buf, len + 1);
		vsnprintf(buf, len + 1, fmt, ap);
	}

	wr = xcalloc(1, sizeof(*wr));

	ubuf = uv_buf_init(buf, len);
	wr->data = ctl;

	uv_write(wr, (uv_stream_t *) ctl->ctl_stream, &ubuf, 1, on_ctl_write_done);
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
on_ctl_shutdown_done(req, status)
	uv_shutdown_t	*req;
{
ctl_client_t	*ctl = req->data;
	free(req);
	uv_close((uv_handle_t *) ctl->ctl_stream, on_ctl_close_done);
}

static void
on_ctl_close_done(handle)
	uv_handle_t	*handle;
{
ctl_client_t	*ctl = handle->data;
	free(handle);
	cq_free(ctl->ctl_rdbuf);
	free(ctl);
}

static void
ctl_close(ctl, drain)
	ctl_client_t	*ctl;
{
	if (drain) {
	uv_shutdown_t	*req = xcalloc(1, sizeof(*req));
		req->data = ctl;
		uv_shutdown(req, (uv_stream_t *) ctl->ctl_stream, on_ctl_shutdown_done);
		return;
	}

	uv_close((uv_handle_t *) ctl->ctl_stream, on_ctl_close_done);
}

void
ctl_timeout(sig)
{
	fprintf(stderr, "timeout executing control command\n");
	_exit(0);
}

int
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
	char	*hash = auth_hash_password(pw);
		printf("%s\n", hash);
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
		ctl_printf(ctl, "%-22s   %12"PRIu64" %12"PRIu64" %12"PRIu64"\n",
			fi->fi_name, fi->fi_num_permit,
			fi->fi_num_deny, fi->fi_num_dunno);
	}
}

void
ctl_do_feeder_stats(ctl)
	ctl_client_t	*ctl;
{
server_t	*se;

	ctl_printf(ctl, "%-20s  %3s %3s %-8s %-8s %s\n",
			"peer", "q", "adp", "state", "mode", "addr");

	SLIST_FOREACH(se, &servers, se_list) {
	feeder_t	*fe = se->se_feeder;
	fconn_t		*fc;
	static char const *const states[] = {
		"dns",
		"connect",
		"grwait",
		"capwait",
		"rdcap",
		"strmwait",
		"running",
	};

		TAILQ_FOREACH(fc, &fe->fe_conns, fc_list) {
			ctl_printf(ctl, "%-20s  %3d %3s %-8s %-8s %s\n",
				se->se_name, fc->fc_ncq,
				(fc->fc_flags & FE_ADP) ? "yes" : "no",
				states[fc->fc_state],
				(fc->fc_mode == FM_IHAVE) ? "ihave" : "stream",
				fc->fc_strname);
		}
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

