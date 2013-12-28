/* RT/NTS -- a lightweight, high performance news transit server. */
/* 
 * Copyright (c) 2011-2013 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */

#include	<pwd.h>
#include	<grp.h>
#include	<errno.h>

#include	<uv.h>

#include	"client.h"
#include	"nts.h"
#include	"log.h"

static uv_loop_t	*handoff_loop;
static uv_pipe_t	*reader_pipe;
static uv_pipe_t	*start_reader_helper(void);
static uid_t		 ruid = 0;
static gid_t		 rgid = 0;
static void		 on_handoff_read(uv_pipe_t *, ssize_t, uv_buf_t const *, uv_handle_type);
static void		 on_handoff_done(uv_write_t *, int);
static void		 on_handoff_close_done(uv_handle_t *);

int
client_reader_init(void)
{
	if (!reader_handler)
		return 0;

	if ((reader_pipe = start_reader_helper()) == NULL)
		return -1;
	return 0;
}

void
client_reader(client)
	client_t	*client;
{
	reader_handoff(client->cl_stream);
}

static uv_pipe_t *
start_reader_helper()
{
pid_t		 pid;
int		 socks[2];
struct group	*grp;
struct passwd	*pwd;
int		 err;
uv_pipe_t	*pipe;

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
		return NULL;

	if ((pid = fork()) == -1)
		return NULL;

	if (pid > 0) {
	uv_pipe_t	*ret = xcalloc(1, sizeof(*ret));

		if (err = uv_pipe_init(loop, ret, 1))
			panic("uv_pipe_init: %s", uv_strerror(err));

		if (err = uv_pipe_open(ret, socks[0]))
			panic("uv_pipe_open: %s", uv_strerror(err));

		close(socks[1]);
		return ret;
	}

	close(socks[0]);

#ifdef HAVE_SETPROCTITLE
	setproctitle("reader helper");
#endif

	handoff_loop = uv_loop_new();

	pipe = xcalloc(1, sizeof(*pipe));
	if (err = uv_pipe_init(handoff_loop, pipe, 1)) {
		fprintf(stderr, "uv_pipe_init: %s", uv_strerror(err));
		_exit(1);
	}

	if (err = uv_pipe_open(pipe, socks[1])) {
		fprintf(stderr, "uv_pipe_open: %s", uv_strerror(err));
		_exit(1);
	}

	uv_read2_start((uv_stream_t *) pipe, uv_alloc, on_handoff_read);

	uv_run(handoff_loop, UV_RUN_DEFAULT);
	_exit(0);
}

static void
on_sock_close(handle)
	uv_handle_t	*handle;
{
	free(handle);
}

static void
on_handoff_read(pipe, nread, buf, pending)
	uv_pipe_t	*pipe;
	ssize_t		 nread;
	const uv_buf_t	*buf;
	uv_handle_type	 pending;
{
uv_pipe_t		*sock;
int			 err;
uv_stdio_container_t	 child_stdio[3];
uv_process_options_t	 options;
uv_process_t		*proc;

	free(buf->base);

	if (pending == UV_UNKNOWN_HANDLE)
		return;

	sock = xcalloc(1, sizeof(*sock));

	if (err = uv_pipe_init(handoff_loop, sock, 0)) {
		fprintf(stderr, "uv_pipe_init: %s", uv_strerror(err));
		return;
	}

	if (err = uv_accept((uv_stream_t *) pipe, (uv_stream_t *) sock)) {
		fprintf(stderr, "uv_accept: %s", uv_strerror(err));
		uv_close((uv_handle_t *) sock, on_sock_close);
		return;
	}

	bzero(child_stdio, sizeof(child_stdio));
	bzero(&options, sizeof(options));

	child_stdio[0].flags = UV_INHERIT_STREAM;
	child_stdio[0].data.stream = (uv_stream_t *) sock;
	child_stdio[1].flags = UV_INHERIT_STREAM;
	child_stdio[1].data.stream = (uv_stream_t *) sock;
	child_stdio[2].flags = UV_INHERIT_STREAM;
	child_stdio[2].data.stream = (uv_stream_t *) sock;

	options.exit_cb = NULL;
	options.file = reader_handler;
	options.args = xcalloc(2, sizeof(char *));
	options.args[0] = reader_handler;
	options.args[1] = NULL;
	options.stdio_count = 3;
	options.stdio = child_stdio;
	options.uid = ruid;
	options.gid = rgid;

	if (ruid)
		options.flags |= UV_PROCESS_SETUID | UV_PROCESS_SETGID;
	options.flags |= UV_PROCESS_DETACHED;
	
	proc = xcalloc(1, sizeof(*proc));
	if (err = uv_spawn(handoff_loop, proc, &options)) {
		fprintf(stderr, "uv_spawn: %s\n", uv_strerror(err));
		free(proc);
		uv_close((uv_handle_t *) sock, on_sock_close);
	}


#define INT_ERR "400 Internal error.\r\n"
}

void
reader_handoff(stream)
	uv_tcp_t	*stream;
{
uv_write_t	*req = xcalloc(1, sizeof(*req));

	req->data = stream;
	uv_write2(req, (uv_stream_t *) reader_pipe, NULL, 0, (uv_stream_t *) stream,
		  on_handoff_done);
}

void
on_handoff_done(req, status)
	uv_write_t	*req;
{
uv_stream_t	*stream = req->data;
	uv_close((uv_handle_t *) stream, on_handoff_close_done);
}

void
on_handoff_close_done(handle)
	uv_handle_t	*handle;
{
	free(handle);
}
