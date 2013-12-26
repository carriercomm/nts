/* RT/NTS -- a lightweight, high performance news transit server. */
/* 
 * Copyright (c) 2011-2013 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */

#include	<sys/uio.h>

#include	<stdlib.h>
#include	<strings.h>
#include	<unistd.h>
#include	<errno.h>
#include	<assert.h>

#include	"charq.h"
#include	"nts.h"

void
cq_init()
{
}

charq_t *
cq_new()
{
charq_t		*cq = xcalloc(1, sizeof(*cq));
	TAILQ_INIT(&cq->cq_ents);
	return cq;
}

void
cq_free(cq)
	charq_t	*cq;
{
charq_ent_t	*cqe;
	while (cqe = TAILQ_FIRST(&cq->cq_ents)) {
		TAILQ_REMOVE(&cq->cq_ents, cqe, cqe_list);
		free(cqe->cqe_data);
		free(cqe);
	}
	free(cq);
}

void
cq_append(cq, data, sz)
	charq_t	*cq;
	char	*data;
	size_t	 sz;
{
charq_ent_t	*new = xcalloc(1, sizeof(*new));
	new->cqe_data = data;
	new->cqe_len = sz;
	cq->cq_len += sz;

	TAILQ_INSERT_TAIL(&cq->cq_ents, new, cqe_list);
}

void
cq_remove_start(cq, sz)
	charq_t	*cq;
	size_t	 sz;
{
charq_ent_t	 *cqe;

	assert(sz <= cq_len(cq));

	while (sz) {
	size_t		 n;

		cqe = cq_first_ent(cq);
		n = (cqe->cqe_len - cq->cq_offs);

		if (sz < n)
			break;

		TAILQ_REMOVE(&cq->cq_ents, cqe, cqe_list);

		cq->cq_len -= n;
		cq->cq_offs = 0;

		sz -= n;

		free(cqe->cqe_data);
		free(cqe);
	}

	if (!sz)
		return;

	cqe = cq_first_ent(cq);
	cq->cq_offs += sz;
	cq->cq_len -= sz;
}

void
cq_extract_start(cq, buf, sz)
	charq_t	*cq;
	void	*buf;
	size_t	 sz;
{
unsigned char	*bufp = buf;
charq_ent_t	 *cqe;

	assert(sz <= cq_len(cq));

	while (sz) {
	size_t		 n;

		cqe = cq_first_ent(cq);
		n = (cqe->cqe_len - cq->cq_offs);
		if (sz < n)
			break;

		TAILQ_REMOVE(&cq->cq_ents, cqe, cqe_list);

		bcopy(cqe->cqe_data + cq->cq_offs, bufp, n);

		cq->cq_len -= n;
		cq->cq_offs = 0;

		sz -= n;
		bufp += n;

		free(cqe->cqe_data);
		free(cqe);
	}

	if (!sz)
		return;

	cqe = cq_first_ent(cq);
	bcopy(cqe->cqe_data + cq->cq_offs, bufp, sz);
	cq->cq_offs += sz;
	cq->cq_len -= sz;
}

static ssize_t
cq_find(cq, c)
	charq_t	*cq;
	char	 c;
{
size_t		 i = 0, offs = cq->cq_offs;
charq_ent_t	*cqe;

	TAILQ_FOREACH(cqe, &cq->cq_ents, cqe_list) {
	char	*r;
		if (r = memchr(cqe->cqe_data + offs, c, cqe->cqe_len - offs))
			return i + (r - (cqe->cqe_data + offs));

		i += cqe->cqe_len;
		offs = 0;
	}

	return -1;
}

char *
cq_read_line(cq)
	charq_t	*cq;
{
ssize_t		 pos;
char		*line;

	if ((pos = cq_find(cq, '\n')) == -1)
		return NULL;
	pos++;
	line = xmalloc(pos + 1);
	cq_extract_start(cq, line, pos);
	line[pos] = 0;

	if (*line && line[pos - 2] == '\r')
		line[pos - 2] = 0;
	return line;
}
