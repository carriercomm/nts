/* RT/NTS -- a lightweight, high performance news transit server. */
/* 
 * Copyright (c) 2011, 2012 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */
/* $Header: /cvsroot/nts/spool.c,v 1.29 2012/01/10 17:13:13 river Exp $ */

/*
 * A spool "file" is actually a directory, containing sequentially numberered
 * files starting at 00000000.  Each article is appended to the current spool
 * file, preceded by a header.  Once the current spool file is full (size >=
 * max size), we open a new file, and possibly delete the oldest file once
 * max-files is reached.
 *
 * At the start of each file, we store its current valid length, which is
 * fsynced every 10 seconds.  We also fsync the spool after every article
 * write.  At startup, we start at the last saved spool position, and verify
 * every article after that until the end of the file.  Articles which are
 * fully written will be verified okay, while articles which were partially
 * written (e.g. due to host crash) will be discarded.  These articles were
 * never fully received from a peer, so the peer will re-send them later.
 */

#include	<sys/types.h>
#include	<sys/stat.h>
#include	<sys/mman.h>
#include	<sys/uio.h>

#include	<stdlib.h>
#include	<unistd.h>
#include	<fcntl.h>
#include	<string.h>
#include	<errno.h>
#include	<assert.h>
#include	<dirent.h>
#include	<limits.h>

#include	"spool.h"
#include	"config.h"
#include	"nts.h"
#include	"log.h"
#include	"crc.h"

#ifndef HAVE_FDATASYNC
# define fdatasync fsync
#endif

static char	*spool_path;
static uint64_t	 spool_size = 1024 * 1024 * 100; /* 100MB */
static int64_t	 spool_max_files = 10;
static int	 spool_do_sync = 1;
static int	 spool_check_crc = 0;
static enum {
	M_FILE,
	M_MMAP
}		 spool_method = M_MMAP;

static void	 spool_set_method(conf_stanza_t *, conf_option_t *, void *, void *);

static config_schema_opt_t spool_opts[] = {
	{ "path",	OPT_TYPE_STRING,	config_simple_string,	&spool_path },
	{ "size",	OPT_TYPE_QUANTITY,	config_simple_quantity,	&spool_size },
	{ "max-files",	OPT_TYPE_NUMBER,	config_simple_number,	&spool_max_files },
	{ "sync",	OPT_TYPE_BOOLEAN,	config_simple_boolean,	&spool_do_sync },
	{ "check-crc",	OPT_TYPE_BOOLEAN,	config_simple_boolean,	&spool_check_crc },
	{ "method",	OPT_TYPE_STRING,	spool_set_method },
	{ }
};

static config_schema_stanza_t spool_stanza = {
	"spool", 0, spool_opts, NULL, NULL
};

typedef struct spool_file {
	int		 sf_fd;
	off_t		 sf_size;
	char		 sf_fname[PATH_MAX];
	unsigned char	*sf_addr;
	size_t		 sf_dsz;
} spool_file_t;

static spool_file_t	*spool_files;
static size_t		 spool_base;
static int		 spool_cur_file;

typedef struct spool_header {
	uint32_t	sa_magic;
	uint32_t	sa_len;
	uint8_t		sa_hdr_len;
	uint32_t	sa_flags;
	double		sa_emp_score;
	double		sa_phl_score;
	uint64_t	sa_crc;
} spool_header_t;

#define	SPOOL_HDR_SIZE	(4 + 4 + 1 + 4 + 8 + 8 + 8)
#define	SPOOL_MAGIC	0x4E53504C	/* NSPL */
#define	SPOOL_MAGIC_EOS	0x4E454E44	/* NEND */

static void	spool_write_size(void *);
static void	spool_verify(spool_file_t *);
static void	spool_file_open(spool_id_t, int create);
static void	spool_file_close(spool_id_t, int delete);
static ssize_t	spool_read_header(spool_file_t *, spool_offset_t, spool_header_t *);
static void	spool_write_eos(spool_file_t *, spool_offset_t);

int
spool_init()
{
	config_add_stanza(&spool_stanza);
	return 0;
}

static int
numcmp(a, b)
	void const	*a, *b;
{
	return *(spool_id_t *)a - *(spool_id_t *)b;
}

static void
spool_set_method(stz, opt, udata, arg)
	conf_stanza_t	*stz;
	conf_option_t	*opt;
	void		*udata, *arg;
{
char	*v = opt->co_value->cv_string;
	if (strcmp(v, "mmap") == 0)
		spool_method = M_MMAP;
	else if (strcmp(v, "file") == 0)
		spool_method = M_FILE;
	else
		nts_log(LOG_ERR, "\"%s\", line %d: invalid spool method \"%s\"",
			opt->co_file, opt->co_lineno, v);
}

int
spool_run()
{
spool_id_t	*files = NULL;
size_t		 nfiles = 0, i;
DIR		*dir;
struct dirent	*de;

	if (!spool_path) {
		nts_log(LOG_CRIT, "spool: spool path not set");
		return -1;
	}

	if (mkdir(spool_path, 0700) == -1 && errno != EEXIST)
		panic("spool: \"%s\": cannot create directory: %s",
			spool_path, strerror(errno));

	if ((dir = opendir(spool_path)) == NULL)
		panic("spool: \"%s\": opendir: %s", spool_path, strerror(errno));

	while (de = readdir(dir)) {
	char		*p;
	long unsigned	 n;

		if (strcmp(de->d_name, ".") == 0 ||
		    strcmp(de->d_name, "..") == 0)
			continue;

		n = strtoul(de->d_name, &p, 16);
		if (*p) {
			nts_log(LOG_WARNING, "spool: \"%s\": junk file in "
				"spool directory: %s", spool_path, de->d_name);
			continue;
		}

		files = xrealloc(files, sizeof(*files) * (nfiles + 1));
		files[nfiles] = n;
		nfiles++;
	}
	
	spool_files = xcalloc(sizeof(*spool_files), spool_max_files);

	if (nfiles) {
		/* Open an existing spool */
		qsort(files, nfiles, sizeof(*files), numcmp);
		spool_base = files[0];

		for (i = 0; i < nfiles; i++)
			spool_file_open(i, 0);

		spool_cur_file = nfiles - 1;
	} else {
		/* Create a new spool */
		spool_file_open(0, 1);
		spool_cur_file = 0;
	}
	spool_write_size(NULL);
	net_cron(10, spool_write_size, NULL);

	return 0;
}

void
spool_close(void)
{
}

int
spool_store(art)
	article_t	*art;
{
spool_file_t	*sf = &spool_files[spool_cur_file];
unsigned char	*hdr;
unsigned char	 hdrbuf[SPOOL_HDR_SIZE * 2];
size_t		 artlen = str_length(art->art_content);
int		 ret;

	if (sf->sf_size + artlen + SPOOL_HDR_SIZE*2 >= sf->sf_dsz) {
		spool_write_size(NULL);

		/* Spool file is full, rotate (if necessary) and open another one. */
		if ((spool_cur_file + 1) == spool_max_files) {
			spool_file_close(0, 1);
			spool_base++;

			bcopy(&spool_files[1], &spool_files[0],
				sizeof(spool_file_t) * (spool_max_files - 1));

			spool_file_open(spool_max_files - 1, 1);

		} else {
			spool_cur_file++;
			spool_file_open(spool_cur_file, 1);
		}

		sf = &spool_files[spool_cur_file];
	}

	if (spool_method == M_MMAP)
		hdr = sf->sf_addr + sf->sf_size;
	else
		hdr = hdrbuf;

	art->art_flags |= ART_CRC;

	int32put(hdr + 0, SPOOL_MAGIC);
	int32put(hdr + 4, artlen);
	int8put(hdr + 8, SPOOL_HDR_SIZE);
	int32put(hdr + 9, art->art_flags & ~ART_FILTERED);
	int64put(hdr + 13, art->art_emp_score * 1000);
	int64put(hdr + 21, art->art_phl_score * 1000);
	int64put(hdr + 29, crc64(str_begin(art->art_content), str_length(art->art_content)));

	if (spool_method == M_MMAP) {
		bcopy(str_begin(art->art_content), hdr + SPOOL_HDR_SIZE, artlen);
		spool_write_eos(sf, sf->sf_size + artlen + SPOOL_HDR_SIZE);
		ret = msync(hdr, SPOOL_HDR_SIZE + artlen, spool_do_sync 
			    ? MS_SYNC : MS_ASYNC);
	} else {
	struct iovec	iov[3];
	char		eos[4];
		int32put(eos, SPOOL_MAGIC_EOS);
		iov[0].iov_base = hdrbuf;
		iov[0].iov_len = SPOOL_HDR_SIZE;
		iov[1].iov_base = str_begin(art->art_content);
		iov[1].iov_len = str_length(art->art_content);
		iov[2].iov_base = eos;
		iov[2].iov_len = sizeof(eos);

		if (pwritev(sf->sf_fd, iov, 3, sf->sf_size) <
		    (iov[0].iov_len + iov[1].iov_len + iov[2].iov_len))
			panic("spool: \"%s\": write error: %s",
			      sf->sf_fname, strerror(errno));
		ret = fdatasync(sf->sf_fd);
	}

	if (ret == -1)
		panic("spool: \"%s\": cannot sync: %s", sf->sf_fname, strerror(errno));

	art->art_spool_pos.sp_id = spool_base + spool_cur_file;
	art->art_spool_pos.sp_offset = sf->sf_size;

	sf->sf_size += SPOOL_HDR_SIZE + artlen;

	return 0;
}

article_t *
spool_fetch(spid, spos)
	spool_id_t	 spid;
	spool_offset_t	 spos;
{
spool_header_t	 hdr;
char		*artdata;
str_t		 artstr;
article_t	*art;
spool_file_t	*sf;
size_t		 artloc;

	if (spid < spool_base || spid > (spool_base + spool_cur_file)) {
		errno = EINVAL;
		return NULL;
	}

	sf = &spool_files[spid - spool_base];
	if (spos + SPOOL_HDR_SIZE > sf->sf_size) {
		errno = EINVAL;
		return NULL;
	}

	spool_read_header(sf, spos, &hdr);

	if (hdr.sa_magic == SPOOL_MAGIC_EOS) {
		errno = EINVAL;
		return NULL;
	}

	if (hdr.sa_magic != SPOOL_MAGIC) {
		nts_log(LOG_WARNING, "spool: \"%s\": article at %X,%lu: "
			"bad magic", sf->sf_fname,
			(int) spid, (long unsigned) spos);
		errno = EIO;
		return NULL;
	}

	artloc = spos + hdr.sa_hdr_len;

	if (artloc + hdr.sa_len > sf->sf_size) {
		nts_log(LOG_WARNING, "spool: \"%s\": article at %.8lX/%lu goes "
			       "past end of spool file", sf->sf_fname,
			       (long unsigned) spid, (long unsigned) spos);
		errno = EIO;
		return NULL;
	}

	if (spool_method == M_MMAP) {
		artdata = (char *) sf->sf_addr + artloc;
	} else {
		artdata = xmalloc(hdr.sa_len);
		if (pread(sf->sf_fd, artdata, hdr.sa_len, artloc) < hdr.sa_len)
			panic("spool: \"%s\": read: %s",
				sf->sf_fname, strerror(errno));
	}

	if (spool_check_crc && (hdr.sa_flags & ART_CRC)) {
		if (crc64(artdata, hdr.sa_len) != hdr.sa_crc) {
			nts_log(LOG_WARNING, "spool: \"%s\": bad CRC", sf->sf_fname);
			if (spool_method == M_FILE)
				free(artdata);
			errno = EIO;
			return NULL;
		}
	}

	if (spool_method == M_MMAP)
		artstr = str_new_cl_nocopy(artdata, hdr.sa_len);
	else
		artstr = str_new_cl(artdata, hdr.sa_len);
	art = article_parse(artstr);
	str_free(artstr);
	if (spool_method == M_FILE)
		free(artdata);

	if (!art)
		return NULL;

	art->art_emp_score = hdr.sa_emp_score;
	art->art_phl_score = hdr.sa_phl_score;
	art->art_flags |= hdr.sa_flags;

	art->art_spool_pos.sp_id = spid;
	art->art_spool_pos.sp_offset = spos;
	art->art_hdr_len = hdr.sa_hdr_len;

	return art;
}

static void
spool_write_size(udata)
	void	*udata;
{
spool_file_t	*sf = &spool_files[spool_cur_file];

	if (spool_method == M_MMAP) {
		int64put(sf->sf_addr, sf->sf_size);
		if (msync(sf->sf_addr, sf->sf_size, MS_SYNC) == -1)
			panic("spool: \"%s/%.8lx\": %s",
					spool_path, (long unsigned) spool_base 
					+ spool_cur_file, strerror(errno));
	} else {
	char	szbuf[sizeof(uint64_t)];
		int64put(szbuf, sf->sf_size);
		if (pwrite(sf->sf_fd, szbuf, sizeof(szbuf), 0) < sizeof(szbuf)
		    || fdatasync(sf->sf_fd) == -1)
			panic("spool: \"%s\": write error: %s",
				sf->sf_fname, strerror(errno));
	}
}

static void
spool_verify(sf)
	spool_file_t	*sf;
{
off_t		pos;
struct stat	sb;
char		hdrbuf[SPOOL_HDR_SIZE];
ssize_t		n;

	if (fstat(sf->sf_fd, &sb) == -1)
		panic("spool: \"%s\": fstat: %s",
				sf->sf_fname, strerror(errno));

	if (sb.st_size < sf->sf_size) {
		nts_log(LOG_WARNING, "spool: \"%s\": invalid stored size, "
				"verifying entire file", sf->sf_fname);
		sf->sf_size = 8;
	}

	/*
	 * 37 bytes after sz should be an EOS header
	 */
	if ((n = pread(sf->sf_fd, hdrbuf, sizeof(hdrbuf), sf->sf_size)) == -1)
		panic("spool: \"%s\": read: %s",
			sf->sf_fname, strerror(errno));

	if (n == SPOOL_HDR_SIZE) {
		if (int32get(hdrbuf) == SPOOL_MAGIC_EOS)
			return;
	}

	nts_log(LOG_WARNING, "spool: \"%s\": unclean shutdown, "
			"verifying from %lu...", sf->sf_fname,
			(long unsigned) sf->sf_size);

	/*
	 * The most likely cause of this error (spool file longer than the
	 * stored size) is that we didn't shut down cleanly, so articles
	 * were written to the spool but the size wasn't updated.  Starting
	 * at the stored size, walk the spool and verify each article.  If
	 * we find an invalid article, assume a partial write and truncate
	 * the spool file at that point, discarding all remaining data.
	 *
	 * We can't lose articles doing this, because we fsync() after every
	 * complete article write.  The purpose of this check is to avoid
	 * half-written articles in the spool.  The article(s) we discarded will
	 * be re-sent by the remote peer eventually.
	 */
	for (pos = sf->sf_size; pos < sb.st_size;) {
	spool_header_t	 hdr;
	char		*data = NULL;

		if (pread(sf->sf_fd, hdrbuf, sizeof(hdrbuf), pos) < sizeof(hdrbuf))
			goto error;

		hdr.sa_magic = int32get(hdrbuf + 0);
		hdr.sa_len = int32get(hdrbuf + 4);
		hdr.sa_hdr_len = int8get(hdrbuf + 8);
		hdr.sa_flags = int32get(hdrbuf + 9);
		hdr.sa_emp_score = ((double) int64get(hdrbuf + 13)) / 1000;
		hdr.sa_phl_score = ((double) int64get(hdrbuf + 21)) / 1000;
		hdr.sa_crc = int64get(hdrbuf + 29);
		assert(37 == sizeof(hdrbuf));

		if (hdr.sa_magic == SPOOL_MAGIC_EOS) {
			nts_log(LOG_WARNING, "spool: \"%s\": found EOS at %lu",
					sf->sf_fname, (long unsigned) sf->sf_size);
			sf->sf_size = pos;
			return;
		}

		if (hdr.sa_magic != SPOOL_MAGIC)
			goto error;

		data = xmalloc(hdr.sa_len);
		if (pread(sf->sf_fd, data, hdr.sa_len, pos + hdr.sa_hdr_len) <
				hdr.sa_hdr_len)
			goto error;

		if (hdr.sa_flags & ART_CRC) {
			if (crc64(data, hdr.sa_len) != hdr.sa_crc)
				goto error;
		}

		free(data);
		pos += hdr.sa_hdr_len + hdr.sa_len;
		continue;

error:
		free(data);

		nts_log(LOG_WARNING, "spool: \"%s\": invalid "
			"article found at %lu",
			sf->sf_fname, (long unsigned) pos);
		sf->sf_size = pos;

		bzero(hdrbuf, sizeof(hdrbuf));
		int64put(hdrbuf, SPOOL_MAGIC_EOS);
		if (pwrite(sf->sf_fd, hdrbuf, sizeof(hdrbuf), pos) < sizeof(hdrbuf)) 
			panic("spool: \"%s\": write: %s",
					sf->sf_fname, strerror(errno));
		return;
	}

	nts_log(LOG_WARNING, "spool: \"%s\": no EOS magic at end of file",
			sf->sf_fname);

	bzero(hdrbuf, sizeof(hdrbuf));
	int64put(hdrbuf, SPOOL_MAGIC_EOS);
	if (pwrite(sf->sf_fd, hdrbuf, sizeof(hdrbuf), pos) < sizeof(hdrbuf)) 
		panic("spool: \"%s\": write: %s",
			sf->sf_fname, strerror(errno));
	sf->sf_size = pos;
}

void
spool_shutdown()
{
	spool_write_size(NULL);
}

static void
spool_file_open(num, create)
	spool_id_t	num;
{
spool_file_t	*sf = &spool_files[num];
int		 flags = O_RDWR;

	if (create)
		flags |= O_CREAT | O_EXCL;

	snprintf(sf->sf_fname, sizeof(sf->sf_fname), "%s/%.8lX", spool_path,
			(unsigned long) num + spool_base);
	if ((sf->sf_fd = open(sf->sf_fname, flags, 0600)) == -1)
		panic("spool: \"%s\" cannot %s: %s",
			sf->sf_fname, create ? "create" : "open",
			strerror(errno));

	if (create) {
	uint64_t	sz = sizeof(uint64_t);
	char		szbuf[sizeof(uint64_t)];
	char		eos[SPOOL_HDR_SIZE];

		int64put(szbuf, sz);
		if (pwrite(sf->sf_fd, szbuf, sizeof(szbuf), 0) < sizeof(szbuf))
			panic("spool: \"%s\": cannot initialise: %s",
				sf->sf_fname, strerror(errno));

		bzero(eos, sizeof(eos));
		int32put(eos, SPOOL_MAGIC_EOS);
		if (pwrite(sf->sf_fd, eos, sizeof(eos), sizeof(uint64_t)) < sizeof(eos))
			panic("spool: \"%s\": cannot initialise: %s",
				sf->sf_fname, strerror(errno));

		sf->sf_size = sz;

		if (ftruncate(sf->sf_fd, spool_size) == -1)
			panic("spool: \"%s\": ftruncate: %s",
				sf->sf_fname, strerror(errno));
		sf->sf_dsz = spool_size;
	} else {
	char		szbuf[sizeof(uint64_t)];
	struct stat	sb;
		if (pread(sf->sf_fd, szbuf, sizeof(szbuf), 0) < sizeof(szbuf))
			panic("spool: \"%s\": cannot read: %s",
					sf->sf_fname, strerror(errno));

		sf->sf_size = int64get(szbuf);
		spool_verify(sf);
		if (fstat(sf->sf_fd, &sb) == -1)
			panic("spool: \"%s\": fstat: %s",
					sf->sf_fname, strerror(errno));
		sf->sf_dsz = sb.st_size;
	}

	if (spool_method == M_MMAP) {
		if ((sf->sf_addr = mmap(NULL, sf->sf_dsz, PROT_READ | PROT_WRITE,
				MAP_FILE | MAP_SHARED, sf->sf_fd, 0))
				== MAP_FAILED)
			panic("spool: \"%s\": mmap: %s",
					sf->sf_fname, strerror(errno));
	}
}

static void
spool_file_close(num, del)
	spool_id_t	num;
	int		del;
{
spool_file_t	*sf = &spool_files[num];

	if (spool_method == M_MMAP) {
		msync(sf->sf_addr, sf->sf_size, MS_SYNC);
		munmap(sf->sf_addr, sf->sf_dsz);
	} else {
		fdatasync(sf->sf_fd);
	}

	if (ftruncate(sf->sf_fd, sf->sf_size) == -1) {
		panic("spool: \"%s\": ftruncate: %s",
			sf->sf_fname, strerror(errno));
	}

	close(sf->sf_fd);

	if (del) {
		if (unlink(sf->sf_fname) == -1)
			panic("spool: %s: cannot unlink: %s",
					sf->sf_fname, strerror(errno));
	}
}

static ssize_t
spool_read_header(sf, pos, hdr)
	spool_file_t	*sf;
	spool_offset_t	 pos;
	spool_header_t	*hdr;
{
unsigned char	*hdrbuf;
unsigned char	 rdbuf[SPOOL_HDR_SIZE];

	if (spool_method == M_MMAP)
		hdrbuf = sf->sf_addr + pos;
	else {
		hdrbuf = rdbuf;
		if (pread(sf->sf_fd, rdbuf, SPOOL_HDR_SIZE, pos) < SPOOL_HDR_SIZE)
			panic("spool: \"%s\": read: %s", sf->sf_fname,
					strerror(errno));
	}

	hdr->sa_magic = int32get(hdrbuf + 0);
	hdr->sa_len = int32get(hdrbuf + 4);
	hdr->sa_hdr_len = int8get(hdrbuf + 8);
	hdr->sa_flags = int32get(hdrbuf + 9);
	hdr->sa_emp_score = ((double) int64get(hdrbuf + 13)) / 1000;
	hdr->sa_phl_score = ((double) int64get(hdrbuf + 21)) / 1000;
	hdr->sa_crc = int64get(hdrbuf + 29);

	return SPOOL_HDR_SIZE;
}

static void
spool_write_eos(sf, pos)
	spool_file_t	*sf;
	spool_offset_t	 pos;
{
	bzero(sf->sf_addr + pos, SPOOL_HDR_SIZE);
	int32put(sf->sf_addr + pos, SPOOL_MAGIC_EOS);
}

void
spool_get_cur_pos(pos)
	spool_pos_t	*pos;
{
	pos->sp_id = spool_base + spool_cur_file;
	pos->sp_offset = spool_files[spool_cur_file].sf_size;
}
