/* RT/NTS -- a lightweight, high performance news transit server. */
/* 
 * Copyright (c) 2011-2013 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */

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

#include	<zlib.h>

#include	"spool.h"
#include	"config.h"
#include	"nts.h"
#include	"log.h"
#include	"crc.h"

#ifndef HAVE_FDATASYNC
# define fdatasync fsync
#endif

int		 spool_do_sync = 1;
static char	*spool_path;
static uint64_t	 spool_size = 1024 * 1024 * 100; /* 100MB */
static int64_t	 spool_max_files = 10;
static int	 spool_check_crc = 0;
static int	 spool_compress;
static enum {
	M_FILE,
	M_MMAP
} spool_method = sizeof(void *) >= 8 ? M_MMAP : M_FILE;

static void	 spool_set_method(conf_stanza_t *, conf_option_t *, void *, void *);
static void	 spool_set_compress(conf_stanza_t *, conf_option_t *, void *, void *);

static config_schema_opt_t spool_opts[] = {
	{ "path",	OPT_TYPE_STRING,	config_simple_string,	&spool_path },
	{ "size",	OPT_TYPE_QUANTITY,	config_simple_quantity,	&spool_size },
	{ "max-files",	OPT_TYPE_NUMBER,	config_simple_number,	&spool_max_files },
	{ "sync",	OPT_TYPE_BOOLEAN,	config_simple_boolean,	&spool_do_sync },
	{ "check-crc",	OPT_TYPE_BOOLEAN,	config_simple_boolean,	&spool_check_crc },
	{ "method",	OPT_TYPE_STRING,	spool_set_method },
	{ "compress",	OPT_TYPE_NUMBER,	spool_set_compress },
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

#define	SPOOL_HDR_SIZE	(4 + 4 + 1 + 4 + 8 + 8 + 8 + 4)
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

static void
spool_set_compress(stz, opt, udata, arg)
	conf_stanza_t	*stz;
	conf_option_t	*opt;
	void		*udata, *arg;
{
int	n = opt->co_value->cv_number;

	if (n < 1 || n > 9)
		nts_log(LOG_ERR, "\"%s\", line %d: compression must be between 1 and 9",
				opt->co_file, opt->co_lineno);
	spool_compress = n;
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
int		 hdrpos = 0;
size_t		 artlen = strlen(art->art_content);
int		 ret;
unsigned char	*data;
unsigned long	 datalen;

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
	art->art_flags &= ~ART_COMPRESSED;

	if (spool_compress && !(art->art_flags & ART_TYPE_YENC)) {
		datalen = compressBound(strlen(art->art_content));
		data = xmalloc(datalen);

		if (compress2(data, &datalen, (unsigned char *)art->art_content,
			      strlen(art->art_content), spool_compress) != Z_OK)
			panic("spool: compress failed");

		art->art_flags |= ART_COMPRESSED;
	} else {
		data = (unsigned char *) art->art_content;
		datalen = strlen(art->art_content);
	}

	int32put(hdr + hdrpos, SPOOL_MAGIC);			hdrpos += 4;
	int32put(hdr + hdrpos, datalen);			hdrpos += 4;
	int8put(hdr + hdrpos, SPOOL_HDR_SIZE);			hdrpos += 1;
	int32put(hdr + hdrpos, art->art_flags & ~ART_FILTERED);	hdrpos += 4;
	int64put(hdr + hdrpos, art->art_emp_score * 1000);	hdrpos += 8;
	int64put(hdr + hdrpos, art->art_phl_score * 1000);	hdrpos += 8;
	int64put(hdr + hdrpos, crc64(data, datalen));		hdrpos += 8;
	int32put(hdr + hdrpos, artlen);				hdrpos += 4;

	assert(hdrpos == SPOOL_HDR_SIZE);

	if (spool_method == M_MMAP) {
		bcopy(data, hdr + SPOOL_HDR_SIZE, datalen);
		spool_write_eos(sf, sf->sf_size + datalen + SPOOL_HDR_SIZE);
		ret = msync(hdr, SPOOL_HDR_SIZE + datalen + SPOOL_HDR_SIZE,
				spool_do_sync ? MS_SYNC : MS_ASYNC);
	} else {
	struct iovec	iov[3];
	char		eos[4];
		int32put(eos, SPOOL_MAGIC_EOS);
		iov[0].iov_base = hdrbuf;
		iov[0].iov_len = SPOOL_HDR_SIZE;
		iov[1].iov_base = data;
		iov[1].iov_len = datalen;
		iov[2].iov_base = eos;
		iov[2].iov_len = sizeof(eos);

		if (pwritev(sf->sf_fd, iov, 3, sf->sf_size) <
		    (iov[0].iov_len + iov[1].iov_len + iov[2].iov_len))
			panic("spool: \"%s\": write error: %s",
			      sf->sf_fname, strerror(errno));
		if (spool_do_sync)
			ret = fdatasync(sf->sf_fd);
		else
			ret = 0;
	}

	if (ret == -1)
		panic("spool: \"%s\": cannot sync: %s", sf->sf_fname, strerror(errno));

	if (art->art_flags & ART_COMPRESSED) {
		free(data);
		data = NULL;
	}

	art->art_spool_pos.sp_id = spool_base + spool_cur_file;
	art->art_spool_pos.sp_offset = sf->sf_size;

	sf->sf_size += SPOOL_HDR_SIZE + datalen;

	return 0;
}

article_t *
spool_fetch(spid, spos)
	spool_id_t	 spid;
	spool_offset_t	 spos;
{
spool_header_t	 hdr;
char		*text;
article_t	*art;

	if (spool_fetch_text(spid, spos, &hdr, &text) == -1)
		return NULL;

	art = article_parse(text);
	free(text);
	text = NULL;

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

int
spool_fetch_text(spid, spos, hdr, text)
	spool_id_t	  spid;
	spool_offset_t	  spos;
	spool_header_t	 *hdr;
	char		**text;
{
char		*artdata;
char		*artstr;
spool_file_t	*sf;
size_t		 artloc;

	if (spid < spool_base || spid > (spool_base + spool_cur_file)) {
		errno = EINVAL;
		return -1;
	}

	sf = &spool_files[spid - spool_base];
	if (spos + SPOOL_HDR_SIZE > sf->sf_size) {
		errno = EINVAL;
		return -1;
	}

	spool_read_header(sf, spos, hdr);

	if (hdr->sa_magic == SPOOL_MAGIC_EOS) {
		errno = EINVAL;
		return -1;
	}

	if (hdr->sa_magic != SPOOL_MAGIC) {
		nts_log(LOG_WARNING, "spool: \"%s\": article at %X,%lu: "
			"bad magic", sf->sf_fname,
			(int) spid, (long unsigned) spos);
		errno = EIO;
		return -1;
	}

	artloc = spos + hdr->sa_hdr_len;

	if (artloc + hdr->sa_len > sf->sf_size) {
		nts_log(LOG_WARNING, "spool: \"%s\": article at %.8lX/%lu goes "
			       "past end of spool file", sf->sf_fname,
			       (long unsigned) spid, (long unsigned) spos);
		errno = EIO;
		return -1;
	}

	if (spool_method == M_MMAP) {
		artdata = (char *) sf->sf_addr + artloc;
	} else {
		artdata = xmalloc(hdr->sa_len);
		if (pread(sf->sf_fd, artdata, hdr->sa_len, artloc) < hdr->sa_len)
			panic("spool: \"%s\": read: %s",
				sf->sf_fname, strerror(errno));
	}

	if (spool_check_crc && (hdr->sa_flags & ART_CRC)) {
		if (crc64(artdata, hdr->sa_len) != hdr->sa_crc) {
			nts_log(LOG_WARNING, "spool: \"%s\": bad CRC", sf->sf_fname);
			if (spool_method == M_FILE) {
				free(artdata);
				artdata = NULL;
			}
			errno = EIO;
			return -1;
		}
	}

	if (hdr->sa_flags & ART_COMPRESSED) {
	unsigned char	*data;
	unsigned long	 datasize;
	int		 ret;

		datasize = hdr->sa_text_len;
		data = xmalloc(datasize);

		if ((ret = uncompress(data, &datasize, (unsigned char *) artdata,
		                      hdr->sa_len)) != Z_OK) {
			nts_log(LOG_WARNING, "spool: \"%s\": uncompress "
					     "failed: %s", sf->sf_fname, zError(ret));

			if (spool_method == M_FILE) {
				free(artdata);
				artdata = NULL;
			}

			free(data);
			data = NULL;

			errno = EIO;
			return -1;
		}

		artstr = xmalloc(datasize + 1);
		bcopy(data, artstr, datasize);
		artstr[datasize] = 0;
		free(data);
		data = NULL;
	} else {
		artstr = xmalloc(hdr->sa_len);
		bcopy(artdata, artstr, hdr->sa_len + 1);
		artstr[hdr->sa_len] = 0;
	}

	if (spool_method == M_FILE) {
		free(artdata);
		artdata = NULL;
	}

	*text = artstr;
	return 0;
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
		data = NULL;
		pos += hdr.sa_hdr_len + hdr.sa_len;
		continue;

error:
		free(data);
		data = NULL;

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
int		 hdrpos = 0;
unsigned char	 rdbuf[SPOOL_HDR_SIZE];

	if (spool_method == M_MMAP)
		hdrbuf = sf->sf_addr + pos;
	else {
		hdrbuf = rdbuf;
		if (pread(sf->sf_fd, rdbuf, SPOOL_HDR_SIZE, pos) < SPOOL_HDR_SIZE)
			panic("spool: \"%s\": read: %s", sf->sf_fname,
					strerror(errno));
	}

	hdr->sa_magic = int32get(hdrbuf + hdrpos);				hdrpos += 4;
	hdr->sa_len = int32get(hdrbuf + hdrpos);				hdrpos += 4;
	hdr->sa_hdr_len = int8get(hdrbuf + hdrpos);				hdrpos += 1;
	hdr->sa_flags = int32get(hdrbuf + hdrpos);				hdrpos += 4;
	hdr->sa_emp_score = ((double) int64get(hdrbuf + hdrpos)) / 1000;	hdrpos += 8;
	hdr->sa_phl_score = ((double) int64get(hdrbuf + hdrpos)) / 1000;	hdrpos += 8;
	hdr->sa_crc = int64get(hdrbuf + hdrpos);				hdrpos += 8;
	hdr->sa_text_len = int32get(hdrbuf + hdrpos);				hdrpos += 4;

	assert(hdrpos == SPOOL_HDR_SIZE);

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

int
spool_check()
{
DIR		*d;
struct dirent	*de;
int		 errors = 0;

	printf("nts: checking spool files in \"%s\"...\n", spool_path);

	if ((d = opendir(spool_path)) == NULL) {
		printf("nts:    \"%s\": cannot open: %s\n", spool_path, strerror(errno));
		return 1;
	}

	while (de = readdir(d)) {
	char		path[PATH_MAX];
	struct stat	sb;
	int		fd;
	char		szbuf[sizeof(uint64_t)];
	uint64_t	spsz;
	uint64_t	bread = 0;
	uint64_t	rawbytes = 0, artbytes = 0;
	int		narts = 0;

		if (*de->d_name == '.')
			continue;

		snprintf(path, sizeof(path), "%s/%s", spool_path, de->d_name);

		if (stat(path, &sb) == -1) {
			printf("nts:    \"%s\": cannot stat: %s\n",
				path, strerror(errno));
			++errors;
			continue;
		}

		if ((fd = open(path, O_RDONLY)) == -1) {
			printf("nts:    \"%s\": cannot open: %s\n",
				path, strerror(errno));
			++errors;
			continue;
		}

		printf("\nnts:    checking \"%s\"\n", path);

		if (read(fd, szbuf, sizeof(szbuf)) < sizeof(szbuf)) {
			printf("nts:    \"%s\": cannot read header: %s\n",
				path, strerror(errno));
			++errors;
			goto next;
		}
		bread += sizeof(szbuf);

		spsz = int64get(szbuf);
		if (spsz > sb.st_size) {
			printf("nts:    \"%s\": size in header (%"PRIu64" bytes)"
				" is larger than file size (%"PRIu64" bytes)\n",
				path, spsz, sb.st_size);
			++errors;
		}

		if (pread(fd, szbuf, 4, spsz) < 4) {
			printf("nts:    \"%s\": short read on EOS header\n", path);
			++errors;
		}

		if (int32get(szbuf) != SPOOL_MAGIC_EOS) {
			printf("nts:    \"%s: no EOS header at end of file\n", path);
			++errors;
		}

		for (;;) {
		char		 hdrbuf[SPOOL_HDR_SIZE];
		int		 hdrpos = 0;
		spool_header_t	 hdr;
		char		*atext;
		uint64_t	 crc;
			if (read(fd, hdrbuf, sizeof(hdrbuf)) < sizeof(hdrbuf)) {
				printf("nts:    \"%s\": short read on header\n",
					path);
				++errors;
				goto next;
			}

			hdr.sa_magic = int32get(hdrbuf + hdrpos);                              hdrpos += 4;
			hdr.sa_len = int32get(hdrbuf + hdrpos);                                hdrpos += 4;
			hdr.sa_hdr_len = int8get(hdrbuf + hdrpos);                             hdrpos += 1;
			hdr.sa_flags = int32get(hdrbuf + hdrpos);                              hdrpos += 4;
			hdr.sa_emp_score = ((double) int64get(hdrbuf + hdrpos)) / 1000;        hdrpos += 8;
			hdr.sa_phl_score = ((double) int64get(hdrbuf + hdrpos)) / 1000;        hdrpos += 8;
			hdr.sa_crc = int64get(hdrbuf + hdrpos);                                hdrpos += 8;
			hdr.sa_text_len = int32get(hdrbuf + hdrpos);                           hdrpos += 4;

			if (hdr.sa_magic == SPOOL_MAGIC_EOS)
				goto next;

			if (hdr.sa_magic != SPOOL_MAGIC) {
				printf("nts:    \"%s\": bad magic\n",
					path);
				++errors;
				goto next;
			}

			bread += sizeof(hdrbuf);

			if (hdr.sa_len > (sb.st_size - bread)) {
				printf("nts:    \"%s\": article extends past end of file\n",
					path);
				++errors;
				goto next;
			}

			atext = malloc(hdr.sa_len);
			if (read(fd, atext, hdr.sa_len) < hdr.sa_len) {
				printf("nts:    \"%s\": short read on article text\n",
					path);
				++errors;
				free(atext);
				atext = NULL;
				goto next;
			}

			crc = crc64(atext, hdr.sa_len);
			if (crc != hdr.sa_crc) {
				printf("nts:    \"%s\": header CRC (%"PRIx64") does not match "
					"article (%"PRIx64")\n", path, crc, hdr.sa_crc);
				++errors;
				free(atext);
				atext = NULL;
				continue;
			}

			free(atext);
			atext = NULL;

			rawbytes += hdr.sa_len;
			artbytes += hdr.sa_text_len;
			++narts;
		}

	next:
		printf("nts:    \"%s\": %d articles, %"PRIu64" bytes on disk, %"PRIu64" bytes uncompressed, "
			"%.2fx ratio, %d error(s)\n",  path, narts, rawbytes, artbytes, (double)artbytes / rawbytes,
			errors);
		close(fd);
	}

	closedir(d);
	return errors;
}
