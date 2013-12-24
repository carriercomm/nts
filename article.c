/* RT/NTS -- a lightweight, high performance news transit server. */
/* 
 * Copyright (c) 2011-2013 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */

#include	<stdlib.h>
#include	<string.h>
#include	<stdio.h>
#include	<time.h>
#include	<errno.h>
#include	<ctype.h>

#include	"article.h"
#include	"nts.h"
#include	"log.h"
#include	"balloc.h"

static int	article_classify(article_t *);
static time_t	parse_date(char const *);

balloc_t	*ba_article;

void
article_init()
{
}

void
article_run()
{
	ba_article = balloc_new(sizeof(article_t) + bs_size(nfilters), 128, "article");
}

article_t *
article_parse(text_)
	char const	*text_;
{
article_t	*article;
char		*line = NULL, *groups = NULL, *groups_ = NULL, *body = NULL;
char		*text, *otext, *p;
size_t		 m;
	
	article = bzalloc(ba_article);
	article->art_filters = (bs_word_t *) ((char *) article + sizeof(article_t));

	SIMPLEQ_INIT(&article->art_groups);
	article->art_content = xstrdup(text_);

	otext = text = xstrdup(text_);
	line = next_line(&text);

	if (!line) {
		free(article->art_content);
		bfree(ba_article, article);
		free(otext);
		nts_log(LOG_INFO, "received empty article?");
		return NULL;
	}

	for (;;) {
	char	 hdr_name[128], hdr_val[512];
	char	*p;

		if (strlen(line) == 0)
			break;

		if ((p = index(line, ':')) == NULL) {
			nts_log(LOG_INFO, "article without colon in header");
			goto err;
		}

		*p++ = 0;
		while (index(" \t", *p))
			p++;

		strlcpy(hdr_name, line, sizeof(hdr_name));
		strlcpy(hdr_val, p, sizeof(hdr_val));

		for (;;) {
		char	*val;

			line = next_line(&text);
			if (strlen(line) == 0 || !index(" \t", line[0]))
				break;
		
			val = line;
			while (index(" \t", *val))
				val++;

			strlcat(hdr_val, " ", sizeof(hdr_val));
			strlcat(hdr_val, val, sizeof(hdr_val));
		}

		if (strcasecmp(hdr_name, "control") == 0) {
			article->art_flags |= ART_CONTROL;
		} else if (strcasecmp(hdr_name, "references") == 0) {
			article->art_flags |= ART_REPLY;
		} else if (strcasecmp(hdr_name, "mime-version") == 0) {
			article->art_flags |= ART_MIME;
		} else if (strcasecmp(hdr_name, "content-type") == 0) {
			if (strstr(hdr_val, "image/") != NULL
			    || (strstr(hdr_val, "application/") != NULL
			        && strstr(hdr_val, "application/pgp-signature") == NULL
				&& strstr(hdr_val, "application/pkcs7-signature") == NULL)
			    || strstr(hdr_val, "audio/") != NULL
			    || strstr(hdr_val, "video/") != NULL) {
				article->art_flags |= ART_TYPE_MIME_BINARY;
			} else if (strstr(hdr_val, "multipart/") != NULL) {
				article->art_flags |= ART_MIME_MULTIPART;
			}
		} else if (strcasecmp(hdr_name, "followup-to") == 0) {
		char	*p;
			for (p = hdr_val; *p; p++)
				if (*p == ',')
					article->art_nfollowups++;
		} else if (strcasecmp(hdr_name, "message-id") == 0) {
			free(article->art_msgid);
			article->art_msgid = xstrdup(hdr_val);
		} else if (strcasecmp(hdr_name, "date") == 0) {
			article->art_date = parse_date(hdr_val);
		} else if (strcasecmp(hdr_name, "path") == 0) {
			free(article->art_path);
			article->art_path = xstrdup(hdr_val);
		} else if (strcasecmp(hdr_name, "newsgroups") == 0) {
			free(article->art_newsgroups);
			article->art_newsgroups = xstrdup(hdr_val);
		} else if (strcasecmp(hdr_name, "nntp-posting-host") == 0) {
			free(article->art_posting_host);
			article->art_posting_host = xstrdup(hdr_val);
		} else if (strcasecmp(hdr_name, "x-original-nntp-posting-host") == 0) {
			/*
			 * Not a real header, but seems to be present in some articles,
			 * store it for PHL use.
			 */
			if (article->art_posting_host == NULL)
				article->art_posting_host = xstrdup(hdr_val);
		}
	}

	free(otext);

	text = otext = line = NULL;

	if (article->art_msgid == NULL) {
		nts_log(LOG_NOTICE, "received article has no Message-ID: header");
		goto err;
	}

	if (article->art_path == NULL) {
		nts_log(LOG_NOTICE, "%s: article has no Path: header",
				article->art_msgid);
		goto err;
	}

	if (article->art_newsgroups == NULL) {
		nts_log(LOG_NOTICE, "%s: article has no Newsgroups: header",
				article->art_msgid);
		goto err;
	}

	if (article->art_date <= 0) {
		nts_log(LOG_NOTICE, "%s: invalid Date: header",
				article->art_msgid);
		goto err;
	}

	m = strlen(article->art_msgid);
	if (m < 3 || m > 250) {
		nts_log(LOG_NOTICE, "%s: invalid message-id",
				article->art_msgid);
		goto err;
	}

	if ((p = strstr(article->art_content, "\r\n\r\n")) == NULL) {
		nts_log(LOG_NOTICE, "%s: article has no body",
				article->art_msgid);
		goto err;
	}

	article->art_body = xstrdup(p + 4);
	article->art_flags |= article_classify(article);

	groups = groups_ = xstrdup(article->art_newsgroups);
	while (line = next_any(&groups, ",")) {
	strlist_entry_t	*ge;
		ge = xcalloc(1, sizeof(*ge));
		ge->sl_str = xstrdup(line);
		SIMPLEQ_INSERT_TAIL(&article->art_groups, ge, sl_list);
		article->art_ngroups++;
	}
	free(groups_);

	for (body = article->art_body; *body; body++)
		if (*body == '\n')
			article->art_lines++;

	return article;

err:
	article_free(article);
	return NULL;
}

void
article_free(art)
	article_t	*art;
{
strlist_entry_t	*ge;

	if (!art)
		return;

	free(art->art_path);
	free(art->art_body);
	free(art->art_msgid);
	free(art->art_content);
	free(art->art_posting_host);
	free(art->art_newsgroups);
	
	while (ge = SIMPLEQ_FIRST(&art->art_groups)) {
		SIMPLEQ_REMOVE_HEAD(&art->art_groups, sl_list);
		free(ge->sl_str);
		free(ge);
	}

	bfree(ba_article, art);
}

void
article_munge_path(art)
	article_t	*art;
{
char		*path, *body;
char		 mypath[512];
path_ent_t	*pe;
size_t		 n;

	if ((body = strstr(art->art_content, "\r\n\r\n")) == NULL) {
		nts_log(LOG_NOTICE, "%s: article has no body?", art->art_msgid);
		return;
	}

	if (bcmp(art->art_content, "Path:", 5) == 0)
		path = art->art_content;
	else {
		path = strstr(art->art_content, "\r\nPath:");

		if (path == NULL || path > body) {
			nts_log(LOG_NOTICE, "%s: article has no Path: header?", art->art_msgid);
			return;
		}

		path += 2;
	}

	path += 5;
	while (*path && index(" \t", *path))
		path++;

	n = (path - art->art_content);

	strlcpy(mypath, pathhost, sizeof(mypath));
	strlcat(mypath, "!", sizeof(mypath));

	SIMPLEQ_FOREACH(pe, &common_paths, pe_list) {
		if (article_path_contains(art, pe->pe_path))
			continue;
		strlcat(mypath, pe->pe_path, sizeof(mypath));
		strlcat(mypath, "!", sizeof(mypath));
	}

	art->art_content = realloc(art->art_content, strlen(art->art_content) + strlen(mypath) + 1);
	bcopy(art->art_content + n,
	      art->art_content + n + strlen(mypath),
	      strlen(art->art_content) - n);
	bcopy(mypath, art->art_content + n, strlen(mypath));
}

static int
article_classify(art)
	article_t	*art;
{
char		*line, *body_ = xstrdup(art->art_content), *body = body_;
int		 ntotal = 0, nuue = 0, has_ybegin = 0, has_yend = 0;
uint32_t	 ret = 0;

	while (line = next_line(&body)) {
	size_t	len = strlen(line);

		ntotal++;

		if (strlen(line) == 0)
			continue;

		/* uuencode */
		if (line[0] == 'M' && len == 61) {
		size_t	i;
			for (i = 0; i < len; i++)
				if (line[i] < 32 || line[i] > 95)
					break;
			++nuue;
		}

		/*
		 * yEnc.  This is somewhat difficult to detect, since it can use
		 * nearly any 8-bit character, and line length is not standardised.
		 * To classify as yEnc, we require =ybegin and =yend, and ensure
		 * that =ybegin contains "line=", "size=" and "name=", and =yend
		 * contains "size=", as required by the yEnc specification.  This
		 * should avoid most false positives caused by discussions *about*
		 * yEnc rather than actual yEnc-encoded files.
		 */

		if (len > 9 && bcmp(line, "=ybegin ", 8) == 0 &&
		    strstr(line, "line=") != NULL &&
		    strstr(line, "size=") != NULL &&
		    strstr(line, "name=") != NULL)
			has_ybegin++;

		if (len > 7 && bcmp(line, "=yend ", 6) == 0 &&
		    strstr(line, "size=") != NULL)
			has_yend++;

		/* MIME multipart */
		if (art->art_flags & ART_MIME_MULTIPART) {
			if (len >= 12 && strcasestr(line, "content-type: ") == line) {
				if (strstr(line, "image/") != NULL
				    || (strstr(line, "application/") != NULL
					&& strstr(line, "application/pgp-signature") == NULL
					&& strstr(line, "application/pkcs7-signature") == NULL)
				    || strstr(line, "audio/") != NULL
				    || strstr(line, "video/") != NULL) {
					ret |= ART_TYPE_MIME_BINARY;
				} else if (strstr(line, "text/") != NULL ||
					   strstr(line, "message/") != NULL)
					ret |= ART_TYPE_MIME_TEXT;
			}

		}
	}

	free(body_);

	if (ntotal > 10 && (nuue >= (ntotal / 2)))
		ret |= ART_TYPE_UUE;

	if (has_ybegin && (has_ybegin == has_yend))
		ret |= ART_TYPE_YENC;

	return ret;
}

static char *days[] = { "sun", "mon", "tue", "wed", "thu", "fri", "sat" };
static char *months[] = { "jan", "feb", "mar", "apr", "may", "jun", "jul",
			"aug", "sep", "oct", "nov", "dec" };

static time_t
parse_date(date_)
	char const	*date_;
{
struct tm	 ret;
char		*word = NULL;
size_t		 i;
char		*odate = xstrdup(date_), *date = odate;

	bzero(&ret, sizeof(ret));

	/* Date: Sun, 25 Dec 2011 17:25:11 +0100 */

	/* Optional day of week, comma */
	if ((word = next_word(&date)) == NULL)
		goto err;

	if (strlen(word) >= 3)
		for (i = 0; i < sizeof(days) / sizeof(*days); i++) {
			/*
			 * Only compare the first three letters; some software generates
			 * Date: headers with the entire day name.
			 */
			if (tolower(word[0]) == days[i][0] &&
			    tolower(word[1]) == days[i][1] &&
			    tolower(word[2]) == days[i][2]) {
				if ((word = next_word(&date)) == NULL)
					goto err;
				ret.tm_wday = i;
				break;
			}
		}

	/* Required day of month */
	if (strlen(word) > 2)
		goto err;

	if (strlen(word) == 2)
		ret.tm_mday = (word[0] - '0') * 10 +
			      (word[1] - '0');
	else
		ret.tm_mday = word[0] - '0';

	if ((word = next_word(&date)) == NULL)
		goto err;

	if (strlen(word) < 3)
		goto err;

	/* Required month */
	for (i = 0, ret.tm_mon = -1; i < sizeof(months) / sizeof(*months); i++) {
		if (tolower(word[0]) == months[i][0] &&
		    tolower(word[1]) == months[i][1] &&
		    tolower(word[2]) == months[i][2]) {
			ret.tm_mon = i;
			break;
		}
	}

	if (ret.tm_mon == -1)
		goto err;

	if ((word = next_word(&date)) == NULL)
		goto err;

	/* Required year */
	if (strlen(word) != 4 && strlen(word) != 2)
		goto err;

	/*
	 * Accept two-digit year.  Yes, some user-agents actually generate this
	 * (e.g. <1112252010511@upload.hitnews.eu>).  Usenet was established in
	 * 1980, so we can assume that any 2-digit year < 80 refers to 20xx.
	 */
	if (strlen(word) == 4)
		ret.tm_year =	((word[0] - '0') * 1000 +
				 (word[1] - '0') * 100 +
				 (word[2] - '0') * 10 +
				 (word[3] - '0')) - 1900;
	else if (strlen(word) == 2) {
		ret.tm_year = (word[0] - '0') * 10 + (word[1] - '0');
		if (ret.tm_year < 80)
			ret.tm_year += 100;
	}

	if (ret.tm_year < /*19*/70 || ret.tm_year > 200)
		goto err;

	if ((word = next_word(&date)) == NULL)
		goto err;

	/* Required time, HH:MM[:SS] */
	if (strlen(word) < 3)
		goto err;

	ret.tm_hour = word[0] - '0';
	i = 1;
	if (word[i] != ':') {
		ret.tm_hour *= 10;
		ret.tm_hour += word[i] - '0';
		i++;
	}

	if (word[i] != ':')
		goto err;
	i++;

	ret.tm_min = word[i] - '0';
	i++;
	if (word[i] != ':') {
		ret.tm_min *= 10;
		ret.tm_min += word[i] - '0';
		i++;
	}

	if (i < strlen(word)) {
		i++;

		ret.tm_sec = word[i] - '0';
		i++;
		if (i < strlen(word)) {
			ret.tm_sec *= 10;
			ret.tm_sec += word[i] - '0';
		}
	}


	/* Time zone is optional (in practice) */
	if (word = next_word(&date)) {
		/*
		 * Many user-agents generate invalid timezones in messages, e.g.
		 * "GMT" (traditional), "UTC", "CST", ... just assume any
		 * timezone that isn't a number is GMT.
		 */
		if (index("+-", word[0]) && strlen(word) == 5) {
		int	hoff, moff;
			hoff =	(word[1] - '0') * 10 +
				(word[2] - '0');
			moff =	(word[3] - '0') * 10 +
				(word[4] - '0');
			ret.tm_gmtoff = ((hoff * 60) + moff) * 60;
			if (word[0] == '-')
				ret.tm_gmtoff = -ret.tm_gmtoff;
		}
	}

	if (ret.tm_gmtoff < -2400 || ret.tm_gmtoff > 2400)
		ret.tm_gmtoff = 0;

	ret.tm_isdst = -1;
	free(odate);
	return mktime(&ret);

err:
	free(odate);
	return 0;
}

int
article_path_contains(art, p)
	article_t	*art;
	char const	*p;
{
	/*
	 * XXX This is much slower than it should be - it's called for 
	 * every entry in common_path e.g. when parsing an article.
	 */
char	*path_ = xstrdup(art->art_path), *path = path_;
char	*e;

	while (e = next_any(&path, "!")) {
		if (strcasecmp(e, p) == 0) {
			free(path_);
			return 1;
		}
	}

	free(path_);
	return 0;
}

int
valid_msgid(msgid)
	char const	*msgid;
{
int	nat = 0;
size_t	i, end;
size_t	len = strlen(msgid);

	if (msgid[0] != '<' || msgid[len - 1] != '>')
		return 0;

	if (len < 3 || len > 250)
		return 0;

	for (i = 0, end = len; i < end; i++)
		if (msgid[i] == '@')
			if (++nat == 2)
				return 0;
	return 1;
}

#ifdef TEST_ARTICLE
void nts_log(int sev, char const *fmt, ...) {}
char *pathhost;

int main(argc, argv)
	char	**argv;
{
str_t	d1 = str_new_c("Sun, 25 Dec 2011 17:25:11 +0100"),
	d2 = str_new_c("Sun, 25 Dec 2011 9:06:53 -0500"),
	d3 = str_new_c("Sun, 25 Dec 2011 9:06:53"),
	d4 = str_new_c("Sun, 25 Dec 2011 9:06"),
	d5 = str_new_c("25 Dec 2011 9:06:53"),
	d6 = str_new_c("25 Dec 11 9:06:53");
time_t	t;

	printf("%.*s: ", str_printf(d1));
	if ((t = parse_date(d1)) == 0 || t != 1324833911)
		printf("failed %d\n", (int) t);
	else
		printf("passed\n");

	printf("%.*s: ", str_printf(d2));
	if ((t = parse_date(d2)) == 0 || t != 1324804013)
		printf("failed %d\n", (int) t);
	else
		printf("passed\n");

	printf("%.*s: ", str_printf(d3));
	if ((t = parse_date(d3)) <= 0 || t != 1324804013)
		printf("failed %d\n", (int) t);
	else
		printf("passed %d\n", (int) t);

	printf("%.*s: ", str_printf(d4));
	if ((t = parse_date(d4)) <= 0 || t != 1324803960)
		printf("failed %d\n", (int) t);
	else
		printf("passed %d\n", (int) t);

	printf("%.*s: ", str_printf(d5));
	if ((t = parse_date(d5)) <= 0 || t != 1324804013)
		printf("failed %d\n", (int) t);
	else
		printf("passed %d\n", (int) t);

	printf("%.*s: ", str_printf(d6));
	if ((t = parse_date(d6)) <= 0 || t != 1324804013)
		printf("failed %d\n", (int) t);
	else
		printf("passed %d\n", (int) t);

	return 0;
}
#endif
