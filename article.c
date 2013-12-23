/* RT/NTS -- a lightweight, high performance news transit server. */
/* 
 * Copyright (c) 2011 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */
/* $Header: /cvsroot/nts/article.c,v 1.22 2012/01/05 14:02:30 river Exp $ */

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

static str_t	next_line(str_t);
static int	article_classify(article_t *);
static time_t	parse_date(str_t);

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

static str_t
next_line(str)
	str_t	str;
{
ssize_t	end;
str_t	line;

	if ((end = str_find(str, "\r\n")) == -1)
		return NULL;

	line = str_copy_len(str, end);
	str_remove_start(str, end + 2);
	return line;
}

static str_t
next_group(str)
	str_t	str;
{
ssize_t	end;
str_t	line;

	if (str_length(str) == 0)
		return NULL;

	if ((end = str_find(str, ",")) == -1) {
	str_t	ret = str_copy(str);
		str_remove_start(str, str_length(str));
		return ret;
	}

	line = str_copy_len(str, end);
	str_remove_start(str, end + 1);
	return line;
}

static str_t
next_path(str)
	str_t	str;
{
ssize_t	end;
str_t	line;

	if (str_length(str) == 0)
		return NULL;

	if ((end = str_find(str, "!")) == -1) {
	str_t	ret = str_copy(str);
		str_remove_start(str, str_length(str));
		return ret;
	}

	line = str_copy_len(str, end);
	str_remove_start(str, end + 1);
	return line;
}

static str_t
next_ws(str)
	str_t	str;
{
ssize_t	end;
str_t	line;

	if (str_length(str) == 0)
		return NULL;

	if ((end = str_find_first_of(str, " \t,")) == -1) {
	str_t	ret = str_copy(str);
		str_remove_start(str, str_length(str));
		return ret;
	}

	line = str_copy_len(str, end);

	str_remove_start(str, end + 1);
	end = str_span_of(str, " \t,");
	str_remove_start(str, end);
	return line;
}

static str_t
header_name(str)
	str_t	str;
{
ssize_t	n;
str_t	name;

	if ((n = str_find_first(str, ':')) == -1)
		return NULL;

	name = str_copy_len(str, n);
	str_remove_start(str, n + 1);
	str_remove_start(str, str_span_of(str, " \t"));

	return name;
}

article_t *
article_parse(text)
	str_t	text;
{
article_t	*article;
str_t		 line = NULL, groups = NULL, body = NULL;
size_t		 n;
	
	/* Don't allow NUL in article body */
	for (n = 0; n < str_length(text); ++n) {
		if (str_index(text, n) == 0) {
			nts_log(LOG_INFO, "received article with NUL character");
			return NULL;
		}
	}

	article = bzalloc(ba_article);
	article->art_filters = (bs_word_t *) ((char *) article + sizeof(article_t));

	SIMPLEQ_INIT(&article->art_groups);
	article->art_content = str_copy(text);
	line = next_line(text);

	if (!line) {
		str_free(article->art_content);
		bfree(ba_article, article);
		return NULL;
	}

	for (;;) {
	str_t	 hdr_name = NULL, hdr_val = NULL;

		if (str_length(line) == 0)
			break;

		if ((hdr_name = header_name(line)) == NULL)
			goto err;

		hdr_val = str_copy(line);

		for (;;) {
			str_free(line);
			line = next_line(text);
			if (str_length(line) == 0 || !index(" \t", str_index(line, 0)))
				break;
			str_remove_start(line, str_span_of(line, " \t"));
			str_append_c(hdr_val, " ");
			str_append(hdr_val, line);
		}

		if (str_case_equal_c(hdr_name, "control")) {
			article->art_flags |= ART_CONTROL;
			str_free(hdr_val);
		} else if (str_case_equal_c(hdr_name, "references")) {
			article->art_flags |= ART_REPLY;
			str_free(hdr_val);
		} else if (str_case_equal_c(hdr_name, "mime-version")) {
			article->art_flags |= ART_MIME;
			str_free(hdr_val);
		} else if (str_case_equal_c(hdr_name, "content-type")) {
			if (str_find(hdr_val, "image/") != -1
			    || (str_find(hdr_val, "application/") != -1
			        && str_find(hdr_val, "application/pgp-signature") == -1
				&& str_find(hdr_val, "application/pkcs7-signature") == -1)
			    || str_find(hdr_val, "audio/") != -1
			    || str_find(hdr_val, "video/") != -1) {
				article->art_flags |= ART_TYPE_MIME_BINARY;
			} else if (str_find(hdr_val, "multipart/") != -1) {
				article->art_flags |= ART_MIME_MULTIPART;
			}
			str_free(hdr_val);
		} else if (str_case_equal_c(hdr_name, "followup-to")) {
		str_t	s;
			while (s = next_group(hdr_val)) {
				article->art_nfollowups++;
				str_free(s);
			}
			str_free(hdr_val);
		} else if (str_case_equal_c(hdr_name, "message-id")) {
			if (article->art_msgid)
				str_free(article->art_msgid);
			article->art_msgid = hdr_val;
		} else if (str_case_equal_c(hdr_name, "date")) {
			article->art_date = parse_date(hdr_val);
			str_free(hdr_val);
		} else if (str_case_equal_c(hdr_name, "path")) {
			if (article->art_path)
				str_free(article->art_path);
			article->art_path = hdr_val;
		} else if (str_case_equal_c(hdr_name, "newsgroups")) {
			if (article->art_newsgroups)
				str_free(article->art_newsgroups);
			article->art_newsgroups = hdr_val;
		} else if (str_case_equal_c(hdr_name, "nntp-posting-host")) {
			if (article->art_posting_host)
				str_free(article->art_posting_host);
			article->art_posting_host = hdr_val;
		} else if (str_case_equal_c(hdr_name, "x-original-nntp-posting-host")) {
			/*
			 * Not a real header, but seems to be present in some articles,
			 * store it for PHL use.
			 */
			if (article->art_posting_host == NULL)
				article->art_posting_host = hdr_val;
			else
				str_free(hdr_val);
		} else
			str_free(hdr_val);

		str_free(hdr_name);
	}

	str_free(line);
	line = NULL;

	if (article->art_msgid == NULL) {
		nts_log(LOG_NOTICE, "received article has no Message-ID: header");
		goto err;
	}

	if (article->art_path == NULL) {
		nts_log(LOG_NOTICE, "%.*s: article has no Path: header",
				str_printf(article->art_msgid));
		goto err;
	}

	if (article->art_newsgroups == NULL) {
		nts_log(LOG_NOTICE, "%.*s: article has no Newsgroups: header",
				str_printf(article->art_msgid));
		goto err;
	}

	if (article->art_date <= 0) {
		nts_log(LOG_NOTICE, "%.*s: invalid Date: header",
				str_printf(article->art_msgid));
		goto err;
	}

	if ((n = str_find(article->art_content, "\r\n\r\n")) == -1) {
		nts_log(LOG_NOTICE, "%.*s: article has no body",
				str_printf(article->art_msgid));
		goto err;
	}

	if (str_length(article->art_msgid) < 3 ||
	    str_length(article->art_msgid) > 250) {
		nts_log(LOG_NOTICE, "%.*s: invalid message-id",
				str_printf(article->art_msgid));
		goto err;
	}

	article->art_body = str_substr(article->art_content, n + 4, -1);
	article->art_flags |= article_classify(article);

	groups = str_copy(article->art_newsgroups);
	while (line = next_group(groups)) {
	strlist_entry_t	*ge;
		ge = bzalloc(ba_strlist);
		ge->sl_str = line;
		SIMPLEQ_INSERT_TAIL(&article->art_groups, ge, sl_list);
		article->art_ngroups++;
	}
	str_free(groups);

	body = str_copy(article->art_body);
	while (line = next_line(body)) {
		article->art_lines++;
		str_free(line);
	}
	str_free(body);

	return article;

err:
	str_free(line);
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

	str_free(art->art_path);
	str_free(art->art_msgid);
	str_free(art->art_content);
	str_free(art->art_body);
	str_free(art->art_posting_host);
	str_free(art->art_newsgroups);
	
	while (ge = SIMPLEQ_FIRST(&art->art_groups)) {
		SIMPLEQ_REMOVE_HEAD(&art->art_groups, sl_list);
		str_free(ge->sl_str);
		bfree(ba_strlist, ge);
	}

	bfree(ba_article, art);
}

void
article_munge_path(art)
	article_t	*art;
{
size_t		 path, body;
str_t		 mypath;
path_ent_t	*pe;

	if ((body = str_find(art->art_content, "\r\n\r\n")) == -1) {
		nts_log(LOG_NOTICE, "%.*s: article has no body?", str_printf(art->art_msgid));
		return;
	}

	if (bcmp(str_begin(art->art_content), "Path:", 5) == 0)
		path = 0;
	else {
		path = str_find(art->art_content, "\r\nPath:");

		if (path == -1 || path > body) {
			nts_log(LOG_NOTICE, "%.*s: article has no Path: header?", str_printf(art->art_msgid));
			return;
		}

		path += 2;
	}

	path += 5;
	while (index(" \t", str_index(art->art_content, path)))
		path++;

	mypath = str_new_c(pathhost);
	str_append_c(mypath, "!");

	SIMPLEQ_FOREACH(pe, &common_paths, pe_list) {
		if (article_path_contains(art, pe->pe_path))
			continue;
		str_append(mypath, pe->pe_path);
		str_append_c(mypath, "!");
	}

	str_insert(art->art_content, path, mypath);
	str_free(mypath);
}

static int
article_classify(art)
	article_t	*art;
{
str_t		line, body = str_copy(art->art_content);
int		ntotal = 0, nuue = 0, has_ybegin = 0, has_yend = 0;
uint32_t	ret = 0;

	while (line = next_line(body)) {
		ntotal++;

		if (str_length(line) == 0) {
			str_free(line);
			continue;
		}

		/* uuencode */
		if (str_index(line, 0) == 'M' && str_length(line) == 61) {
		size_t	i;
			for (i = 0; i < str_length(line); i++)
				if (str_index(line, i) < 32 || str_index(line, i) > 95)
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

		if (str_length(line) > 9 && bcmp(str_begin(line), "=ybegin ", 8) == 0 &&
		    str_find(line, "line=") != -1 &&
		    str_find(line, "size=") != -1 &&
		    str_find(line, "name=") != -1)
			has_ybegin++;

		if (str_length(line) > 7 && bcmp(str_begin(line), "=yend ", 6) == 0 &&
		    str_find(line, "size=") != -1)
			has_yend++;

		/* MIME multipart */
		if (art->art_flags & ART_MIME_MULTIPART) {
			if (str_length(line) >= 12 && str_find_case(line, "content-type: ") == 0) {
				if (str_find(line, "image/") != -1
				    || (str_find(line, "application/") != -1
					&& str_find(line, "application/pgp-signature") == -1
					&& str_find(line, "application/pkcs7-signature") == -1)
				    || str_find(line, "audio/") != -1
				    || str_find(line, "video/") != -1) {
					ret |= ART_TYPE_MIME_BINARY;
				} else if (str_find(line, "text/") != -1 ||
					   str_find(line, "message/") != -1)
					ret |= ART_TYPE_MIME_TEXT;
			}

		}
		str_free(line);
	}

	str_free(body);

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
parse_date(date)
	str_t	date;
{
struct tm	ret;
str_t		word = NULL;
size_t		i;

	bzero(&ret, sizeof(ret));

	/* Date: Sun, 25 Dec 2011 17:25:11 +0100 */

	/* Optional day of week, comma */
	if ((word = next_ws(date)) == NULL)
		goto err;

	if (str_length(word) >= 3)
		for (i = 0; i < sizeof(days) / sizeof(*days); i++) {
			/*
			 * Only compare the first three letters; some software generates
			 * Date: headers with the entire day name.
			 */
			if (tolower(str_index(word, 0)) == days[i][0] &&
			    tolower(str_index(word, 1)) == days[i][1] &&
			    tolower(str_index(word, 2)) == days[i][2]) {
				str_free(word);
				if ((word = next_ws(date)) == NULL)
					goto err;
				ret.tm_wday = i;
				break;
			}
		}

	/* Required day of month */
	if (str_length(word) > 2)
		goto err;

	if (str_length(word) == 2)
		ret.tm_mday = (str_index(word, 0) - '0') * 10 +
				(str_index(word, 1) - '0');
	else
		ret.tm_mday = str_index(word, 0) - '0';

	str_free(word);
	if ((word = next_ws(date)) == NULL)
		goto err;

	if (str_length(word) < 3)
		goto err;

	/* Required month */
	for (i = 0, ret.tm_mon = -1; i < sizeof(months) / sizeof(*months); i++) {
		if (tolower(str_index(word, 0)) == months[i][0] &&
		    tolower(str_index(word, 1)) == months[i][1] &&
		    tolower(str_index(word, 2)) == months[i][2]) {
			ret.tm_mon = i;
			break;
		}
	}

	if (ret.tm_mon == -1)
		goto err;

	str_free(word);
	if ((word = next_ws(date)) == NULL)
		goto err;

	/* Required year */
	if (str_length(word) != 4 && str_length(word) != 2)
		goto err;

	/*
	 * Accept two-digit year.  Yes, some user-agents actually generate this
	 * (e.g. <1112252010511@upload.hitnews.eu>).  Usenet was established in
	 * 1980, so we can assume that any 2-digit year < 80 refers to 20xx.
	 */
	if (str_length(word) == 4)
		ret.tm_year =	((str_index(word, 0) - '0') * 1000 +
				(str_index(word, 1) - '0') * 100 +
				(str_index(word, 2) - '0') * 10 +
				(str_index(word, 3) - '0')) - 1900;
	else if (str_length(word) == 2) {
		ret.tm_year = (str_index(word, 0) - '0') * 10 + (str_index(word, 1) - '0');
		if (ret.tm_year < 80)
			ret.tm_year += 100;
	}

	if (ret.tm_year < /*19*/70 || ret.tm_year > 200)
		goto err;

	str_free(word);
	if ((word = next_ws(date)) == NULL)
		goto err;

	/* Required time, HH:MM[:SS] */
	if (str_length(word) < 3)
		goto err;

	ret.tm_hour = str_index(word, 0) - '0';
	i = 1;
	if (str_index(word, i) != ':') {
		ret.tm_hour *= 10;
		ret.tm_hour += str_index(word, i) - '0';
		i++;
	}

	if (str_index(word, i) != ':')
		goto err;
	i++;

	ret.tm_min = str_index(word, i) - '0';
	i++;
	if (str_index(word, i) != ':') {
		ret.tm_min *= 10;
		ret.tm_min += str_index(word, i) - '0';
		i++;
	}

	if (i < str_length(word)) {
		i++;

		ret.tm_sec = str_index(word, i) - '0';
		i++;
		if (i < str_length(word)) {
			ret.tm_sec *= 10;
			ret.tm_sec += str_index(word, i) - '0';
		}
	}

	str_free(word);

	/* Time zone is optional (in practice) */
	if (word = next_ws(date)) {
		/*
		 * Many user-agents generate invalid timezones in messages, e.g.
		 * "GMT" (traditional), "UTC", "CST", ... just assume any
		 * timezone that isn't a number is GMT.
		 */
		if (index("+-", str_index(word, 0)) && str_length(word) == 5) {
		int	hoff, moff;
			hoff =	(str_index(word, 1) - '0') * 10 +
				(str_index(word, 2) - '0');
			moff =	(str_index(word, 3) - '0') * 10 +
				(str_index(word, 4) - '0');
			ret.tm_gmtoff = ((hoff * 60) + moff) * 60;
			if (str_index(word, 0) == '-')
				ret.tm_gmtoff = -ret.tm_gmtoff;
		}
	}

	if (ret.tm_gmtoff < -2400 || ret.tm_gmtoff > 2400)
		ret.tm_gmtoff = 0;

	ret.tm_isdst = -1;
	str_free(word);
	return mktime(&ret);

err:
	str_free(word);
	return 0;
}

int
article_path_contains(art, p)
	article_t	*art;
	str_t		 p;
{
str_t	path = str_copy(art->art_path);
str_t	e;

	while (e = next_path(path)) {
		if (str_case_equal(e, p)) {
			str_free(path);
			str_free(e);
			return 1;
		}

		str_free(e);
	}

	str_free(path);
	return 0;
}

int
valid_msgid(msgid)
	str_t	msgid;
{
int	nat = 0;
size_t	i, end;

	if (str_index(msgid, 0) != '<' || str_index(msgid, str_length(msgid) - 1) != '>')
		return 0;

	if (str_length(msgid) < 3 || str_length(msgid) > 250)
		return 0;

	for (i = 0, end = str_length(msgid); i < end; i++)
		if (str_index(msgid, i) == '@')
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
