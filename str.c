/* RT/NTS -- a lightweight, high performance news transit server. */
/* 
 * Copyright (c) 2011 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */
/* $Header: /cvsroot/nts/str.c,v 1.18 2012/01/08 22:33:55 river Exp $ */

#include	<string.h>
#include	<strings.h>
#include	<ctype.h>
#include	<stdio.h>
#include	<unistd.h>
#include	<assert.h>

#include	"nts.h"
#include	"str.h"
#include	"balloc.h"

#ifdef TEST_STR
# define	xmalloc		malloc
# define	xcalloc		calloc
# define	xrealloc	realloc
#endif

static balloc_t	*ba_str, *ba_base;
balloc_t	*ba_strlist;

static void		 base_deref(strbase_t *);
static int		 str_match_impl(strchar_t const *, strchar_t const *, strchar_t const *, strchar_t const *);

balloc_t	*ba_str_128,
		*ba_str_4096,
		*ba_str_16384,
		*ba_str_65535;

void
str_init()
{
	ba_str = balloc_new(sizeof(struct str), 1024, "str");
	ba_base = balloc_new(sizeof(strbase_t), 1024, "strbase");
	ba_strlist = balloc_new(sizeof(strlist_entry_t), 1024, "strlist");
	ba_str_128 = balloc_new(128, 1024, "str_128");
	ba_str_4096 = balloc_new(4096, 1024, "str_4096");
	ba_str_16384 = balloc_new(16384, 1024, "str_16384");
	ba_str_65535 = balloc_new(65535, 1024, "str_65535");
}

static strchar_t *
str_alloc(len)
	size_t	len;
{
	if (len <= 128)
		return balloc(ba_str_128);
	else if (len <= 4096)
		return balloc(ba_str_4096);
	else if (len <= 16384)
		return balloc(ba_str_16384);
	else if (len <= 65535)
		return balloc(ba_str_65535);
	else
		return xmalloc(len);
}

void
str_dealloc(p, len)
	strchar_t	*p;
	size_t		 len;
{
	if (!p) {
		assert(len == 0);
		return;
	}

	if (len <= 128)
		bfree(ba_str_128, p);
	else if (len <= 4096)
		bfree(ba_str_4096, p);
	else if (len <= 16384)
		bfree(ba_str_16384, p);
	else if (len <= 65535)
		bfree(ba_str_65535, p);
	else
		free(p);
}


str_t
str_new()
{
strbase_t	*base;
str_t		 str;
	base = bzalloc(ba_base);
	str = bzalloc(ba_str);
	base->sb_refs = 1;
	str->s_base = base;
	return str;
}

str_t
str_new_c(s)
	char const	*s;
{
	assert(s);

	return str_new_cl(s, strlen(s));
}

str_t
str_new_cl(s, len)
	char const	*s;
	size_t		 len;
{
strbase_t	*base;
str_t		 str;

	assert(s);
	assert(len >= 0);

	base = bzalloc(ba_base);
	str = bzalloc(ba_str);

	str->s_base = base;
	str->s_len = len;

	base->sb_refs = 1;
	if (len) {
		base->sb_addr = str_alloc(len);
		bcopy(s, base->sb_addr, len);
		base->sb_len = len;
	}
	return str;
}

str_t
str_new_cl_nocopy(s, len)
	char const	*s;
	size_t		 len;
{
strbase_t	*base;
str_t		 str;
	assert(s);
	assert(len >= 0);

	base = bzalloc(ba_base);
	str = bzalloc(ba_str);

	str->s_base = base;
	str->s_len = len;

	base->sb_refs = 1;
	base->sb_len = len;
	base->sb_addr = (strchar_t *) s;
	base->sb_flags |= STR_IMMUTABLE;
	return str;
}

str_t
str_new_cl_take(s, len)
	char const	*s;
	size_t		 len;
{
strbase_t	*base;
str_t		 str;
	assert(s);
	assert(len >= 0);

	base = bzalloc(ba_base);
	str = bzalloc(ba_str);

	str->s_base = base;
	str->s_len = len;

	base->sb_refs = 1;
	base->sb_len = len;
	base->sb_addr = (strchar_t *) s;
	base->sb_flags = STR_NOBALLOC;
	return str;
}

void
str_free_impl(str)
	str_t	str;
{
	base_deref(str->s_base);
	bfree(ba_str, str);
}

void
base_deref(base)
	strbase_t	*base;
{
	assert(base->sb_refs >= 1);

	if (--base->sb_refs)
		return;

	if (!(base->sb_flags & STR_IMMUTABLE)) {
		if (base->sb_flags & STR_NOBALLOC)
			free(base->sb_addr);
		else
			str_dealloc(base->sb_addr, base->sb_len);
	}

	bfree(ba_base, base);
}

str_t
str_copy(str)
	cstr_t	str;
{
str_t		 copy;

	assert(str);

	copy = balloc(ba_str);
	bcopy(str, copy, sizeof(*copy));
	++copy->s_base->sb_refs;
	return copy;
}

str_t
str_copy_len(str, n)
	cstr_t	str;
	size_t	n;
{
str_t	copy;

	assert(str);
	assert(n >= 0 && n <= str->s_len);

	copy = str_copy(str);
	copy->s_len = n;
	return copy;
}

void
str_append(a, b)
	str_t	a;
	cstr_t	b;
{
strbase_t	*base;
strchar_t	*as;

	assert(a);
	assert(b);

	str_unimmutify(a);

	base = a->s_base;
	
	as = str_alloc(str_length(a) + str_length(b));
	bcopy(str_begin(a), as, str_length(a));
	bcopy(str_begin(b), as + str_length(a), str_length(b));

	if (base->sb_flags & STR_NOBALLOC)
		free(base->sb_addr);
	else
		str_dealloc(base->sb_addr, base->sb_len);

	base->sb_flags &= ~STR_NOBALLOC;
	base->sb_addr = as;
	base->sb_len = a->s_len + str_length(b);
	a->s_offset = 0;
	a->s_len += str_length(b);
}

void
str_append_cl(str, s, len)
	str_t		 str;
	char const	*s;
	size_t		 len;
{
strbase_t	*base;
strchar_t	*a;

	assert(str);
	assert(s);
	assert(len >= 0);

	str_unimmutify(str);
	
	base = str->s_base;
	
	a = str_alloc(str_length(str) + len);
	bcopy(str_begin(str), a, str_length(str));
	bcopy(s, a + str_length(str), len);

	if (base->sb_flags & STR_NOBALLOC)
		free(base->sb_addr);
	else
		str_dealloc(base->sb_addr, base->sb_len);
	base->sb_flags &= ~STR_NOBALLOC;

	base->sb_addr = a;
	base->sb_len = str->s_len + len;
	str->s_offset = 0;
	str->s_len += len;
}

void
str_append_c(str, s)
	str_t		 str;
	char const	*s;
{
	assert(str);
	assert(s);

	str_append_cl(str, s, strlen(s));
}

void
str_insert(str, where, what)
	str_t	str;
	cstr_t	what;
	size_t	where;
{
strchar_t	*newstr;

	assert(where >= 0 && where <= str_length(str));
	assert(str);
	assert(what);

	str_unimmutify(str);

	newstr = str_alloc(str_length(str) + str_length(what));
	bcopy(str_begin(str), newstr, where);
	bcopy(str_begin(what), newstr + where, str_length(what));
	bcopy(str_begin(str) + where, newstr + where + str_length(what), str_length(str) - where);

	if (str->s_base->sb_flags & STR_NOBALLOC)
		free(str->s_base->sb_addr);
	else
		str_dealloc(str->s_base->sb_addr, str->s_base->sb_len);
	str->s_base->sb_flags &= ~STR_NOBALLOC;

	str->s_base->sb_addr = newstr;
	str->s_base->sb_len = str->s_len + what->s_len;
	str->s_len += str_length(what);
	str->s_offset = 0;
}

void
str_insert_cl(str, where, what, len)
	str_t		 str;
	size_t		 where, len;
	char const	*what;
{
strchar_t	*newstr;

	assert(str);
	assert(len >= 0);
	assert(what);
	assert(where >= 0 && where <= str_length(str));

	str_unimmutify(str);

	newstr = str_alloc(str_length(str) + len);
	bcopy(str_begin(str), newstr, where);
	bcopy(what, newstr + where, len);
	bcopy(str_begin(str) + where, newstr + where + len, str_length(str) - where);

	if (str->s_base->sb_flags & STR_NOBALLOC)
		free(str->s_base->sb_addr);
	else
		str_dealloc(str->s_base->sb_addr, str->s_base->sb_len);
	str->s_base->sb_flags &= ~STR_NOBALLOC;

	str->s_base->sb_addr = newstr;
	str->s_base->sb_len = str->s_len + len;
	str->s_len += len;
	str->s_offset = 0;
}

void
str_insert_c(str, where, what)
	str_t		 str;
	size_t		 where;
	char const	*what;
{
	assert(str);
	assert(where >= 0);
	assert(what);

	str_insert_cl(str, where, what, strlen(what));
}

void
str_unimmutify(str)
	str_t	str;
{
strbase_t	*base;

	if (!(str->s_base->sb_flags & STR_IMMUTABLE) && str->s_base->sb_refs == 1)
		return;

	base = bzalloc(ba_base);
	base->sb_flags = 0;
	base->sb_refs = 1;
	base->sb_len = str->s_len;
	if (base->sb_len) {
		base->sb_addr = str_alloc(str->s_len);
		bcopy(str_begin(str), base->sb_addr, str->s_len);
	}

	base_deref(str->s_base);
	str->s_base = base;
	str->s_offset = 0;
}

ssize_t
str_find(str, s)
	cstr_t		 str;
	char const	*s;
{
unsigned char	 c = *(unsigned char *)s,
		*rest = (unsigned char *)s + 1,
		*pos = str_begin(str),
		*loc,
		*end = str_end(str);
size_t		 rlen = strlen(s + 1);

	while (loc = memchr(pos, c, end - pos)) {
		if ((loc + 1 + rlen) > end)
			return -1;
		if (memcmp(loc + 1, rest, rlen) == 0)
			return loc - str_begin(str);
		pos = loc + 1;
	}

	return -1;
}

ssize_t
str_find_case(str, s)
	cstr_t		 str;
	char const	*s;
{
size_t	loc;

	for (loc = 0; loc < str_length(str); loc++) {
	char const	*p = s;
	size_t		 loc2 = loc;
		while (tolower(str_index(str, loc2++)) == tolower((unsigned char) *p++))
			if (*p == '\0')
				return loc;
	}

	return -1;
}

ssize_t
str_find_first(str, c)
	cstr_t	str;
	int	c;
{
strchar_t	*s, *end;
	for (s = str_begin(str), end = str_end(str); s < end; s++)
		if (*s == (strchar_t) c)
			return s - str_begin(str);
	return -1;
}

ssize_t
str_find_first_of(str, c)
	cstr_t		 str;
	char const	*c;
{
strchar_t	*s, *end;
	for (s = str_begin(str), end = str_end(str); s < end; s++)
		if (index(c, *s))
			return s - str_begin(str);
	return -1;
}

ssize_t
str_find_first_not(str, c)
	cstr_t	str;
	int	c;
{
strchar_t	*s, *end;
	for (s = str_begin(str), end = str_end(str); s < end; s++)
		if (*s != c)
			return s - str_begin(str);
	return -1;
}

ssize_t
str_find_first_not_of(str, c)
	cstr_t		 str;
	char const	*c;
{
strchar_t	*s, *end;
	for (s = str_begin(str), end = str_end(str); s < end; s++)
		if (!index(c, *s))
			return s - str_begin(str);
	return -1;
}

ssize_t
str_span_of(str, c)
	cstr_t		str;
	char const	*c;
{
strchar_t	*s, *end;
	for (s = str_begin(str), end = str_end(str); s < end; s++)
		if (!index(c, *s))
			return s - str_begin(str);
	return str->s_len;
}

ssize_t
str_span_not_of(str, c)
	cstr_t		str;
	char const	*c;
{
strchar_t	*s, *end;
	for (s = str_begin(str), end = str_end(str); s < end; s++)
		if (index(c, *s))
			return s - str_begin(str);
	return str->s_len;
}

int
str_compare(a, b)
	cstr_t	a, b;
{
size_t	n = 0; 
	for (;;) {
		if (str_index(a, n) != str_index(b, n))
			return str_index(a, n) - str_index(b, n);
		if (str_length(a) == str_length(b) && str_length(b) == (n + 1))
			return 0;
		if (str_length(a) == (n + 1))
			return str_index(a, n) - 0;
		else if (str_length(b) == (n + 1))
			return 0 - str_index(b, n);
		n++;
	}
}

int
str_compare_c(a, b)
	cstr_t		 a;
	char const	*b;
{
size_t	n = 0; 
	for (;;) {
		if (str_index(a, n) != b[n])
			return str_index(a, n) - (unsigned char) b[n];
		if (str_length(a) == (n + 1) && b[n + 1] == 0)
			return 0;
		if (str_length(a) == (n + 1))
			return str_index(a, n) - 0;
		else if (b[n + 1] == 0)
			return 0 - (unsigned char) b[n];
		n++;
	}
}

int
str_case_compare(a, b)
	cstr_t	a, b;
{
size_t	n = 0; 
	for (;;) {
	char	ac = tolower(str_index(a, n)),
		bc = tolower(str_index(b, n));

		if (ac != bc)
			return ac - bc;
		if (str_length(a) == str_length(b) && str_length(b) == (n + 1))
			return 0;
		if (str_length(a) == (n + 1))
			return ac - 0;
		else if (str_length(b) == (n + 1))
			return 0 - bc;
		n++;
	}
}

int
str_case_compare_c(a, b)
	cstr_t		 a;
	char const	*b;
{
size_t	n = 0; 
	for (;;) {
	strchar_t	ac = tolower(str_index(a, n)),
			bc = tolower((unsigned char) b[n]);

		if (ac != bc)
			return ac - bc;
		if (str_length(a) == (n + 1) && b[n + 1] == 0)
			return 0;
		if (str_length(a) == (n + 1))
			return ac - 0;
		else if (b[n + 1] == 0)
			return 0 - bc;
		n++;
	}
}

ssize_t
str_write(str, fd)
	cstr_t	str;
{
ssize_t	n;
	n = write(fd, str_begin(str), str_length(str));
	return n;
}

str_t
str_substr(str, start, len)
	cstr_t	str;
	size_t	start, len;
{
str_t	ret = str_copy(str);
	ret->s_offset += start;

	if (len != -1)
		ret->s_len = len;
	else
		ret->s_len = str->s_len - start;

	return ret;
}

int
str_match(str, pattern)
	cstr_t	str, pattern;
{
	return str_match_impl(str_begin(str), str_end(str),
			str_begin(pattern), str_end(pattern));
}

int
str_match_cl(str, pattern, len)
	cstr_t		 str;
	char const	*pattern;
	size_t		 len;
{
	return str_match_impl(str_begin(str), str_end(str),
			(strchar_t *) pattern, (strchar_t *) pattern + len);
}

int
str_match_c(str, pattern)
	cstr_t		 str;
	char const	*pattern;
{
	return str_match_cl(str, pattern, strlen(pattern));
}

str_t
str_next_word(str)
	str_t	str;
{
ssize_t	n;
str_t	ret;

	str_remove_start(str, str_span_of(str, " \t"));

	if (str_length(str) == 0)
		return NULL;

	n = str_span_not_of(str, " \t");

	ret = str_copy_len(str, n);
	str_remove_start(str, n);

	return ret;
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

static strchar_t const	*rangematch(strchar_t const *, strchar_t const *, int);

static int
str_match_impl(str, strend, pattern, patend)
	strchar_t const	*str, *strend, *pattern, *patend;
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
				if (str_match_impl(str, strend, pattern, patend))
					return 1;
				str++;
			}

		case '[':
			if (str == strend)
				return 0;
			if ((pattern = rangematch(pattern, patend, tolower(*str))) == NULL)
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

static strchar_t const *
rangematch(pattern, patend, test)
	strchar_t const	*pattern, *patend;
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

#ifdef TEST_STR
int
main(argc, argv)
	char	**argv;
{
str_t	a, b, c1, c2, c3;
ssize_t	n;
int	i;

	c1 = str_new_c("ello, worl");
	c2 = str_new_c("a");
	c3 = str_new_c("z");

#define PASS(c) ((c) ? "PASS" : "FAIL")

	a = str_new_c("hello");			printf("create new string: %s [%.*s] (expected = [hello])\n",
							PASS((str_equal_c(a, "hello"))), str_printf(a));
	str_append_c(a, ", world");		printf("append string:     %s [%.*s] (expected = [hello, world])\n",
							PASS((str_equal_c(a, "hello, world"))), str_printf(a));
	str_remove_start(a, 1);			printf("remove start:      %s [%.*s] (expected = [ello, world])\n",
							PASS((str_equal_c(a, "ello, world"))), str_printf(a));
	str_remove_end(a, 1);			printf("remove end:        %s [%.*s] (expected = [ello, worl])\n", 
							PASS((str_equal_c(a, "ello, worl"))), str_printf(a));
	n = str_compare(a, c1);			printf("compare 1:         %s %d (expected = 0)\n", PASS(n == 0), (int) n);
	n = str_compare(a, c2);			printf("compare 2:         %s %d (expected > 0)\n", PASS(n > 0), (int) n);
	n = str_compare(a, c3);			printf("compare 3:         %s %d (expected < 0)\n", PASS(n < 0), (int) n);
	n = str_compare_c(a, "ello, worl");	printf("compare_c 1:       %s %d (expected = 0)\n", PASS(n == 0), (int) n);
	n = str_compare_c(a, "a");		printf("compare_c 2:       %s %d (expected > 0)\n", PASS(n > 0), (int) n);
	n = str_compare_c(a, "z");		printf("compare_c 3:       %s %d (expected < 0)\n", PASS(n < 0), (int) n);
	n = str_find(a, "orl");			printf("find:              %s %d (expected = 7)\n", PASS(n == 7), (int) n);
	n = str_find_case(a, "oRl");		printf("find_case:         %s %d (expected = 7)\n", PASS(n == 7), (int) n);
	n = str_find_first(a, 'o');		printf("find_first:        %s %d (expected = 3)\n", PASS(n == 3), (int) n);
	n = str_find_first_of(a, "zqo");	printf("find_first_of:     %s %d (expected = 3)\n", PASS(n == 3), (int) n);
	n = str_find_first_not(a, 'e');		printf("find_first_not:    %s %d (expected = 1)\n", PASS(n == 1), (int) n);
	n = str_find_first_not_of(a, "elo");	printf("find_first_not_of: %s %d (expected = 4)\n", PASS(n == 4), (int) n);
	n = str_span_of(a, "e");		printf("span_of:           %s %d (expected = 1)\n", PASS(n == 1), (int) n);
	n = str_span_of(a, "z");		printf("span_of 2:         %s %d (expected = 0)\n", PASS(n == 0), (int) n);
	n = str_span_not_of(a, "o");		printf("span_not_of:       %s %d (expected = 3)\n", PASS(n == 3), (int) n);
	n = str_span_not_of(a, "z");		printf("span_not_of 2:     %s %d (expected = 10)\n", PASS(n == 10), (int) n);
	b = str_substr(a, 2, 4);		printf("substr 1:          %s [%.*s] (expected = [lo, ])\n",
							PASS((str_equal_c(b, "lo, "))), str_printf(b));
	b = str_substr(a, 3, -1);		printf("substr 2:          %s [%.*s] (expected = [o, worl])\n",
							PASS((str_equal_c(b, "o, worl"))), str_printf(b));
	str_append_c(a, ", world");		printf("append string:     %s [%.*s] (expected = [ello, worl, world])\n",
							PASS((str_equal_c(a, "ello, worl, world"))), str_printf(a));
	str_insert_c(a, 3, "test");		printf("insert:            %s [%.*s] (expected = [elltesto, worl, world])\n",
							PASS((str_equal_c(a, "elltesto, worl, world"))), str_printf(a));
	i = str_match_c(a, "elltest*");		printf("match 1:           %s %d (expected = 1)\n", PASS(i == 1), i);
	i = str_match_c(a, "el?t*ld");		printf("match 2:           %s %d (expected = 1)\n", PASS(i == 1), i);
	i = str_match_c(a, "el?t*lq");		printf("match 3:           %s %d (expected = 0)\n", PASS(i == 0), i);
	i = str_match_c(a, "elltesto, worl, world");	printf("match 4:           %s %d (expected = 1)\n", PASS(i == 1), i);
	i = str_match_c(a, "[ez][ql]*");	printf("match 5:           %s %d (expected = 1)\n", PASS(i == 1), i);
	i = str_match_c(a, "?[el]?[qt]*[qd]");	printf("match 6:           %s %d (expected = 1)\n", PASS(i == 1), i);
	i = str_match_c(a, "?[qz]?[qt]*[qd]");	printf("match 7:           %s %d (expected = 0)\n", PASS(i == 0), i);
	str_insert(a, 3, c1);		printf("insert:            %s [%.*s] (expected = [ellello, worltesto, worl, world])\n",
							PASS((str_equal_c(a, "ellello, worltesto, worl, world"))), str_printf(a));
	return 0;
}
#endif
