/* RT/NTS -- a lightweight, high performance news transit server. */
/* 
 * Copyright (c) 2011 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */
/* $Header: /cvsroot/nts/str.h,v 1.10 2012/01/05 14:02:30 river Exp $ */

#ifndef	NTS_STR_H
#define	NTS_STR_H

#include	<stdlib.h>
#include	<assert.h>

#include	"nts.h"
#include	"balloc.h"

#define	STR_IMMUTABLE	0x1
#define	STR_NOBALLOC	0x2

typedef unsigned char strchar_t;

typedef struct str_base {
	union {
		strchar_t	*sbu_addr;
		struct str_base	*sbu_next;
	}		 sb_ptr;
	size_t		 sb_len;
	int		 sb_flags;
	int		 sb_refs;

	struct str_base	*sb_next;
#define	sb_next	sb_ptr.sbu_next
#define sb_addr	sb_ptr.sbu_addr
} strbase_t;

typedef struct str {
	union {
		strbase_t	*su_base;
		struct str	*su_next;
	}		 s_ptr;
	size_t		 s_offset;
	size_t		 s_len;
#define	s_base	s_ptr.su_base
#define s_next	s_ptr.su_next
} *str_t;
typedef struct str const *cstr_t;

typedef struct strlist_entry {
	str_t				 sl_str;
	SIMPLEQ_ENTRY(strlist_entry)	 sl_list;
} strlist_entry_t;

extern balloc_t	*ba_strlist;

typedef SIMPLEQ_HEAD(strlist, strlist_entry) strlist_t;

#define str_begin(s)	((s)->s_base->sb_addr + (s)->s_offset)
#define str_end(s)	((s)->s_base->sb_addr + (s)->s_offset + (s)->s_len)

void	 str_init(void);

str_t	 str_new(void) attr_malloc;
str_t	 str_new_c(char const *) attr_malloc;
str_t	 str_new_cl(char const *, size_t) attr_malloc;
str_t	 str_new_cl_nocopy(char const *s, size_t) attr_malloc;
str_t	 str_new_cl_take(char const *s, size_t) attr_malloc;
str_t	 str_copy(cstr_t) attr_malloc;
str_t	 str_copy_len(cstr_t, size_t) attr_malloc;
void	 str_unimmutify(str_t);
void	 str_free_impl(str_t);
#define	 str_free(str)	do { if (str) str_free_impl(str); } while (0)

void	 str_append(str_t, cstr_t);
void	 str_append_c(str_t, char const *);
void	 str_append_cl(str_t, char const *, size_t);
void	 str_append_s(str_t, cstr_t);

void	 str_insert(str_t, size_t where, cstr_t);
void	 str_insert_c(str_t, size_t where, char const *s);
void	 str_insert_cl(str_t, size_t where, char const *s, size_t);

int	 str_compare(cstr_t, cstr_t) attr_pure;
int	 str_compare_c(cstr_t, char const *) attr_pure;
int	 str_case_compare(cstr_t, cstr_t) attr_pure;
int	 str_case_compare_c(cstr_t, char const *) attr_pure;

ssize_t	 str_write(cstr_t, int fd);

#define	str_equal_c(a,b)	(str_compare_c((a), (b)) == 0)
#define	str_equal(a,b)		(str_compare((a), (b)) == 0)
#define	str_case_equal_c(a,b)	(str_case_compare_c((a), (b)) == 0)
#define	str_case_equal(a,b)	(str_case_compare((a), (b)) == 0)

ssize_t	 str_find(cstr_t, char const *) attr_pure;
ssize_t	 str_find_case(cstr_t, char const *) attr_pure;
ssize_t	 str_find_first(cstr_t, int) attr_pure;
ssize_t	 str_find_first_of(cstr_t, char const *) attr_pure;
ssize_t	 str_find_first_not(cstr_t, int) attr_pure;
ssize_t	 str_find_first_not_of(cstr_t, char const *) attr_pure;
ssize_t	 str_span_of(cstr_t, char const *) attr_pure;
ssize_t	 str_span_not_of(cstr_t, char const *) attr_pure;

int	 str_match(cstr_t, cstr_t) attr_pure;
int	 str_match_cl(cstr_t, char const *, size_t) attr_pure;
int	 str_match_c(cstr_t, char const *) attr_pure;

str_t	 str_substr(cstr_t, size_t start, size_t len) attr_malloc;
str_t	 str_next_word(str_t) attr_malloc;

/* Use with %*s:  printf("foo = %*s\n", str_printf(str)); */
#define	str_printf(str)		(int) (str)->s_len, str_begin(str)

#define	str_index(str, n)	(*(str_begin(str) + (n)))
#define	str_length(str)		((str)->s_len)

#define	str_remove_start(str, n)		\
	do {					\
		assert(n >= 0);			\
		assert(n <= (str)->s_len);	\
		(str)->s_len -= n; 		\
		(str)->s_offset += n; 		\
	} while (0)
#define str_remove_end(str, n)			\
	do {					\
		assert(n >= 0);			\
		assert(n <= (str)->s_len);	\
	       	(str)->s_len -= n;		\
       	} while (0)

#endif	/* !NTS_STR_H */
