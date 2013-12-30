/* RT/NTS -- a lightweight, high performance news transit server. */
/* 
 * Copyright (c) 2011 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */
/* $Header: /cvsroot/nts/nts.h,v 1.22 2012/01/09 03:06:12 river Exp $ */

#ifndef NTS_NTS_H
#define	NTS_NTS_H

#include	<sys/uio.h>
#include	<stdlib.h>
#include	<stdarg.h>
#include	<inttypes.h>

#include	"uv.h"

#include	"queue.h"
#include	"setup.h"

#ifdef __GNUC__
# define attr_printf(x,y)	__attribute__((__format__(__printf__, (x), (y))))
# define attr_malloc		__attribute__((__malloc__))
# define attr_noreturn		__attribute__((__noreturn__))
# define attr_const		__attribute__((__const__))
# define attr_pure		__attribute__((__pure__))
#else
# define attr_printf(x,y)
# define attr_malloc
# define attr_noreturn
# define attr_const
# define attr_pure
#endif

#ifndef TEST
void	*xmalloc(size_t) attr_malloc;
void	*xrealloc(void *, size_t);
void	*xcalloc(size_t, size_t) attr_malloc;
char	*xstrdup(char const *) attr_malloc;
char	*xstrndup(char const *, size_t) attr_malloc;
#else	/* TEST */
# define	xmalloc	malloc
# define	xcalloc	calloc
# define	xrealloc	realloc
# define	xstrdup		strdup
# define	xstrndup	strndup
#endif	/* !TEST */

void	 panic(char const *, ...) attr_noreturn attr_printf(1, 2);
void	 vpanic(char const *, va_list) attr_noreturn;

void	 nts_shutdown(char const *reason);

typedef struct path_ent {
	char	*pe_path;

	SIMPLEQ_ENTRY(path_ent)	 pe_list;
} path_ent_t;

typedef SIMPLEQ_HEAD(path_list, path_ent) path_list_t;

extern uint64_t		 max_article_size;
extern int		 defer_pending;
extern char		*contact_address;
extern char		*pathhost;
extern uint64_t		 history_remember;
extern path_list_t	 common_paths;
extern int		 log_incoming_connections;
extern char		*reader_handler;
extern uint64_t		 stats_interval;
extern uint64_t		 worker_threads;
extern char		*reader_user, *reader_group;
extern uv_loop_t	*loop;
extern char		*pid_file;
extern char		*control_path;
extern uint64_t		 client_timeout;

extern char		 version_string[];
extern const char	*buildhost,
       			*builddate,
			*builder;

#ifndef HAVE_STRLCPY
size_t strlcpy(char *, const char *, size_t);
#endif

#ifndef HAVE_STRLCAT
size_t strlcat(char *dst, const char *src, size_t size);
#endif

#ifndef HAVE_ARC4RANDOM
uint32_t arc4random(void);
#endif

/*
 * Macros to store/get integers in network byte order.  Use them for storing
 * values in the database (to make it portable between systems) or when
 * accessing unaligned data.
 */
#define	int8put(buf, v)						\
	do {							\
		*((unsigned char *) buf) = 			\
			((unsigned char) v);			\
	} while (0)

#define int8get(buf) *((unsigned char *) (buf))						\

#define	int16put(buf, v)					\
	do {							\
	uint16_t	 val = (v);				\
	unsigned char	*b = (unsigned char *) (buf);		\
		*(b + 0) = (val & 0xFF00) >> 8;			\
		*(b + 1) = (val & 0x00FF) >> 0;			\
	} while (0)

#define int16get(buf)						\
	( ((uint16_t) *((unsigned char *) (buf) + 0)) << 8	\
	| ((uint16_t) *((unsigned char *) (buf) + 1)) << 0	\
	)

#define	int32put(buf, v)					\
	do {							\
	uint32_t	 val = (v);				\
	unsigned char	*b = (unsigned char *) (buf);		\
		*(b + 0) = (val & 0xFF000000) >> 24;		\
		*(b + 1) = (val & 0x00FF0000) >> 16;		\
		*(b + 2) = (val & 0x0000FF00) >> 8;		\
		*(b + 3) = (val & 0x000000FF) >> 0;		\
	} while (0)

#define int32get(buf)						\
	( ((uint32_t) *((unsigned char *) (buf) + 0)) << 24	\
	| ((uint32_t) *((unsigned char *) (buf) + 1)) << 16	\
	| ((uint32_t) *((unsigned char *) (buf) + 2)) <<  8	\
	| ((uint32_t) *((unsigned char *) (buf) + 3)) <<  0	\
	)

#define	int64put(buf, v)					\
	do {							\
	uint64_t	 val = (v);				\
	unsigned char	*b = (unsigned char *) (buf);		\
		*(b + 0) = (val & 0xFF00000000000000) >> 56;	\
		*(b + 1) = (val & 0x00FF000000000000) >> 48;	\
		*(b + 2) = (val & 0x0000FF0000000000) >> 40;	\
		*(b + 3) = (val & 0x000000FF00000000) >> 32;	\
		*(b + 4) = (val & 0x00000000FF000000) >> 24;	\
		*(b + 5) = (val & 0x0000000000FF0000) >> 16;	\
		*(b + 6) = (val & 0x000000000000FF00) >> 8;	\
		*(b + 7) = (val & 0x00000000000000FF) >> 0;	\
	} while (0)

#define int64get(buf)						\
	( ((uint64_t) *((unsigned char *) (buf) + 0)) << 56	\
	| ((uint64_t) *((unsigned char *) (buf) + 1)) << 48	\
	| ((uint64_t) *((unsigned char *) (buf) + 2)) << 40	\
	| ((uint64_t) *((unsigned char *) (buf) + 3)) << 32	\
	| ((uint64_t) *((unsigned char *) (buf) + 4)) << 24	\
	| ((uint64_t) *((unsigned char *) (buf) + 5)) << 16	\
	| ((uint64_t) *((unsigned char *) (buf) + 6)) <<  8	\
	| ((uint64_t) *((unsigned char *) (buf) + 7)) <<  0	\
	)

#define intXput(buf, v)						\
	do {							\
		switch (sizeof((v))) {				\
		case 1:	int8put((buf), (v)); break;		\
		case 2:	int16put((buf), (v)); break;		\
		case 4: int32put((buf), (v)); break;		\
		case 8: int64put((buf), (v)); break;		\
		default: abort();				\
		}						\
	} while (0)

#define intXget(buf, v)						\
	do {							\
		switch (sizeof((v))) {				\
		case 1:	(v) = int8get((buf)); break;		\
		case 2:	(v) = int16get((buf)); break;		\
		case 4: (v) = int32get((buf)); break;		\
		case 8: (v) = int64get((buf)); break;		\
		default: abort();				\
		}						\
	} while (0)

#if defined(HAVE_SYS_ATOMIC)
# define ATOMIC
# include <sys/atomic.h>
#elif defined(HAVE_GCC_ATOMIC)
# define ATOMIC
# define atomic_cas_ptr(p,o,n) __sync_val_compare_and_swap(p,o,n)
# define atomic_inc_ulong(p) __sync_fetch_and_add(p,1)
#endif

#define	ARRAY_HEAD(headname, type)					\
	struct headname {						\
		size_t	 ar_nelems;					\
		type	*ar_elems;					\
	}
#define	ARRAY_HEAD_INITIALIZER(head)	{ 0, NULL }
#define	ARRAY_INIT(head)						\
	do {								\
		bzero(&head, sizeof(head));				\
	} while (0)
#define	ARRAY_INSERT_BEFORE(head, lelm, newelm)				\
	do {								\
		head.ar_elems = xrealloc(head.ar_elems,			\
			sizeof(*head.ar_elems) *			\
			(head.ar_nelems + 1));				\
		bcopy(head.ar_elems + (lelm - head.ar_elems),		\
			head.ar_elems + (lelm - head.ar_elems) + 1,	\
			head.ar_nelems - (lelm - head.ar_elems));	\
		bcopy(newelm, head.ar_elems + (lelm - head.ar_elems),	\
				sizeof(*newelm));			\
		++head.ar_nelems;					\
	} while(0)
#define	ARRAY_INSERT_AFTER(head, lelm, newelm)				\
	ARRAY_INSERT_BEFORE(head, lelm + 1, newelm)
#define	ARRAY_INSERT_HEAD(head, newelm)					\
	ARRAY_INSERT_BEFORE(head, head.ar_elems, newelm)
#define	ARRAY_INSERT_TAIL(head, newelm)					\
	ARRAY_INSERT_AFTER(head, head.ar_elems + (head.ar_nelems - 1),	\
			newelm)
#define ARRAY_SIZE(head)	head.ar_nelems
#define	ARRAY_EMPTY(head)	(ARRAY_SIZE(head) == 0)
#define	ARRAY_FIRST(head)	(head.ar_elems)
#define	ARRAY_NEXT(head, elm)	((elm == head.ar_elems + 		\
				  (head.ar_nelems - 1)) ? NULL :	\
				 (elm + 1))
#define	ARRAY_FOREACH(var, head)					\
	for (var = ARRAY_FIRST(head); var; var = ARRAY_NEXT(head, var))	\

/*
 * Functions for (un)serializing data to byte buffers.  No attempt at error
 * handling, type detection, etc; it just puts what you give it into the
 * buffer.
 *
 * Format is a string consisting of a series of letters:
 *
 *      b               unsigned 8-bit integer (uint8_t)
 *      i, I            signed 32 or 64-bit integer (int32_t, int64_t)
 *      u, U            unsigned 32 or 64-bit integer (uint32_t, uint64_t)
 *      f               double, stored as a fixed-point number to 4 d.p.
 *                      (double)
 *      s               string, null terminated (char *)
 *      S               string, 4-byte length prefix (fray)
 *
 * For pack(), pass by value.  For unpack(), pass by pointer.
 *
 * Example:
 *      unsigned char   buf[sizeof(uint32_t) + sizeof(uint64_t)];
 *      uint32_t        i = 1;
 *      uint64_t        j = 2;
 *              pack(buf, "uU", i, j);
 *              unpack(buf, "uU", &i, &j);
 */
void	pack(unsigned char *buf, char const *fmt, ...);
void	unpack(unsigned char const *buf, char const *fmt, ...);

#ifndef HAVE_PWRITEV
ssize_t pwritev(int d, const struct iovec *iov, int iovcnt, off_t offset);
#endif

char	*next_any(char **, char const *);
#define next_word(x)	next_any((x), " \t")
#define next_bang(x)	next_any((x), "!")
#define next_comma(x)	next_any((x), ",")
char	*next_line(char **);

int	 strmatch(char const *, char const *);

typedef struct strlist_entry {
	char	*sl_str;

	SIMPLEQ_ENTRY(strlist_entry)	sl_list;
} strlist_entry_t;

typedef SIMPLEQ_HEAD(strlist, strlist_entry) strlist_t;

#ifdef	NDEBUG
#define	DEBUG(x)	0
#else	/* NDEBUG */
extern int nts_debug_flags;
#define	DEBUG_CIO	0x1
#define	DEBUG_CTL	0x2

#define	DEBUG(x)	(nts_debug_flags & (DEBUG_##x))
#endif	/* NDEBUG */

void	uv_alloc(uv_handle_t *, size_t, uv_buf_t *);

#endif	/* !NTS_NTS_H */
