/* RT/NTS -- a lightweight, high performance news transit server. */
/* 
 * Copyright (c) 2011, 2012 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */
/* $Header: /cvsroot/nts/bitset.h,v 1.1 2012/01/04 20:56:40 river Exp $ */

#ifndef	NTS_BITSET_H
#define	NTS_BITSET_H

/*
 * Macros for working with arbitrary-sized bitsets.
 */
#include	<stdlib.h>
#include	<limits.h>

typedef unsigned long bs_word_t;

#define	bs_bitsperword		(sizeof(bs_word_t) * CHAR_BIT)
#define	bs_nwords(nbits)	((nbits + bs_bitsperword - 1) / bs_bitsperword)
#define	bs_size(nbits)		(bs_nwords(nbits) * sizeof(bs_word_t))
#define bs_wordforbit(b)	(bs_nwords(b + 1) - 1)
#define	bs_bitinword(b)		(b % bs_bitsperword)
#define	bs_getword(bs,b)	((bs)[bs_wordforbit(b)])

#define	bs_alloc(b)		xcalloc(bs_nwords(b), sizeof(bs_word_t))
#define	bs_free(b)		free(b)

#define	bs_bit(b)		(1UL << bs_bitinword(b))
#define bs_set(bs,b)		(bs_getword(bs,b) |= bs_bit(b))
#define	bs_clear(bs,b)		(bs_getword(bs,b) &= ~bs_bit(b))
#define	bs_test(bs,b)		(bs_getword(bs,b) & bs_bit(b))

#endif	/* !NTS_BITSET_H */
