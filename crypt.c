/* RT/NTS -- a lightweight, high performance news transit server. */
/* 
 * Copyright (c) 2011, 2012 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */
/* $Header: /cvsroot/nts/crypt.c,v 1.2 2012/01/04 06:19:24 river Exp $ */

/*
 * This provides implementations of DES, MD5, Blowfish and SHA-1 crypted
 * passwords.  From NetBSD.
 */

#include	<sys/types.h>
#include	<sys/time.h>

#include	<limits.h>
#include	<pwd.h>
#include	<stdlib.h>
#include	<unistd.h>
#include	<stdio.h>
#include	<errno.h>
#include	<string.h>
#include	<time.h>
#include	<inttypes.h>
#include	<fcntl.h>

#include	"crypt.h"
#include	"nts.h"

#ifndef HAVE_ARC4RANDOM
uint32_t	arc4random(void);
#endif

static const unsigned char itoa64[] =		/* 0 ... 63 => ascii - 64 */
	"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

static void
nts_crypt_to64(char *s, u_int32_t v, int n)
{

	while (--n >= 0) {
		*s++ = itoa64[v & 0x3f];
		v >>= 6;
	}
}

/*	$NetBSD: crypt.c,v 1.26 2007/01/17 23:24:22 hubertf Exp $	*/
/*
 * Copyright (c) 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Tom Truscott.
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

/*
 * UNIX password, and DES, encryption.
 * By Tom Truscott, trt@rti.rti.org,
 * from algorithms by Robert W. Baldwin and James Gillogly.
 *
 * References:
 * "Mathematical Cryptology for Computer Scientists and Mathematicians,"
 * by Wayne Patterson, 1987, ISBN 0-8476-7438-X.
 *
 * "Password Security: A Case History," R. Morris and Ken Thompson,
 * Communications of the ACM, vol. 22, pp. 594-597, Nov. 1979.
 *
 * "DES will be Totally Insecure within Ten Years," M.E. Hellman,
 * IEEE Spectrum, vol. 16, pp. 32-39, July 1979.
 */

/* =====  Configuration ==================== */

/*
 * define "MUST_ALIGN" if your compiler cannot load/store
 * long integers at arbitrary (e.g. odd) memory locations.
 * (Either that or never pass unaligned addresses to des_cipher!)
 */
#define	MUST_ALIGN

/* ==================================== */

/*
 * Cipher-block representation (Bob Baldwin):
 *
 * DES operates on groups of 64 bits, numbered 1..64 (sigh).  One
 * representation is to store one bit per byte in an array of bytes.  Bit N of
 * the NBS spec is stored as the LSB of the Nth byte (index N-1) in the array.
 * Another representation stores the 64 bits in 8 bytes, with bits 1..8 in the
 * first byte, 9..16 in the second, and so on.  The DES spec apparently has
 * bit 1 in the MSB of the first byte, but that is particularly noxious so we
 * bit-reverse each byte so that bit 1 is the LSB of the first byte, bit 8 is
 * the MSB of the first byte.  Specifically, the 64-bit input data and key are
 * converted to LSB format, and the output 64-bit block is converted back into
 * MSB format.
 *
 * DES operates internally on groups of 32 bits which are expanded to 48 bits
 * by permutation E and shrunk back to 32 bits by the S boxes.  To speed up
 * the computation, the expansion is applied only once, the expanded
 * representation is maintained during the encryption, and a compression
 * permutation is applied only at the end.  To speed up the S-box lookups,
 * the 48 bits are maintained as eight 6 bit groups, one per byte, which
 * directly feed the eight S-boxes.  Within each byte, the 6 bits are the
 * most significant ones.  The low two bits of each byte are zero.  (Thus,
 * bit 1 of the 48 bit E expansion is stored as the "4"-valued bit of the
 * first byte in the eight byte representation, bit 2 of the 48 bit value is
 * the "8"-valued bit, and so on.)  In fact, a combined "SPE"-box lookup is
 * used, in which the output is the 64 bit result of an S-box lookup which
 * has been permuted by P and expanded by E, and is ready for use in the next
 * iteration.  Two 32-bit wide tables, SPE[0] and SPE[1], are used for this
 * lookup.  Since each byte in the 48 bit path is a multiple of four, indexed
 * lookup of SPE[0] and SPE[1] is simple and fast.  The key schedule and
 * "salt" are also converted to this 8*(6+2) format.  The SPE table size is
 * 8*64*8 = 4K bytes.
 *
 * To speed up bit-parallel operations (such as XOR), the 8 byte
 * representation is "union"ed with 32 bit values "i0" and "i1", and, on
 * machines which support it, a 64 bit value "b64".  This data structure,
 * "C_block", has two problems.  First, alignment restrictions must be
 * honored.  Second, the byte-order (e.g. little-endian or big-endian) of
 * the architecture becomes visible.
 *
 * The byte-order problem is unfortunate, since on the one hand it is good
 * to have a machine-independent C_block representation (bits 1..8 in the
 * first byte, etc.), and on the other hand it is good for the LSB of the
 * first byte to be the LSB of i0.  We cannot have both these things, so we
 * currently use the "little-endian" representation and avoid any multi-byte
 * operations that depend on byte order.  This largely precludes use of the
 * 64-bit datatype since the relative order of i0 and i1 are unknown.  It
 * also inhibits grouping the SPE table to look up 12 bits at a time.  (The
 * 12 bits can be stored in a 16-bit field with 3 low-order zeroes and 1
 * high-order zero, providing fast indexing into a 64-bit wide SPE.)  On the
 * other hand, 64-bit datatypes are currently rare, and a 12-bit SPE lookup
 * requires a 128 kilobyte table, so perhaps this is not a big loss.
 *
 * Permutation representation (Jim Gillogly):
 *
 * A transformation is defined by its effect on each of the 8 bytes of the
 * 64-bit input.  For each byte we give a 64-bit output that has the bits in
 * the input distributed appropriately.  The transformation is then the OR
 * of the 8 sets of 64-bits.  This uses 8*256*8 = 16K bytes of storage for
 * each transformation.  Unless LARGEDATA is defined, however, a more compact
 * table is used which looks up 16 4-bit "chunks" rather than 8 8-bit chunks.
 * The smaller table uses 16*16*8 = 2K bytes for each transformation.  This
 * is slower but tolerable, particularly for password encryption in which
 * the SPE transformation is iterated many times.  The small tables total 9K
 * bytes, the large tables total 72K bytes.
 *
 * The transformations used are:
 * IE3264: MSB->LSB conversion, initial permutation, and expansion.
 *	This is done by collecting the 32 even-numbered bits and applying
 *	a 32->64 bit transformation, and then collecting the 32 odd-numbered
 *	bits and applying the same transformation.  Since there are only
 *	32 input bits, the IE3264 transformation table is half the size of
 *	the usual table.
 * CF6464: Compression, final permutation, and LSB->MSB conversion.
 *	This is done by two trivial 48->32 bit compressions to obtain
 *	a 64-bit block (the bit numbering is given in the "CIFP" table)
 *	followed by a 64->64 bit "cleanup" transformation.  (It would
 *	be possible to group the bits in the 64-bit block so that 2
 *	identical 32->32 bit transformations could be used instead,
 *	saving a factor of 4 in space and possibly 2 in time, but
 *	byte-ordering and other complications rear their ugly head.
 *	Similar opportunities/problems arise in the key schedule
 *	transforms.)
 * PC1ROT: MSB->LSB, PC1 permutation, rotate, and PC2 permutation.
 *	This admittedly baroque 64->64 bit transformation is used to
 *	produce the first code (in 8*(6+2) format) of the key schedule.
 * PC2ROT[0]: Inverse PC2 permutation, rotate, and PC2 permutation.
 *	It would be possible to define 15 more transformations, each
 *	with a different rotation, to generate the entire key schedule.
 *	To save space, however, we instead permute each code into the
 *	next by using a transformation that "undoes" the PC2 permutation,
 *	rotates the code, and then applies PC2.  Unfortunately, PC2
 *	transforms 56 bits into 48 bits, dropping 8 bits, so PC2 is not
 *	invertible.  We get around that problem by using a modified PC2
 *	which retains the 8 otherwise-lost bits in the unused low-order
 *	bits of each byte.  The low-order bits are cleared when the
 *	codes are stored into the key schedule.
 * PC2ROT[1]: Same as PC2ROT[0], but with two rotations.
 *	This is faster than applying PC2ROT[0] twice,
 *
 * The Bell Labs "salt" (Bob Baldwin):
 *
 * The salting is a simple permutation applied to the 48-bit result of E.
 * Specifically, if bit i (1 <= i <= 24) of the salt is set then bits i and
 * i+24 of the result are swapped.  The salt is thus a 24 bit number, with
 * 16777216 possible values.  (The original salt was 12 bits and could not
 * swap bits 13..24 with 36..48.)
 *
 * It is possible, but ugly, to warp the SPE table to account for the salt
 * permutation.  Fortunately, the conditional bit swapping requires only
 * about four machine instructions and can be done on-the-fly with about an
 * 8% performance penalty.
 */

typedef union {
	unsigned char b[8];
	struct {
		int32_t	i0;
		int32_t	i1;
	} b32;
} C_block;

/*
 * Convert twenty-four-bit long in host-order
 * to six bits (and 2 low-order zeroes) per char little-endian format.
 */
#define	TO_SIX_BIT(rslt, src) {				\
		C_block cvt;				\
		cvt.b[0] = src; src >>= 6;		\
		cvt.b[1] = src; src >>= 6;		\
		cvt.b[2] = src; src >>= 6;		\
		cvt.b[3] = src;				\
		rslt = (cvt.b32.i0 & 0x3f3f3f3fL) << 2;	\
	}

/*
 * These macros may someday permit efficient use of 64-bit integers.
 */
#define	ZERO(d,d0,d1)			d0 = 0, d1 = 0
#define	LOAD(d,d0,d1,bl)		d0 = (bl).b32.i0, d1 = (bl).b32.i1
#define	LOADREG(d,d0,d1,s,s0,s1)	d0 = s0, d1 = s1
#define	OR(d,d0,d1,bl)			d0 |= (bl).b32.i0, d1 |= (bl).b32.i1
#define	STORE(s,s0,s1,bl)		(bl).b32.i0 = s0, (bl).b32.i1 = s1
#define	DCL_BLOCK(d,d0,d1)		int32_t d0, d1

#define	LGCHUNKBITS	3
#define	CHUNKBITS	(1<<LGCHUNKBITS)
#define	PERM6464(d,d0,d1,cpp,p)				\
	LOAD(d,d0,d1,(p)[(0<<CHUNKBITS)+(cpp)[0]]);		\
	OR (d,d0,d1,(p)[(1<<CHUNKBITS)+(cpp)[1]]);		\
	OR (d,d0,d1,(p)[(2<<CHUNKBITS)+(cpp)[2]]);		\
	OR (d,d0,d1,(p)[(3<<CHUNKBITS)+(cpp)[3]]);		\
	OR (d,d0,d1,(p)[(4<<CHUNKBITS)+(cpp)[4]]);		\
	OR (d,d0,d1,(p)[(5<<CHUNKBITS)+(cpp)[5]]);		\
	OR (d,d0,d1,(p)[(6<<CHUNKBITS)+(cpp)[6]]);		\
	OR (d,d0,d1,(p)[(7<<CHUNKBITS)+(cpp)[7]]);
#define	PERM3264(d,d0,d1,cpp,p)				\
	LOAD(d,d0,d1,(p)[(0<<CHUNKBITS)+(cpp)[0]]);		\
	OR (d,d0,d1,(p)[(1<<CHUNKBITS)+(cpp)[1]]);		\
	OR (d,d0,d1,(p)[(2<<CHUNKBITS)+(cpp)[2]]);		\
	OR (d,d0,d1,(p)[(3<<CHUNKBITS)+(cpp)[3]]);

static	void nts_init_des(void);
static	void nts_init_perm(C_block [64/CHUNKBITS][1<<CHUNKBITS],
		       const unsigned char [64], int, int);
static	int nts_des_setkey(char const *);
static	int nts_des_cipher(char const *in, char *out, long salt, int num_iter);

/* =====  (mostly) Standard DES Tables ==================== */

static const unsigned char IP[] = {	/* initial permutation */
	58, 50, 42, 34, 26, 18, 10,  2,
	60, 52, 44, 36, 28, 20, 12,  4,
	62, 54, 46, 38, 30, 22, 14,  6,
	64, 56, 48, 40, 32, 24, 16,  8,
	57, 49, 41, 33, 25, 17,  9,  1,
	59, 51, 43, 35, 27, 19, 11,  3,
	61, 53, 45, 37, 29, 21, 13,  5,
	63, 55, 47, 39, 31, 23, 15,  7,
};

/* The final permutation is the inverse of IP - no table is necessary */

static const unsigned char ExpandTr[] = {	/* expansion operation */
	32,  1,  2,  3,  4,  5,
	 4,  5,  6,  7,  8,  9,
	 8,  9, 10, 11, 12, 13,
	12, 13, 14, 15, 16, 17,
	16, 17, 18, 19, 20, 21,
	20, 21, 22, 23, 24, 25,
	24, 25, 26, 27, 28, 29,
	28, 29, 30, 31, 32,  1,
};

static const unsigned char PC1[] = {	/* permuted choice table 1 */
	57, 49, 41, 33, 25, 17,  9,
	 1, 58, 50, 42, 34, 26, 18,
	10,  2, 59, 51, 43, 35, 27,
	19, 11,  3, 60, 52, 44, 36,

	63, 55, 47, 39, 31, 23, 15,
	 7, 62, 54, 46, 38, 30, 22,
	14,  6, 61, 53, 45, 37, 29,
	21, 13,  5, 28, 20, 12,  4,
};

static const unsigned char Rotates[] = {/* PC1 rotation schedule */
	1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1,
};

/* note: each "row" of PC2 is left-padded with bits that make it invertible */
static const unsigned char PC2[] = {	/* permuted choice table 2 */
	 9, 18,    14, 17, 11, 24,  1,  5,
	22, 25,     3, 28, 15,  6, 21, 10,
	35, 38,    23, 19, 12,  4, 26,  8,
	43, 54,    16,  7, 27, 20, 13,  2,

	 0,  0,    41, 52, 31, 37, 47, 55,
	 0,  0,    30, 40, 51, 45, 33, 48,
	 0,  0,    44, 49, 39, 56, 34, 53,
	 0,  0,    46, 42, 50, 36, 29, 32,
};

static const unsigned char S[8][64] = {	/* 48->32 bit substitution tables */
					/* S[1]			*/
	{ 14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
	   0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
	   4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
	  15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13 },
					/* S[2]			*/
	{ 15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
	   3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
	   0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
	  13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9 },
					/* S[3]			*/
	{ 10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
	  13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
	  13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
	   1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12 },
					/* S[4]			*/
	{  7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
	  13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
	  10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
	   3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14 },
					/* S[5]			*/
	{  2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
	  14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
	   4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
	  11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3 },
					/* S[6]			*/
	{ 12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
	  10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
	   9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
	   4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13 },
					/* S[7]			*/
	{  4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
	  13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
	   1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
	   6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12 },
					/* S[8]			*/
	{ 13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
	   1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
	   7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
	   2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11 }
};

static const unsigned char P32Tr[] = {	/* 32-bit permutation function */
	16,  7, 20, 21,
	29, 12, 28, 17,
	 1, 15, 23, 26,
	 5, 18, 31, 10,
	 2,  8, 24, 14,
	32, 27,  3,  9,
	19, 13, 30,  6,
	22, 11,  4, 25,
};

static const unsigned char CIFP[] = {	/* compressed/interleaved permutation */
	 1,  2,  3,  4,   17, 18, 19, 20,
	 5,  6,  7,  8,   21, 22, 23, 24,
	 9, 10, 11, 12,   25, 26, 27, 28,
	13, 14, 15, 16,   29, 30, 31, 32,

	33, 34, 35, 36,   49, 50, 51, 52,
	37, 38, 39, 40,   53, 54, 55, 56,
	41, 42, 43, 44,   57, 58, 59, 60,
	45, 46, 47, 48,   61, 62, 63, 64,
};

/* =====  Tables that are initialized at run time  ==================== */


static unsigned char a64toi[128];	/* ascii-64 => 0..63 */

/* Initial key schedule permutation */
static C_block	PC1ROT[64/CHUNKBITS][1<<CHUNKBITS];

/* Subsequent key schedule rotation permutations */
static C_block	PC2ROT[2][64/CHUNKBITS][1<<CHUNKBITS];

/* Initial permutation/expansion table */
static C_block	IE3264[32/CHUNKBITS][1<<CHUNKBITS];

/* Table that combines the S, P, and E operations.  */
static int32_t SPE[2][8][64];

/* compressed/interleaved => final permutation table */
static C_block	CF6464[64/CHUNKBITS][1<<CHUNKBITS];


/* ==================================== */


static C_block	constdatablock;			/* encryption constant */
static char	cryptresult[1+4+4+11+1];	/* encrypted result */


/*
 * Return a pointer to static data consisting of the "setting"
 * followed by an encryption produced by the "key" and "setting".
 */
char *
nts_crypt(key, setting)
	const char *key, *setting;
{
char	*encp;
int32_t	 i;
int	 t;
int32_t	 salt;
int 	 num_iter, salt_size;
C_block	 keyblock, rsltblock;

	/* Non-DES encryption schemes hook in here. */
	if (setting[0] == PASSWORD_NONDES) {
		switch (setting[1]) {
		case '2':
			return (nts_crypt_blowfish(key, setting));
		case 's':
			return (nts_crypt_sha1(key, setting));
		case '1':
		default:
			return (nts_crypt_md5(key, setting));
		}
	}

	for (i = 0; i < 8; i++) {
		if ((t = 2*(unsigned char)(*key)) != 0)
			key++;
		keyblock.b[i] = t;
	}
	if (nts_des_setkey((char *)keyblock.b))	/* also initializes "a64toi" */
		return (NULL);

	encp = &cryptresult[0];
	switch (*setting) {
	case PASSWORD_EFMT1:
		/*
		 * Involve the rest of the password 8 characters at a time.
		 */
		while (*key) {
			if (nts_des_cipher((char *)(void *)&keyblock,
			    (char *)(void *)&keyblock, 0L, 1))
				return (NULL);
			for (i = 0; i < 8; i++) {
				if ((t = 2*(unsigned char)(*key)) != 0)
					key++;
				keyblock.b[i] ^= t;
			}
			if (nts_des_setkey((char *)keyblock.b))
				return (NULL);
		}

		*encp++ = *setting++;

		/* get iteration count */
		num_iter = 0;
		for (i = 4; --i >= 0; ) {
			if ((t = (unsigned char)setting[i]) == '\0')
				t = '.';
			encp[i] = t;
			num_iter = (num_iter<<6) | a64toi[t];
		}
		setting += 4;
		encp += 4;
		salt_size = 4;
		break;
	default:
		num_iter = 25;
		salt_size = 2;
	}

	salt = 0;
	for (i = salt_size; --i >= 0; ) {
		if ((t = (unsigned char)setting[i]) == '\0')
			t = '.';
		encp[i] = t;
		salt = (salt<<6) | a64toi[t];
	}
	encp += salt_size;
	if (nts_des_cipher((char *)(void *)&constdatablock,
	    (char *)(void *)&rsltblock, salt, num_iter))
		return (NULL);

	/*
	 * Encode the 64 cipher bits as 11 ascii characters.
	 */
	i = ((int32_t)((rsltblock.b[0]<<8) | rsltblock.b[1])<<8) |
	    rsltblock.b[2];
	encp[3] = itoa64[i&0x3f];	i >>= 6;
	encp[2] = itoa64[i&0x3f];	i >>= 6;
	encp[1] = itoa64[i&0x3f];	i >>= 6;
	encp[0] = itoa64[i];		encp += 4;
	i = ((int32_t)((rsltblock.b[3]<<8) | rsltblock.b[4])<<8) |
	    rsltblock.b[5];
	encp[3] = itoa64[i&0x3f];	i >>= 6;
	encp[2] = itoa64[i&0x3f];	i >>= 6;
	encp[1] = itoa64[i&0x3f];	i >>= 6;
	encp[0] = itoa64[i];		encp += 4;
	i = ((int32_t)((rsltblock.b[6])<<8) | rsltblock.b[7])<<2;
	encp[2] = itoa64[i&0x3f];	i >>= 6;
	encp[1] = itoa64[i&0x3f];	i >>= 6;
	encp[0] = itoa64[i];

	encp[3] = 0;

	return (cryptresult);
}


/*
 * The Key Schedule, filled in by des_setkey() or setkey().
 */
#define	KS_SIZE	16
static C_block	KS[KS_SIZE];

/*
 * Set up the key schedule from the key.
 */
static int
nts_des_setkey(key)
	const char *key;
{
	DCL_BLOCK(K, K0, K1);
	C_block *help, *ptabp;
	int i;
	static int des_ready = 0;

	if (!des_ready) {
		nts_init_des();
		des_ready = 1;
	}

	PERM6464(K,K0,K1,(const unsigned char *)key,(C_block *)PC1ROT);
	help = &KS[0];
	STORE(K&~0x03030303L, K0&~0x03030303L, K1, *help);
	for (i = 1; i < 16; i++) {
		help++;
		STORE(K,K0,K1,*help);
		ptabp = (C_block *)PC2ROT[Rotates[i]-1];
		PERM6464(K,K0,K1,(const unsigned char *)help,ptabp);
		STORE(K&~0x03030303L, K0&~0x03030303L, K1, *help);
	}
	return (0);
}

/*
 * Encrypt (or decrypt if num_iter < 0) the 8 chars at "in" with abs(num_iter)
 * iterations of DES, using the given 24-bit salt and the pre-computed key
 * schedule, and store the resulting 8 chars at "out" (in == out is permitted).
 *
 * NOTE: the performance of this routine is critically dependent on your
 * compiler and machine architecture.
 */
static int
nts_des_cipher(in, out, salt, num_iter)
	const char *in;
	char *out;
	long salt;
	int num_iter;
{
	/* variables that we want in registers, most important first */
#if defined(pdp11)
	int j;
#endif
	int32_t L0, L1, R0, R1, k;
	C_block *kp;
	int ks_inc, loop_count;
	C_block B;

	L0 = salt;
	TO_SIX_BIT(salt, L0);	/* convert to 4*(6+2) format */

#if defined(__vax__) || defined(pdp11)
	salt = ~salt;	/* "x &~ y" is faster than "x & y". */
#define	SALT (~salt)
#else
#define	SALT salt
#endif

#if defined(MUST_ALIGN)
	B.b[0] = in[0]; B.b[1] = in[1]; B.b[2] = in[2]; B.b[3] = in[3];
	B.b[4] = in[4]; B.b[5] = in[5]; B.b[6] = in[6]; B.b[7] = in[7];
	LOAD(L,L0,L1,B);
#else
	LOAD(L,L0,L1,*(const C_block *)in);
#endif
	LOADREG(R,R0,R1,L,L0,L1);
	L0 &= 0x55555555L;
	L1 &= 0x55555555L;
	L0 = (L0 << 1) | L1;	/* L0 is the even-numbered input bits */
	R0 &= 0xaaaaaaaaL;
	R1 = (R1 >> 1) & 0x55555555L;
	L1 = R0 | R1;		/* L1 is the odd-numbered input bits */
	STORE(L,L0,L1,B);
	PERM3264(L,L0,L1,B.b,  (C_block *)IE3264);	/* even bits */
	PERM3264(R,R0,R1,B.b+4,(C_block *)IE3264);	/* odd bits */

	if (num_iter >= 0)
	{		/* encryption */
		kp = &KS[0];
		ks_inc  = sizeof(*kp);
	}
	else
	{		/* decryption */
		num_iter = -num_iter;
		kp = &KS[KS_SIZE-1];
		ks_inc  = -(long)sizeof(*kp);
	}

	while (--num_iter >= 0) {
		loop_count = 8;
		do {

#define	SPTAB(t, i) \
	    (*(int32_t *)((unsigned char *)t + i*(sizeof(int32_t)/4)))
#if defined(gould)
			/* use this if B.b[i] is evaluated just once ... */
#define	DOXOR(x,y,i)	x^=SPTAB(SPE[0][i],B.b[i]); y^=SPTAB(SPE[1][i],B.b[i]);
#else
#if defined(pdp11)
			/* use this if your "long" int indexing is slow */
#define	DOXOR(x,y,i)	j=B.b[i]; x^=SPTAB(SPE[0][i],j); y^=SPTAB(SPE[1][i],j);
#else
			/* use this if "k" is allocated to a register ... */
#define	DOXOR(x,y,i)	k=B.b[i]; x^=SPTAB(SPE[0][i],k); y^=SPTAB(SPE[1][i],k);
#endif
#endif

#define	CRUNCH(p0, p1, q0, q1)	\
			k = (q0 ^ q1) & SALT;	\
			B.b32.i0 = k ^ q0 ^ kp->b32.i0;		\
			B.b32.i1 = k ^ q1 ^ kp->b32.i1;		\
			kp = (C_block *)((char *)kp+ks_inc);	\
							\
			DOXOR(p0, p1, 0);		\
			DOXOR(p0, p1, 1);		\
			DOXOR(p0, p1, 2);		\
			DOXOR(p0, p1, 3);		\
			DOXOR(p0, p1, 4);		\
			DOXOR(p0, p1, 5);		\
			DOXOR(p0, p1, 6);		\
			DOXOR(p0, p1, 7);

			CRUNCH(L0, L1, R0, R1);
			CRUNCH(R0, R1, L0, L1);
		} while (--loop_count != 0);
		kp = (C_block *)((char *)kp-(ks_inc*KS_SIZE));


		/* swap L and R */
		L0 ^= R0;  L1 ^= R1;
		R0 ^= L0;  R1 ^= L1;
		L0 ^= R0;  L1 ^= R1;
	}

	/* store the encrypted (or decrypted) result */
	L0 = ((L0 >> 3) & 0x0f0f0f0fL) | ((L1 << 1) & 0xf0f0f0f0L);
	L1 = ((R0 >> 3) & 0x0f0f0f0fL) | ((R1 << 1) & 0xf0f0f0f0L);
	STORE(L,L0,L1,B);
	PERM6464(L,L0,L1,B.b, (C_block *)CF6464);
#if defined(MUST_ALIGN)
	STORE(L,L0,L1,B);
	out[0] = B.b[0]; out[1] = B.b[1]; out[2] = B.b[2]; out[3] = B.b[3];
	out[4] = B.b[4]; out[5] = B.b[5]; out[6] = B.b[6]; out[7] = B.b[7];
#else
	STORE(L,L0,L1,*(C_block *)out);
#endif
	return (0);
}


/*
 * Initialize various tables.  This need only be done once.  It could even be
 * done at compile time, if the compiler were capable of that sort of thing.
 */
static void
nts_init_des()
{
	int i, j;
	int32_t k;
	int tableno;
	static unsigned char perm[64], tmp32[32];	/* "static" for speed */

	/*
	 * table that converts chars "./0-9A-Za-z"to integers 0-63.
	 */
	for (i = 0; i < 64; i++)
		a64toi[itoa64[i]] = i;

	/*
	 * PC1ROT - bit reverse, then PC1, then Rotate, then PC2.
	 */
	for (i = 0; i < 64; i++)
		perm[i] = 0;
	for (i = 0; i < 64; i++) {
		if ((k = PC2[i]) == 0)
			continue;
		k += Rotates[0]-1;
		if ((k%28) < Rotates[0]) k -= 28;
		k = PC1[k];
		if (k > 0) {
			k--;
			k = (k|07) - (k&07);
			k++;
		}
		perm[i] = k;
	}
#ifdef DEBUG
	prtab("pc1tab", perm, 8);
#endif
	nts_init_perm(PC1ROT, perm, 8, 8);

	/*
	 * PC2ROT - PC2 inverse, then Rotate (once or twice), then PC2.
	 */
	for (j = 0; j < 2; j++) {
		unsigned char pc2inv[64];
		for (i = 0; i < 64; i++)
			perm[i] = pc2inv[i] = 0;
		for (i = 0; i < 64; i++) {
			if ((k = PC2[i]) == 0)
				continue;
			pc2inv[k-1] = i+1;
		}
		for (i = 0; i < 64; i++) {
			if ((k = PC2[i]) == 0)
				continue;
			k += j;
			if ((k%28) <= j) k -= 28;
			perm[i] = pc2inv[k];
		}
#ifdef DEBUG
		prtab("pc2tab", perm, 8);
#endif
		nts_init_perm(PC2ROT[j], perm, 8, 8);
	}

	/*
	 * Bit reverse, then initial permutation, then expansion.
	 */
	for (i = 0; i < 8; i++) {
		for (j = 0; j < 8; j++) {
			k = (j < 2)? 0: IP[ExpandTr[i*6+j-2]-1];
			if (k > 32)
				k -= 32;
			else if (k > 0)
				k--;
			if (k > 0) {
				k--;
				k = (k|07) - (k&07);
				k++;
			}
			perm[i*8+j] = k;
		}
	}
#ifdef DEBUG
	prtab("ietab", perm, 8);
#endif
	nts_init_perm(IE3264, perm, 4, 8);

	/*
	 * Compression, then final permutation, then bit reverse.
	 */
	for (i = 0; i < 64; i++) {
		k = IP[CIFP[i]-1];
		if (k > 0) {
			k--;
			k = (k|07) - (k&07);
			k++;
		}
		perm[k-1] = i+1;
	}
#ifdef DEBUG
	prtab("cftab", perm, 8);
#endif
	nts_init_perm(CF6464, perm, 8, 8);

	/*
	 * SPE table
	 */
	for (i = 0; i < 48; i++)
		perm[i] = P32Tr[ExpandTr[i]-1];
	for (tableno = 0; tableno < 8; tableno++) {
		for (j = 0; j < 64; j++)  {
			k = (((j >> 0) &01) << 5)|
			    (((j >> 1) &01) << 3)|
			    (((j >> 2) &01) << 2)|
			    (((j >> 3) &01) << 1)|
			    (((j >> 4) &01) << 0)|
			    (((j >> 5) &01) << 4);
			k = S[tableno][k];
			k = (((k >> 3)&01) << 0)|
			    (((k >> 2)&01) << 1)|
			    (((k >> 1)&01) << 2)|
			    (((k >> 0)&01) << 3);
			for (i = 0; i < 32; i++)
				tmp32[i] = 0;
			for (i = 0; i < 4; i++)
				tmp32[4 * tableno + i] = (k >> i) & 01;
			k = 0;
			for (i = 24; --i >= 0; )
				k = (k<<1) | tmp32[perm[i]-1];
			TO_SIX_BIT(SPE[0][tableno][j], k);
			k = 0;
			for (i = 24; --i >= 0; )
				k = (k<<1) | tmp32[perm[i+24]-1];
			TO_SIX_BIT(SPE[1][tableno][j], k);
		}
	}
}

/*
 * Initialize "perm" to represent transformation "p", which rearranges
 * (perhaps with expansion and/or contraction) one packed array of bits
 * (of size "chars_in" characters) into another array (of size "chars_out"
 * characters).
 *
 * "perm" must be all-zeroes on entry to this routine.
 */
static void
nts_init_perm(perm, p, chars_in, chars_out)
	C_block perm[64/CHUNKBITS][1<<CHUNKBITS];
	const unsigned char p[64];
	int chars_in, chars_out;
{
	int i, j, k, l;

	for (k = 0; k < chars_out*8; k++) {	/* each output bit position */
		l = p[k] - 1;		/* where this bit comes from */
		if (l < 0)
			continue;	/* output bit is always 0 */
		i = l>>LGCHUNKBITS;	/* which chunk this bit comes from */
		l = 1<<(l&(CHUNKBITS-1));	/* mask for this bit */
		for (j = 0; j < (1<<CHUNKBITS); j++) {	/* each chunk value */
			if ((j & l) != 0)
				perm[i][j].b[k>>3] |= 1<<(k&07);
		}
	}
}


/*****
 *
 * bcrypt
 */


/*	$NetBSD: bcrypt.c,v 1.9 2006/10/27 19:39:11 drochner Exp $	*/
/*	$OpenBSD: bcrypt.c,v 1.16 2002/02/19 19:39:36 millert Exp $	*/

/*
 * Copyright 1997 Niels Provos <provos@physnet.uni-hamburg.de>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Niels Provos.
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* This password hashing algorithm was designed by David Mazieres
 * <dm@lcs.mit.edu> and works as follows:
 *
 * 1. state := InitState ()
 * 2. state := ExpandKey (state, salt, password) 3.
 * REPEAT rounds:
 *	state := ExpandKey (state, 0, salt)
 *      state := ExpandKey(state, 0, password)
 * 4. ctext := "OrpheanBeholderScryDoubt"
 * 5. REPEAT 64:
 * 	ctext := Encrypt_ECB (state, ctext);
 * 6. RETURN Concatenate (salt, ctext);
 *
 */

/*	$NetBSD: blowfish.c,v 1.4 2005/12/24 21:11:16 perry Exp $	*/
/* $OpenBSD: blowfish.c,v 1.16 2002/02/19 19:39:36 millert Exp $ */
/*
 * Blowfish block cipher for OpenBSD
 * Copyright 1997 Niels Provos <provos@physnet.uni-hamburg.de>
 * All rights reserved.
 *
 * Implementation advice by David Mazieres <dm@lcs.mit.edu>.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Niels Provos.
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * This code is derived from section 14.3 and the given source
 * in section V of Applied Cryptography, second edition.
 * Blowfish is an unpatented fast block cipher designed by
 * Bruce Schneier.
 */

/*
 * Note: This has been trimmed down to only what is needed by
 * __bcrypt().  Also note that this file is actually included
 * directly by bcrypt.c, not built separately.
 */

/* Schneier specifies a maximum key length of 56 bytes.
 * This ensures that every key bit affects every cipher
 * bit.  However, the subkeys can hold up to 72 bytes.
 * Warning: For normal blowfish encryption only 56 bytes
 * of the key affect all cipherbits.
 */

#define BLF_N	16			/* Number of Subkeys */
#define BLF_MAXKEYLEN ((BLF_N-2)*4)	/* 448 bits */

/* Blowfish context */
typedef struct BlowfishContext {
	u_int32_t S[4][256];	/* S-Boxes */
	u_int32_t P[BLF_N + 2];	/* Subkeys */
} blf_ctx;


/* Function for Feistel Networks */

#define F(s, x) ((((s)[        (((x)>>24)&0xFF)]  \
		 + (s)[0x100 + (((x)>>16)&0xFF)]) \
		 ^ (s)[0x200 + (((x)>> 8)&0xFF)]) \
		 + (s)[0x300 + ( (x)     &0xFF)])

#define BLFRND(s,p,i,j,n) (i ^= F(s,j) ^ (p)[n])

static void
Blowfish_encipher(blf_ctx *c, u_int32_t *xl, u_int32_t *xr)
{
	u_int32_t Xl;
	u_int32_t Xr;
	u_int32_t *s = c->S[0];
	u_int32_t *p = c->P;

	Xl = *xl;
	Xr = *xr;

	Xl ^= p[0];
	BLFRND(s, p, Xr, Xl, 1); BLFRND(s, p, Xl, Xr, 2);
	BLFRND(s, p, Xr, Xl, 3); BLFRND(s, p, Xl, Xr, 4);
	BLFRND(s, p, Xr, Xl, 5); BLFRND(s, p, Xl, Xr, 6);
	BLFRND(s, p, Xr, Xl, 7); BLFRND(s, p, Xl, Xr, 8);
	BLFRND(s, p, Xr, Xl, 9); BLFRND(s, p, Xl, Xr, 10);
	BLFRND(s, p, Xr, Xl, 11); BLFRND(s, p, Xl, Xr, 12);
	BLFRND(s, p, Xr, Xl, 13); BLFRND(s, p, Xl, Xr, 14);
	BLFRND(s, p, Xr, Xl, 15); BLFRND(s, p, Xl, Xr, 16);

	*xl = Xr ^ p[17];
	*xr = Xl;
}

static void
Blowfish_initstate(blf_ctx *c)
{

/* P-box and S-box tables initialized with digits of Pi */

	static const blf_ctx init_state =

	{ {
		{
			0xd1310ba6, 0x98dfb5ac, 0x2ffd72db, 0xd01adfb7,
			0xb8e1afed, 0x6a267e96, 0xba7c9045, 0xf12c7f99,
			0x24a19947, 0xb3916cf7, 0x0801f2e2, 0x858efc16,
			0x636920d8, 0x71574e69, 0xa458fea3, 0xf4933d7e,
			0x0d95748f, 0x728eb658, 0x718bcd58, 0x82154aee,
			0x7b54a41d, 0xc25a59b5, 0x9c30d539, 0x2af26013,
			0xc5d1b023, 0x286085f0, 0xca417918, 0xb8db38ef,
			0x8e79dcb0, 0x603a180e, 0x6c9e0e8b, 0xb01e8a3e,
			0xd71577c1, 0xbd314b27, 0x78af2fda, 0x55605c60,
			0xe65525f3, 0xaa55ab94, 0x57489862, 0x63e81440,
			0x55ca396a, 0x2aab10b6, 0xb4cc5c34, 0x1141e8ce,
			0xa15486af, 0x7c72e993, 0xb3ee1411, 0x636fbc2a,
			0x2ba9c55d, 0x741831f6, 0xce5c3e16, 0x9b87931e,
			0xafd6ba33, 0x6c24cf5c, 0x7a325381, 0x28958677,
			0x3b8f4898, 0x6b4bb9af, 0xc4bfe81b, 0x66282193,
			0x61d809cc, 0xfb21a991, 0x487cac60, 0x5dec8032,
			0xef845d5d, 0xe98575b1, 0xdc262302, 0xeb651b88,
			0x23893e81, 0xd396acc5, 0x0f6d6ff3, 0x83f44239,
			0x2e0b4482, 0xa4842004, 0x69c8f04a, 0x9e1f9b5e,
			0x21c66842, 0xf6e96c9a, 0x670c9c61, 0xabd388f0,
			0x6a51a0d2, 0xd8542f68, 0x960fa728, 0xab5133a3,
			0x6eef0b6c, 0x137a3be4, 0xba3bf050, 0x7efb2a98,
			0xa1f1651d, 0x39af0176, 0x66ca593e, 0x82430e88,
			0x8cee8619, 0x456f9fb4, 0x7d84a5c3, 0x3b8b5ebe,
			0xe06f75d8, 0x85c12073, 0x401a449f, 0x56c16aa6,
			0x4ed3aa62, 0x363f7706, 0x1bfedf72, 0x429b023d,
			0x37d0d724, 0xd00a1248, 0xdb0fead3, 0x49f1c09b,
			0x075372c9, 0x80991b7b, 0x25d479d8, 0xf6e8def7,
			0xe3fe501a, 0xb6794c3b, 0x976ce0bd, 0x04c006ba,
			0xc1a94fb6, 0x409f60c4, 0x5e5c9ec2, 0x196a2463,
			0x68fb6faf, 0x3e6c53b5, 0x1339b2eb, 0x3b52ec6f,
			0x6dfc511f, 0x9b30952c, 0xcc814544, 0xaf5ebd09,
			0xbee3d004, 0xde334afd, 0x660f2807, 0x192e4bb3,
			0xc0cba857, 0x45c8740f, 0xd20b5f39, 0xb9d3fbdb,
			0x5579c0bd, 0x1a60320a, 0xd6a100c6, 0x402c7279,
			0x679f25fe, 0xfb1fa3cc, 0x8ea5e9f8, 0xdb3222f8,
			0x3c7516df, 0xfd616b15, 0x2f501ec8, 0xad0552ab,
			0x323db5fa, 0xfd238760, 0x53317b48, 0x3e00df82,
			0x9e5c57bb, 0xca6f8ca0, 0x1a87562e, 0xdf1769db,
			0xd542a8f6, 0x287effc3, 0xac6732c6, 0x8c4f5573,
			0x695b27b0, 0xbbca58c8, 0xe1ffa35d, 0xb8f011a0,
			0x10fa3d98, 0xfd2183b8, 0x4afcb56c, 0x2dd1d35b,
			0x9a53e479, 0xb6f84565, 0xd28e49bc, 0x4bfb9790,
			0xe1ddf2da, 0xa4cb7e33, 0x62fb1341, 0xcee4c6e8,
			0xef20cada, 0x36774c01, 0xd07e9efe, 0x2bf11fb4,
			0x95dbda4d, 0xae909198, 0xeaad8e71, 0x6b93d5a0,
			0xd08ed1d0, 0xafc725e0, 0x8e3c5b2f, 0x8e7594b7,
			0x8ff6e2fb, 0xf2122b64, 0x8888b812, 0x900df01c,
			0x4fad5ea0, 0x688fc31c, 0xd1cff191, 0xb3a8c1ad,
			0x2f2f2218, 0xbe0e1777, 0xea752dfe, 0x8b021fa1,
			0xe5a0cc0f, 0xb56f74e8, 0x18acf3d6, 0xce89e299,
			0xb4a84fe0, 0xfd13e0b7, 0x7cc43b81, 0xd2ada8d9,
			0x165fa266, 0x80957705, 0x93cc7314, 0x211a1477,
			0xe6ad2065, 0x77b5fa86, 0xc75442f5, 0xfb9d35cf,
			0xebcdaf0c, 0x7b3e89a0, 0xd6411bd3, 0xae1e7e49,
			0x00250e2d, 0x2071b35e, 0x226800bb, 0x57b8e0af,
			0x2464369b, 0xf009b91e, 0x5563911d, 0x59dfa6aa,
			0x78c14389, 0xd95a537f, 0x207d5ba2, 0x02e5b9c5,
			0x83260376, 0x6295cfa9, 0x11c81968, 0x4e734a41,
			0xb3472dca, 0x7b14a94a, 0x1b510052, 0x9a532915,
			0xd60f573f, 0xbc9bc6e4, 0x2b60a476, 0x81e67400,
			0x08ba6fb5, 0x571be91f, 0xf296ec6b, 0x2a0dd915,
			0xb6636521, 0xe7b9f9b6, 0xff34052e, 0xc5855664,
		0x53b02d5d, 0xa99f8fa1, 0x08ba4799, 0x6e85076a},
		{
			0x4b7a70e9, 0xb5b32944, 0xdb75092e, 0xc4192623,
			0xad6ea6b0, 0x49a7df7d, 0x9cee60b8, 0x8fedb266,
			0xecaa8c71, 0x699a17ff, 0x5664526c, 0xc2b19ee1,
			0x193602a5, 0x75094c29, 0xa0591340, 0xe4183a3e,
			0x3f54989a, 0x5b429d65, 0x6b8fe4d6, 0x99f73fd6,
			0xa1d29c07, 0xefe830f5, 0x4d2d38e6, 0xf0255dc1,
			0x4cdd2086, 0x8470eb26, 0x6382e9c6, 0x021ecc5e,
			0x09686b3f, 0x3ebaefc9, 0x3c971814, 0x6b6a70a1,
			0x687f3584, 0x52a0e286, 0xb79c5305, 0xaa500737,
			0x3e07841c, 0x7fdeae5c, 0x8e7d44ec, 0x5716f2b8,
			0xb03ada37, 0xf0500c0d, 0xf01c1f04, 0x0200b3ff,
			0xae0cf51a, 0x3cb574b2, 0x25837a58, 0xdc0921bd,
			0xd19113f9, 0x7ca92ff6, 0x94324773, 0x22f54701,
			0x3ae5e581, 0x37c2dadc, 0xc8b57634, 0x9af3dda7,
			0xa9446146, 0x0fd0030e, 0xecc8c73e, 0xa4751e41,
			0xe238cd99, 0x3bea0e2f, 0x3280bba1, 0x183eb331,
			0x4e548b38, 0x4f6db908, 0x6f420d03, 0xf60a04bf,
			0x2cb81290, 0x24977c79, 0x5679b072, 0xbcaf89af,
			0xde9a771f, 0xd9930810, 0xb38bae12, 0xdccf3f2e,
			0x5512721f, 0x2e6b7124, 0x501adde6, 0x9f84cd87,
			0x7a584718, 0x7408da17, 0xbc9f9abc, 0xe94b7d8c,
			0xec7aec3a, 0xdb851dfa, 0x63094366, 0xc464c3d2,
			0xef1c1847, 0x3215d908, 0xdd433b37, 0x24c2ba16,
			0x12a14d43, 0x2a65c451, 0x50940002, 0x133ae4dd,
			0x71dff89e, 0x10314e55, 0x81ac77d6, 0x5f11199b,
			0x043556f1, 0xd7a3c76b, 0x3c11183b, 0x5924a509,
			0xf28fe6ed, 0x97f1fbfa, 0x9ebabf2c, 0x1e153c6e,
			0x86e34570, 0xeae96fb1, 0x860e5e0a, 0x5a3e2ab3,
			0x771fe71c, 0x4e3d06fa, 0x2965dcb9, 0x99e71d0f,
			0x803e89d6, 0x5266c825, 0x2e4cc978, 0x9c10b36a,
			0xc6150eba, 0x94e2ea78, 0xa5fc3c53, 0x1e0a2df4,
			0xf2f74ea7, 0x361d2b3d, 0x1939260f, 0x19c27960,
			0x5223a708, 0xf71312b6, 0xebadfe6e, 0xeac31f66,
			0xe3bc4595, 0xa67bc883, 0xb17f37d1, 0x018cff28,
			0xc332ddef, 0xbe6c5aa5, 0x65582185, 0x68ab9802,
			0xeecea50f, 0xdb2f953b, 0x2aef7dad, 0x5b6e2f84,
			0x1521b628, 0x29076170, 0xecdd4775, 0x619f1510,
			0x13cca830, 0xeb61bd96, 0x0334fe1e, 0xaa0363cf,
			0xb5735c90, 0x4c70a239, 0xd59e9e0b, 0xcbaade14,
			0xeecc86bc, 0x60622ca7, 0x9cab5cab, 0xb2f3846e,
			0x648b1eaf, 0x19bdf0ca, 0xa02369b9, 0x655abb50,
			0x40685a32, 0x3c2ab4b3, 0x319ee9d5, 0xc021b8f7,
			0x9b540b19, 0x875fa099, 0x95f7997e, 0x623d7da8,
			0xf837889a, 0x97e32d77, 0x11ed935f, 0x16681281,
			0x0e358829, 0xc7e61fd6, 0x96dedfa1, 0x7858ba99,
			0x57f584a5, 0x1b227263, 0x9b83c3ff, 0x1ac24696,
			0xcdb30aeb, 0x532e3054, 0x8fd948e4, 0x6dbc3128,
			0x58ebf2ef, 0x34c6ffea, 0xfe28ed61, 0xee7c3c73,
			0x5d4a14d9, 0xe864b7e3, 0x42105d14, 0x203e13e0,
			0x45eee2b6, 0xa3aaabea, 0xdb6c4f15, 0xfacb4fd0,
			0xc742f442, 0xef6abbb5, 0x654f3b1d, 0x41cd2105,
			0xd81e799e, 0x86854dc7, 0xe44b476a, 0x3d816250,
			0xcf62a1f2, 0x5b8d2646, 0xfc8883a0, 0xc1c7b6a3,
			0x7f1524c3, 0x69cb7492, 0x47848a0b, 0x5692b285,
			0x095bbf00, 0xad19489d, 0x1462b174, 0x23820e00,
			0x58428d2a, 0x0c55f5ea, 0x1dadf43e, 0x233f7061,
			0x3372f092, 0x8d937e41, 0xd65fecf1, 0x6c223bdb,
			0x7cde3759, 0xcbee7460, 0x4085f2a7, 0xce77326e,
			0xa6078084, 0x19f8509e, 0xe8efd855, 0x61d99735,
			0xa969a7aa, 0xc50c06c2, 0x5a04abfc, 0x800bcadc,
			0x9e447a2e, 0xc3453484, 0xfdd56705, 0x0e1e9ec9,
			0xdb73dbd3, 0x105588cd, 0x675fda79, 0xe3674340,
			0xc5c43465, 0x713e38d8, 0x3d28f89e, 0xf16dff20,
		0x153e21e7, 0x8fb03d4a, 0xe6e39f2b, 0xdb83adf7},
		{
			0xe93d5a68, 0x948140f7, 0xf64c261c, 0x94692934,
			0x411520f7, 0x7602d4f7, 0xbcf46b2e, 0xd4a20068,
			0xd4082471, 0x3320f46a, 0x43b7d4b7, 0x500061af,
			0x1e39f62e, 0x97244546, 0x14214f74, 0xbf8b8840,
			0x4d95fc1d, 0x96b591af, 0x70f4ddd3, 0x66a02f45,
			0xbfbc09ec, 0x03bd9785, 0x7fac6dd0, 0x31cb8504,
			0x96eb27b3, 0x55fd3941, 0xda2547e6, 0xabca0a9a,
			0x28507825, 0x530429f4, 0x0a2c86da, 0xe9b66dfb,
			0x68dc1462, 0xd7486900, 0x680ec0a4, 0x27a18dee,
			0x4f3ffea2, 0xe887ad8c, 0xb58ce006, 0x7af4d6b6,
			0xaace1e7c, 0xd3375fec, 0xce78a399, 0x406b2a42,
			0x20fe9e35, 0xd9f385b9, 0xee39d7ab, 0x3b124e8b,
			0x1dc9faf7, 0x4b6d1856, 0x26a36631, 0xeae397b2,
			0x3a6efa74, 0xdd5b4332, 0x6841e7f7, 0xca7820fb,
			0xfb0af54e, 0xd8feb397, 0x454056ac, 0xba489527,
			0x55533a3a, 0x20838d87, 0xfe6ba9b7, 0xd096954b,
			0x55a867bc, 0xa1159a58, 0xcca92963, 0x99e1db33,
			0xa62a4a56, 0x3f3125f9, 0x5ef47e1c, 0x9029317c,
			0xfdf8e802, 0x04272f70, 0x80bb155c, 0x05282ce3,
			0x95c11548, 0xe4c66d22, 0x48c1133f, 0xc70f86dc,
			0x07f9c9ee, 0x41041f0f, 0x404779a4, 0x5d886e17,
			0x325f51eb, 0xd59bc0d1, 0xf2bcc18f, 0x41113564,
			0x257b7834, 0x602a9c60, 0xdff8e8a3, 0x1f636c1b,
			0x0e12b4c2, 0x02e1329e, 0xaf664fd1, 0xcad18115,
			0x6b2395e0, 0x333e92e1, 0x3b240b62, 0xeebeb922,
			0x85b2a20e, 0xe6ba0d99, 0xde720c8c, 0x2da2f728,
			0xd0127845, 0x95b794fd, 0x647d0862, 0xe7ccf5f0,
			0x5449a36f, 0x877d48fa, 0xc39dfd27, 0xf33e8d1e,
			0x0a476341, 0x992eff74, 0x3a6f6eab, 0xf4f8fd37,
			0xa812dc60, 0xa1ebddf8, 0x991be14c, 0xdb6e6b0d,
			0xc67b5510, 0x6d672c37, 0x2765d43b, 0xdcd0e804,
			0xf1290dc7, 0xcc00ffa3, 0xb5390f92, 0x690fed0b,
			0x667b9ffb, 0xcedb7d9c, 0xa091cf0b, 0xd9155ea3,
			0xbb132f88, 0x515bad24, 0x7b9479bf, 0x763bd6eb,
			0x37392eb3, 0xcc115979, 0x8026e297, 0xf42e312d,
			0x6842ada7, 0xc66a2b3b, 0x12754ccc, 0x782ef11c,
			0x6a124237, 0xb79251e7, 0x06a1bbe6, 0x4bfb6350,
			0x1a6b1018, 0x11caedfa, 0x3d25bdd8, 0xe2e1c3c9,
			0x44421659, 0x0a121386, 0xd90cec6e, 0xd5abea2a,
			0x64af674e, 0xda86a85f, 0xbebfe988, 0x64e4c3fe,
			0x9dbc8057, 0xf0f7c086, 0x60787bf8, 0x6003604d,
			0xd1fd8346, 0xf6381fb0, 0x7745ae04, 0xd736fccc,
			0x83426b33, 0xf01eab71, 0xb0804187, 0x3c005e5f,
			0x77a057be, 0xbde8ae24, 0x55464299, 0xbf582e61,
			0x4e58f48f, 0xf2ddfda2, 0xf474ef38, 0x8789bdc2,
			0x5366f9c3, 0xc8b38e74, 0xb475f255, 0x46fcd9b9,
			0x7aeb2661, 0x8b1ddf84, 0x846a0e79, 0x915f95e2,
			0x466e598e, 0x20b45770, 0x8cd55591, 0xc902de4c,
			0xb90bace1, 0xbb8205d0, 0x11a86248, 0x7574a99e,
			0xb77f19b6, 0xe0a9dc09, 0x662d09a1, 0xc4324633,
			0xe85a1f02, 0x09f0be8c, 0x4a99a025, 0x1d6efe10,
			0x1ab93d1d, 0x0ba5a4df, 0xa186f20f, 0x2868f169,
			0xdcb7da83, 0x573906fe, 0xa1e2ce9b, 0x4fcd7f52,
			0x50115e01, 0xa70683fa, 0xa002b5c4, 0x0de6d027,
			0x9af88c27, 0x773f8641, 0xc3604c06, 0x61a806b5,
			0xf0177a28, 0xc0f586e0, 0x006058aa, 0x30dc7d62,
			0x11e69ed7, 0x2338ea63, 0x53c2dd94, 0xc2c21634,
			0xbbcbee56, 0x90bcb6de, 0xebfc7da1, 0xce591d76,
			0x6f05e409, 0x4b7c0188, 0x39720a3d, 0x7c927c24,
			0x86e3725f, 0x724d9db9, 0x1ac15bb4, 0xd39eb8fc,
			0xed545578, 0x08fca5b5, 0xd83d7cd3, 0x4dad0fc4,
			0x1e50ef5e, 0xb161e6f8, 0xa28514d9, 0x6c51133c,
			0x6fd5c7e7, 0x56e14ec4, 0x362abfce, 0xddc6c837,
		0xd79a3234, 0x92638212, 0x670efa8e, 0x406000e0},
		{
			0x3a39ce37, 0xd3faf5cf, 0xabc27737, 0x5ac52d1b,
			0x5cb0679e, 0x4fa33742, 0xd3822740, 0x99bc9bbe,
			0xd5118e9d, 0xbf0f7315, 0xd62d1c7e, 0xc700c47b,
			0xb78c1b6b, 0x21a19045, 0xb26eb1be, 0x6a366eb4,
			0x5748ab2f, 0xbc946e79, 0xc6a376d2, 0x6549c2c8,
			0x530ff8ee, 0x468dde7d, 0xd5730a1d, 0x4cd04dc6,
			0x2939bbdb, 0xa9ba4650, 0xac9526e8, 0xbe5ee304,
			0xa1fad5f0, 0x6a2d519a, 0x63ef8ce2, 0x9a86ee22,
			0xc089c2b8, 0x43242ef6, 0xa51e03aa, 0x9cf2d0a4,
			0x83c061ba, 0x9be96a4d, 0x8fe51550, 0xba645bd6,
			0x2826a2f9, 0xa73a3ae1, 0x4ba99586, 0xef5562e9,
			0xc72fefd3, 0xf752f7da, 0x3f046f69, 0x77fa0a59,
			0x80e4a915, 0x87b08601, 0x9b09e6ad, 0x3b3ee593,
			0xe990fd5a, 0x9e34d797, 0x2cf0b7d9, 0x022b8b51,
			0x96d5ac3a, 0x017da67d, 0xd1cf3ed6, 0x7c7d2d28,
			0x1f9f25cf, 0xadf2b89b, 0x5ad6b472, 0x5a88f54c,
			0xe029ac71, 0xe019a5e6, 0x47b0acfd, 0xed93fa9b,
			0xe8d3c48d, 0x283b57cc, 0xf8d56629, 0x79132e28,
			0x785f0191, 0xed756055, 0xf7960e44, 0xe3d35e8c,
			0x15056dd4, 0x88f46dba, 0x03a16125, 0x0564f0bd,
			0xc3eb9e15, 0x3c9057a2, 0x97271aec, 0xa93a072a,
			0x1b3f6d9b, 0x1e6321f5, 0xf59c66fb, 0x26dcf319,
			0x7533d928, 0xb155fdf5, 0x03563482, 0x8aba3cbb,
			0x28517711, 0xc20ad9f8, 0xabcc5167, 0xccad925f,
			0x4de81751, 0x3830dc8e, 0x379d5862, 0x9320f991,
			0xea7a90c2, 0xfb3e7bce, 0x5121ce64, 0x774fbe32,
			0xa8b6e37e, 0xc3293d46, 0x48de5369, 0x6413e680,
			0xa2ae0810, 0xdd6db224, 0x69852dfd, 0x09072166,
			0xb39a460a, 0x6445c0dd, 0x586cdecf, 0x1c20c8ae,
			0x5bbef7dd, 0x1b588d40, 0xccd2017f, 0x6bb4e3bb,
			0xdda26a7e, 0x3a59ff45, 0x3e350a44, 0xbcb4cdd5,
			0x72eacea8, 0xfa6484bb, 0x8d6612ae, 0xbf3c6f47,
			0xd29be463, 0x542f5d9e, 0xaec2771b, 0xf64e6370,
			0x740e0d8d, 0xe75b1357, 0xf8721671, 0xaf537d5d,
			0x4040cb08, 0x4eb4e2cc, 0x34d2466a, 0x0115af84,
			0xe1b00428, 0x95983a1d, 0x06b89fb4, 0xce6ea048,
			0x6f3f3b82, 0x3520ab82, 0x011a1d4b, 0x277227f8,
			0x611560b1, 0xe7933fdc, 0xbb3a792b, 0x344525bd,
			0xa08839e1, 0x51ce794b, 0x2f32c9b7, 0xa01fbac9,
			0xe01cc87e, 0xbcc7d1f6, 0xcf0111c3, 0xa1e8aac7,
			0x1a908749, 0xd44fbd9a, 0xd0dadecb, 0xd50ada38,
			0x0339c32a, 0xc6913667, 0x8df9317c, 0xe0b12b4f,
			0xf79e59b7, 0x43f5bb3a, 0xf2d519ff, 0x27d9459c,
			0xbf97222c, 0x15e6fc2a, 0x0f91fc71, 0x9b941525,
			0xfae59361, 0xceb69ceb, 0xc2a86459, 0x12baa8d1,
			0xb6c1075e, 0xe3056a0c, 0x10d25065, 0xcb03a442,
			0xe0ec6e0e, 0x1698db3b, 0x4c98a0be, 0x3278e964,
			0x9f1f9532, 0xe0d392df, 0xd3a0342b, 0x8971f21e,
			0x1b0a7441, 0x4ba3348c, 0xc5be7120, 0xc37632d8,
			0xdf359f8d, 0x9b992f2e, 0xe60b6f47, 0x0fe3f11d,
			0xe54cda54, 0x1edad891, 0xce6279cf, 0xcd3e7e6f,
			0x1618b166, 0xfd2c1d05, 0x848fd2c5, 0xf6fb2299,
			0xf523f357, 0xa6327623, 0x93a83531, 0x56cccd02,
			0xacf08162, 0x5a75ebb5, 0x6e163697, 0x88d273cc,
			0xde966292, 0x81b949d0, 0x4c50901b, 0x71c65614,
			0xe6c6c7bd, 0x327a140a, 0x45e1d006, 0xc3f27b9a,
			0xc9aa53fd, 0x62a80f00, 0xbb25bfe2, 0x35bdd2f6,
			0x71126905, 0xb2040222, 0xb6cbcf7c, 0xcd769c2b,
			0x53113ec0, 0x1640e3d3, 0x38abbd60, 0x2547adf0,
			0xba38209c, 0xf746ce76, 0x77afa1c5, 0x20756060,
			0x85cbfe4e, 0x8ae88dd8, 0x7aaaf9b0, 0x4cf9aa7e,
			0x1948c25c, 0x02fb8a8c, 0x01c36ae4, 0xd6ebe1f9,
			0x90d4f869, 0xa65cdea0, 0x3f09252d, 0xc208e69f,
		0xb74e6132, 0xce77e25b, 0x578fdfe3, 0x3ac372e6}
	},
	{
		0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344,
		0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89,
		0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c,
		0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917,
		0x9216d5d9, 0x8979fb1b
	} };

	*c = init_state;

}

static u_int32_t
Blowfish_stream2word(const u_int8_t *data, u_int16_t databytes, u_int16_t *current)
{
	u_int8_t i;
	u_int16_t j;
	u_int32_t temp;

	temp = 0x00000000;
	j = *current;

	for (i = 0; i < 4; i++, j++) {
		if (j >= databytes)
			j = 0;
		temp = (temp << 8) | data[j];
	}

	*current = j;
	return temp;
}

static void
Blowfish_expand0state(blf_ctx *c, const u_int8_t *key, u_int16_t keybytes)
{
	u_int16_t i;
	u_int16_t j;
	u_int16_t k;
	u_int32_t temp;
	u_int32_t datal;
	u_int32_t datar;

	j = 0;
	for (i = 0; i < BLF_N + 2; i++) {
		/* Extract 4 int8 to 1 int32 from keystream */
		temp = Blowfish_stream2word(key, keybytes, &j);
		c->P[i] = c->P[i] ^ temp;
	}

	j = 0;
	datal = 0x00000000;
	datar = 0x00000000;
	for (i = 0; i < BLF_N + 2; i += 2) {
		Blowfish_encipher(c, &datal, &datar);

		c->P[i] = datal;
		c->P[i + 1] = datar;
	}

	for (i = 0; i < 4; i++) {
		for (k = 0; k < 256; k += 2) {
			Blowfish_encipher(c, &datal, &datar);

			c->S[i][k] = datal;
			c->S[i][k + 1] = datar;
		}
	}
}


static void
Blowfish_expandstate(blf_ctx *c, const u_int8_t *data, u_int16_t databytes,
		     const u_int8_t *key, u_int16_t keybytes)
{
	u_int16_t i;
	u_int16_t j;
	u_int16_t k;
	u_int32_t temp;
	u_int32_t datal;
	u_int32_t datar;

	j = 0;
	for (i = 0; i < BLF_N + 2; i++) {
		/* Extract 4 int8 to 1 int32 from keystream */
		temp = Blowfish_stream2word(key, keybytes, &j);
		c->P[i] = c->P[i] ^ temp;
	}

	j = 0;
	datal = 0x00000000;
	datar = 0x00000000;
	for (i = 0; i < BLF_N + 2; i += 2) {
		datal ^= Blowfish_stream2word(data, databytes, &j);
		datar ^= Blowfish_stream2word(data, databytes, &j);
		Blowfish_encipher(c, &datal, &datar);

		c->P[i] = datal;
		c->P[i + 1] = datar;
	}

	for (i = 0; i < 4; i++) {
		for (k = 0; k < 256; k += 2) {
			datal ^= Blowfish_stream2word(data, databytes, &j);
			datar ^= Blowfish_stream2word(data, databytes, &j);
			Blowfish_encipher(c, &datal, &datar);

			c->S[i][k] = datal;
			c->S[i][k + 1] = datar;
		}
	}

}

static void
blf_enc(blf_ctx *c, u_int32_t *data, u_int16_t blocks)
{
	u_int32_t *d;
	u_int16_t i;

	d = data;
	for (i = 0; i < blocks; i++) {
		Blowfish_encipher(c, d, d + 1);
		d += 2;
	}
}

/* This implementation is adaptable to current computing power.
 * You can have up to 2^31 rounds which should be enough for some
 * time to come.
 */

#define BCRYPT_VERSION '2'
#define BCRYPT_MAXSALT 16	/* Precomputation is just so nice */
#define BCRYPT_MAXSALTLEN 	(BCRYPT_MAXSALT * 4 / 3 + 1)
#define BCRYPT_BLOCKS 6		/* Ciphertext blocks */
#define BCRYPT_MINROUNDS 16	/* we have log2(rounds) in salt */

static void encode_salt(char *, u_int8_t *, u_int16_t, u_int8_t);
static void encode_base64(u_int8_t *, u_int8_t *, u_int16_t);
static void decode_base64(u_int8_t *, u_int16_t, const u_int8_t *);

static char    encrypted[PASSWORD_LEN];
static char    error[] = ":";

static const u_int8_t Base64Code[] =
"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

static const u_int8_t index_64[128] =
{
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 0, 1, 54, 55,
	56, 57, 58, 59, 60, 61, 62, 63, 255, 255,
	255, 255, 255, 255, 255, 2, 3, 4, 5, 6,
	7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
	17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
	255, 255, 255, 255, 255, 255, 28, 29, 30,
	31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
	41, 42, 43, 44, 45, 46, 47, 48, 49, 50,
	51, 52, 53, 255, 255, 255, 255, 255
};
#define CHAR64(c)  ( (c) > 127 ? 255 : index_64[(c)])

static void
decode_base64(u_int8_t *buffer, u_int16_t len, const u_int8_t *data)
{
	u_int8_t *bp = buffer;
	const u_int8_t *p = data;
	u_int8_t c1, c2, c3, c4;
	while (bp < buffer + len) {
		c1 = CHAR64(*p);
		c2 = CHAR64(*(p + 1));

		/* Invalid data */
		if (c1 == 255 || c2 == 255)
			break;

		*bp++ = ((u_int32_t)c1 << 2) | (((u_int32_t)c2 & 0x30) >> 4);
		if (bp >= buffer + len)
			break;

		c3 = CHAR64(*(p + 2));
		if (c3 == 255)
			break;

		*bp++ = (((u_int32_t)c2 & 0x0f) << 4) | (((uint32_t)c3 & 0x3c) >> 2);
		if (bp >= buffer + len)
			break;

		c4 = CHAR64(*(p + 3));
		if (c4 == 255)
			break;
		*bp++ = ((c3 & 0x03) << 6) | c4;

		p += 4;
	}
}

static void
encode_salt(char *salt, u_int8_t *csalt, u_int16_t clen, u_int8_t logr)
{
	salt[0] = '$';
	salt[1] = BCRYPT_VERSION;
	salt[2] = 'a';
	salt[3] = '$';

	snprintf(salt + 4, 4, "%2.2u$", logr);

	encode_base64((u_int8_t *) salt + 7, csalt, clen);
}

static int
nts_gensalt_blowfish(char *salt, size_t saltlen, const char *option)
{
	size_t i;
	u_int32_t seed = 0;
	u_int8_t csalt[BCRYPT_MAXSALT];
	unsigned long nrounds;
	char *ep;

	if (saltlen < BCRYPT_MAXSALTLEN) {
		errno = ENOSPC;
		return -1;
	}
	if (option == NULL) {
		errno = EINVAL;
		return -1;
	}
	nrounds = strtoul(option, &ep, 0);
	if (option == ep || *ep) {
		errno = EINVAL;
		return -1;
	}
	if (errno == ERANGE && nrounds == ULONG_MAX)
		return -1;

	if (nrounds > 255) {
		errno = EINVAL;
		return -1;
	}

	if (nrounds < 4)
		nrounds = 4;

	for (i = 0; i < BCRYPT_MAXSALT; i++) {
		if (i % 4 == 0)
			seed = arc4random();
		csalt[i] = seed & 0xff;
		seed = seed >> 8;
	}
	encode_salt(salt, csalt, BCRYPT_MAXSALT, (u_int8_t)nrounds);
	return 0;
}

/* We handle $Vers$log2(NumRounds)$salt+passwd$
   i.e. $2$04$iwouldntknowwhattosayetKdJ6iFtacBqJdKe6aW7ou */

char   *
nts_crypt_blowfish(key, salt)
	const char   *key;
	const char   *salt;
{
	blf_ctx state;
	u_int32_t rounds, i, k;
	u_int16_t j;
	u_int8_t key_len, salt_len, logr, minor;
	u_int8_t ciphertext[4 * BCRYPT_BLOCKS] = "OrpheanBeholderScryDoubt";
	u_int8_t csalt[BCRYPT_MAXSALT];
	u_int32_t cdata[BCRYPT_BLOCKS];

	/* Discard "$" identifier */
	salt++;

	if (*salt > BCRYPT_VERSION) {
		/* How do I handle errors ? Return ':' */
		return error;
	}

	/* Check for minor versions */
	if (salt[1] != '$') {
		 switch (salt[1]) {
		 case 'a':
			 /* 'ab' should not yield the same as 'abab' */
			 minor = salt[1];
			 salt++;
			 break;
		 default:
			 return error;
		 }
	} else
		 minor = 0;

	/* Discard version + "$" identifier */
	salt += 2;

	if (salt[2] != '$')
		/* Out of sync with passwd entry */
		return error;

	/* Computer power doesn't increase linear, 2^x should be fine */
	if ((rounds = (u_int32_t) 1 << (logr = atoi(salt))) < BCRYPT_MINROUNDS)
		return error;

	/* Discard num rounds + "$" identifier */
	salt += 3;

	if (strlen(salt) * 3 / 4 < BCRYPT_MAXSALT)
		return error;

	/* We dont want the base64 salt but the raw data */
	decode_base64(csalt, BCRYPT_MAXSALT, (const u_int8_t *)salt);
	salt_len = BCRYPT_MAXSALT;
	key_len = strlen(key) + (minor >= 'a' ? 1 : 0);

	/* Setting up S-Boxes and Subkeys */
	Blowfish_initstate(&state);
	Blowfish_expandstate(&state, csalt, salt_len,
	    (const u_int8_t *) key, key_len);
	for (k = 0; k < rounds; k++) {
		Blowfish_expand0state(&state, (const u_int8_t *) key, key_len);
		Blowfish_expand0state(&state, csalt, salt_len);
	}

	/* This can be precomputed later */
	j = 0;
	for (i = 0; i < BCRYPT_BLOCKS; i++)
		cdata[i] = Blowfish_stream2word(ciphertext, 4 * BCRYPT_BLOCKS, &j);

	/* Now do the encryption */
	for (k = 0; k < 64; k++)
		blf_enc(&state, cdata, BCRYPT_BLOCKS / 2);

	for (i = 0; i < BCRYPT_BLOCKS; i++) {
		ciphertext[4 * i + 3] = cdata[i] & 0xff;
		cdata[i] = cdata[i] >> 8;
		ciphertext[4 * i + 2] = cdata[i] & 0xff;
		cdata[i] = cdata[i] >> 8;
		ciphertext[4 * i + 1] = cdata[i] & 0xff;
		cdata[i] = cdata[i] >> 8;
		ciphertext[4 * i + 0] = cdata[i] & 0xff;
	}


	i = 0;
	encrypted[i++] = '$';
	encrypted[i++] = BCRYPT_VERSION;
	if (minor)
		encrypted[i++] = minor;
	encrypted[i++] = '$';

	snprintf(encrypted + i, 4, "%2.2u$", logr);

	encode_base64((u_int8_t *) encrypted + i + 3, csalt, BCRYPT_MAXSALT);
	encode_base64((u_int8_t *) encrypted + strlen(encrypted), ciphertext,
	    4 * BCRYPT_BLOCKS - 1);
	return encrypted;
}

static void
encode_base64(u_int8_t *buffer, u_int8_t *data, u_int16_t len)
{
	u_int8_t *bp = buffer;
	u_int8_t *p = data;
	u_int8_t c1, c2;
	while (p < data + len) {
		c1 = *p++;
		*bp++ = Base64Code[((u_int32_t)c1 >> 2)];
		c1 = (c1 & 0x03) << 4;
		if (p >= data + len) {
			*bp++ = Base64Code[c1];
			break;
		}
		c2 = *p++;
		c1 |= ((u_int32_t)c2 >> 4) & 0x0f;
		*bp++ = Base64Code[c1];
		c1 = (c2 & 0x0f) << 2;
		if (p >= data + len) {
			*bp++ = Base64Code[c1];
			break;
		}
		c2 = *p++;
		c1 |= ((u_int32_t)c2 >> 6) & 0x03;
		*bp++ = Base64Code[c1];
		*bp++ = Base64Code[c2 & 0x3f];
	}
	*bp = '\0';
}

/*****
 *
 * md5crypt
 */

/*	$NetBSD: md5crypt.c,v 1.9 2007/01/17 23:24:22 hubertf Exp $	*/

/*
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <phk@login.dknet.dk> wrote this file.  As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.   Poul-Henning Kamp
 * ----------------------------------------------------------------------------
 *
 * from FreeBSD: crypt.c,v 1.5 1996/10/14 08:34:02 phk Exp
 * via OpenBSD: md5crypt.c,v 1.9 1997/07/23 20:58:27 kstailey Exp
 *
 */

#define MD5_MAGIC	"$1$"
#define MD5_MAGIC_LEN	3

#define	INIT(x)			nts_MD5Init((x))
#define	UPDATE(x, b, l)		nts_MD5Update((x), (b), (l))
#define	FINAL(v, x)		nts_MD5Final((v), (x))


/*	$NetBSD: md5c.c,v 1.3 2008/02/16 17:37:13 apb Exp $	*/

/*
 * This file is derived from the RSA Data Security, Inc. MD5 Message-Digest
 * Algorithm and has been modified by Jason R. Thorpe <thorpej@NetBSD.org>
 * for portability and formatting.
 */

/*
 * Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
 * rights reserved.
 *
 * License to copy and use this software is granted provided that it
 * is identified as the "RSA Data Security, Inc. MD5 Message-Digest
 * Algorithm" in all material mentioning or referencing this software
 * or this function.
 *
 * License is also granted to make and use derivative works provided
 * that such works are identified as "derived from the RSA Data
 * Security, Inc. MD5 Message-Digest Algorithm" in all material
 * mentioning or referencing the derived work.
 *
 * RSA Data Security, Inc. makes no representations concerning either
 * the merchantability of this software or the suitability of this
 * software for any particular purpose. It is provided "as is"
 * without express or implied warranty of any kind.
 *
 * These notices must be retained in any copies of any part of this
 * documentation and/or software.
 */

#define	ZEROIZE(d, l)		memset((d), 0, (l))

typedef unsigned char *POINTER;
typedef uint16_t UINT2;
typedef uint32_t UINT4;

/*
 * Constants for MD5Transform routine.
 */
#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

/*	$NetBSD: md5.h,v 1.9 2005/12/26 18:41:36 perry Exp $	*/

/*
 * This file is derived from the RSA Data Security, Inc. MD5 Message-Digest
 * Algorithm and has been modified by Jason R. Thorpe <thorpej@NetBSD.org>
 * for portability and formatting.
 */

/*
 * Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
 * rights reserved.
 *
 * License to copy and use this software is granted provided that it
 * is identified as the "RSA Data Security, Inc. MD5 Message-Digest
 * Algorithm" in all material mentioning or referencing this software
 * or this function.
 *
 * License is also granted to make and use derivative works provided
 * that such works are identified as "derived from the RSA Data
 * Security, Inc. MD5 Message-Digest Algorithm" in all material
 * mentioning or referencing the derived work.
 *
 * RSA Data Security, Inc. makes no representations concerning either
 * the merchantability of this software or the suitability of this
 * software for any particular purpose. It is provided "as is"
 * without express or implied warranty of any kind.
 *
 * These notices must be retained in any copies of any part of this
 * documentation and/or software.
 */

#define MD5_DIGEST_LENGTH		16
#define	MD5_DIGEST_STRING_LENGTH	33

/* MD5 context. */
typedef struct MD5Context {
	uint32_t state[4];	/* state (ABCD) */
	uint32_t count[2];	/* number of bits, modulo 2^64 (lsb first) */
	unsigned char buffer[64]; /* input buffer */
} MD5_CTX;

void	nts_MD5Init(MD5_CTX *);
void	nts_MD5Update(MD5_CTX *, const unsigned char *, unsigned int);
void	nts_MD5Final(unsigned char[MD5_DIGEST_LENGTH], MD5_CTX *);

static void MD5Transform (UINT4 [4], const unsigned char [64]);

static void Encode(unsigned char *, UINT4 *, unsigned int);
static void Decode(UINT4 *, const unsigned char *, unsigned int);

/*
 * Encodes input (UINT4) into output (unsigned char).  Assumes len is
 * a multiple of 4.
 */
static void
Encode (output, input, len)
	unsigned char *output;
	UINT4 *input;
	unsigned int len;
{
	unsigned int i, j;

	for (i = 0, j = 0; j < len; i++, j += 4) {
		output[j] = (unsigned char)(input[i] & 0xff);
		output[j+1] = (unsigned char)((input[i] >> 8) & 0xff);
		output[j+2] = (unsigned char)((input[i] >> 16) & 0xff);
		output[j+3] = (unsigned char)((input[i] >> 24) & 0xff);
	}
}

/*
 * Decodes input (unsigned char) into output (UINT4).  Assumes len is
 * a multiple of 4.
 */
static void
Decode (output, input, len)
	UINT4 *output;
	const unsigned char *input;
	unsigned int len;
{
	unsigned int i, j;

	for (i = 0, j = 0; j < len; i++, j += 4)
		output[i] = ((UINT4)input[j]) | (((UINT4)input[j+1]) << 8) |
		    (((UINT4)input[j+2]) << 16) | (((UINT4)input[j+3]) << 24);
}

static const unsigned char PADDING[64] = {
	0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/*
 * F, G, H and I are basic MD5 functions.
 */
#undef F
#define F(x, y, z)	(((x) & (y)) | ((~x) & (z)))
#define G(x, y, z)	(((x) & (z)) | ((y) & (~z)))
#define H(x, y, z)	((x) ^ (y) ^ (z))
#define I(x, y, z)	((y) ^ ((x) | (~z)))

/*
 * ROTATE_LEFT rotates x left n bits.
 */
#define ROTATE_LEFT(x, n)	(((x) << (n)) | ((x) >> (32-(n))))

/*
 * FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.
 * Rotation is separate from addition to prevent recomputation.
 */
#define FF(a, b, c, d, x, s, ac) { \
	(a) += F ((b), (c), (d)) + (x) + (UINT4)(ac); \
	(a) = ROTATE_LEFT ((a), (s)); \
	(a) += (b); \
}

#define GG(a, b, c, d, x, s, ac) { \
	(a) += G ((b), (c), (d)) + (x) + (UINT4)(ac); \
	(a) = ROTATE_LEFT ((a), (s)); \
	(a) += (b); \
}

#define HH(a, b, c, d, x, s, ac) { \
	(a) += H ((b), (c), (d)) + (x) + (UINT4)(ac); \
	(a) = ROTATE_LEFT ((a), (s)); \
	(a) += (b); \
}

#define II(a, b, c, d, x, s, ac) { \
	(a) += I ((b), (c), (d)) + (x) + (UINT4)(ac); \
	(a) = ROTATE_LEFT ((a), (s)); \
	(a) += (b); \
}

/*
 * MD5 initialization. Begins an MD5 operation, writing a new context.
 */
void
nts_MD5Init(context)
	MD5_CTX *context;		/* context */
{
	context->count[0] = context->count[1] = 0;

	/* Load magic initialization constants. */
	context->state[0] = 0x67452301;
	context->state[1] = 0xefcdab89;
	context->state[2] = 0x98badcfe;
	context->state[3] = 0x10325476;
}

/*
 * MD5 block update operation.  Continues an MD5 message-digest
 * operation, processing another message block, and updating the
 * context.
 */
void
nts_MD5Update(context, input, inputLen)
	MD5_CTX *context;		/* context */
	const unsigned char *input;	/* input block */
	unsigned int inputLen;		/* length of input block */
{
	unsigned int i, idx, partLen;

	/* Compute number of bytes mod 64 */
	idx = (unsigned int)((context->count[0] >> 3) & 0x3F);

	/* Update number of bits */
	if ((context->count[0] += ((UINT4)inputLen << 3))
	    < ((UINT4)inputLen << 3))
		context->count[1]++;
	context->count[1] += ((UINT4)inputLen >> 29);

	partLen = 64 - idx;

	/* Transform as many times as possible. */
	if (inputLen >= partLen) {
		memcpy((POINTER)&context->buffer[idx], input, partLen);
		MD5Transform(context->state, context->buffer);

		for (i = partLen; i + 63 < inputLen; i += 64)
			MD5Transform(context->state, &input[i]);

		idx = 0;
	} else
		i = 0;

	/* Buffer remaining input */
	memcpy(&context->buffer[idx], &input[i], inputLen - i);
}

/*
 * MD5 finalization.  Ends an MD5 message-digest operation, writing the
 * message digest and zeroing the context.
 */
void
nts_MD5Final(digest, context)
	unsigned char digest[16];	/* message digest */
	MD5_CTX *context;		/* context */
{
	unsigned char bits[8];
	unsigned int idx, padLen;

	/* Save number of bits */
	Encode(bits, context->count, 8);

	/* Pad out to 56 mod 64. */
	idx = (unsigned int)((context->count[0] >> 3) & 0x3f);
	padLen = (idx < 56) ? (56 - idx) : (120 - idx);
	nts_MD5Update (context, PADDING, padLen);

	/* Append length (before padding) */
	nts_MD5Update(context, bits, 8);

	/* Store state in digest */
	Encode(digest, context->state, 16);

	/* Zeroize sensitive information. */
	ZEROIZE((POINTER)(void *)context, sizeof(*context));
}

/*
 * MD5 basic transformation. Transforms state based on block.
 */
static void
MD5Transform(state, block)
	UINT4 state[4];
	const unsigned char block[64];
{
	UINT4 a = state[0], b = state[1], c = state[2], d = state[3], x[16];

	Decode(x, block, 64);

	/* Round 1 */
	FF (a, b, c, d, x[ 0], S11, 0xd76aa478); /* 1 */
	FF (d, a, b, c, x[ 1], S12, 0xe8c7b756); /* 2 */
	FF (c, d, a, b, x[ 2], S13, 0x242070db); /* 3 */
	FF (b, c, d, a, x[ 3], S14, 0xc1bdceee); /* 4 */
	FF (a, b, c, d, x[ 4], S11, 0xf57c0faf); /* 5 */
	FF (d, a, b, c, x[ 5], S12, 0x4787c62a); /* 6 */
	FF (c, d, a, b, x[ 6], S13, 0xa8304613); /* 7 */
	FF (b, c, d, a, x[ 7], S14, 0xfd469501); /* 8 */
	FF (a, b, c, d, x[ 8], S11, 0x698098d8); /* 9 */
	FF (d, a, b, c, x[ 9], S12, 0x8b44f7af); /* 10 */
	FF (c, d, a, b, x[10], S13, 0xffff5bb1); /* 11 */
	FF (b, c, d, a, x[11], S14, 0x895cd7be); /* 12 */
	FF (a, b, c, d, x[12], S11, 0x6b901122); /* 13 */
	FF (d, a, b, c, x[13], S12, 0xfd987193); /* 14 */
	FF (c, d, a, b, x[14], S13, 0xa679438e); /* 15 */
	FF (b, c, d, a, x[15], S14, 0x49b40821); /* 16 */

	/* Round 2 */
	GG (a, b, c, d, x[ 1], S21, 0xf61e2562); /* 17 */
	GG (d, a, b, c, x[ 6], S22, 0xc040b340); /* 18 */
	GG (c, d, a, b, x[11], S23, 0x265e5a51); /* 19 */
	GG (b, c, d, a, x[ 0], S24, 0xe9b6c7aa); /* 20 */
	GG (a, b, c, d, x[ 5], S21, 0xd62f105d); /* 21 */
	GG (d, a, b, c, x[10], S22,  0x2441453); /* 22 */
	GG (c, d, a, b, x[15], S23, 0xd8a1e681); /* 23 */
	GG (b, c, d, a, x[ 4], S24, 0xe7d3fbc8); /* 24 */
	GG (a, b, c, d, x[ 9], S21, 0x21e1cde6); /* 25 */
	GG (d, a, b, c, x[14], S22, 0xc33707d6); /* 26 */
	GG (c, d, a, b, x[ 3], S23, 0xf4d50d87); /* 27 */
	GG (b, c, d, a, x[ 8], S24, 0x455a14ed); /* 28 */
	GG (a, b, c, d, x[13], S21, 0xa9e3e905); /* 29 */
	GG (d, a, b, c, x[ 2], S22, 0xfcefa3f8); /* 30 */
	GG (c, d, a, b, x[ 7], S23, 0x676f02d9); /* 31 */
	GG (b, c, d, a, x[12], S24, 0x8d2a4c8a); /* 32 */

	/* Round 3 */
	HH (a, b, c, d, x[ 5], S31, 0xfffa3942); /* 33 */
	HH (d, a, b, c, x[ 8], S32, 0x8771f681); /* 34 */
	HH (c, d, a, b, x[11], S33, 0x6d9d6122); /* 35 */
	HH (b, c, d, a, x[14], S34, 0xfde5380c); /* 36 */
	HH (a, b, c, d, x[ 1], S31, 0xa4beea44); /* 37 */
	HH (d, a, b, c, x[ 4], S32, 0x4bdecfa9); /* 38 */
	HH (c, d, a, b, x[ 7], S33, 0xf6bb4b60); /* 39 */
	HH (b, c, d, a, x[10], S34, 0xbebfbc70); /* 40 */
	HH (a, b, c, d, x[13], S31, 0x289b7ec6); /* 41 */
	HH (d, a, b, c, x[ 0], S32, 0xeaa127fa); /* 42 */
	HH (c, d, a, b, x[ 3], S33, 0xd4ef3085); /* 43 */
	HH (b, c, d, a, x[ 6], S34,  0x4881d05); /* 44 */
	HH (a, b, c, d, x[ 9], S31, 0xd9d4d039); /* 45 */
	HH (d, a, b, c, x[12], S32, 0xe6db99e5); /* 46 */
	HH (c, d, a, b, x[15], S33, 0x1fa27cf8); /* 47 */
	HH (b, c, d, a, x[ 2], S34, 0xc4ac5665); /* 48 */

	/* Round 4 */
	II (a, b, c, d, x[ 0], S41, 0xf4292244); /* 49 */
	II (d, a, b, c, x[ 7], S42, 0x432aff97); /* 50 */
	II (c, d, a, b, x[14], S43, 0xab9423a7); /* 51 */
	II (b, c, d, a, x[ 5], S44, 0xfc93a039); /* 52 */
	II (a, b, c, d, x[12], S41, 0x655b59c3); /* 53 */
	II (d, a, b, c, x[ 3], S42, 0x8f0ccc92); /* 54 */
	II (c, d, a, b, x[10], S43, 0xffeff47d); /* 55 */
	II (b, c, d, a, x[ 1], S44, 0x85845dd1); /* 56 */
	II (a, b, c, d, x[ 8], S41, 0x6fa87e4f); /* 57 */
	II (d, a, b, c, x[15], S42, 0xfe2ce6e0); /* 58 */
	II (c, d, a, b, x[ 6], S43, 0xa3014314); /* 59 */
	II (b, c, d, a, x[13], S44, 0x4e0811a1); /* 60 */
	II (a, b, c, d, x[ 4], S41, 0xf7537e82); /* 61 */
	II (d, a, b, c, x[11], S42, 0xbd3af235); /* 62 */
	II (c, d, a, b, x[ 2], S43, 0x2ad7d2bb); /* 63 */
	II (b, c, d, a, x[ 9], S44, 0xeb86d391); /* 64 */

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;

	/* Zeroize sensitive information. */
	ZEROIZE((POINTER)(void *)x, sizeof (x));
}

/*
 * MD5 password encryption.
 */
char *
nts_crypt_md5(const char *pw, const char *salt)
{
	static char passwd[120], *p;
	const char *sp, *ep;
	unsigned char final[16];
	unsigned int i, sl, pwl;
	MD5_CTX	ctx, ctx1;
	u_int32_t l;
	int pl;
	
	pwl = strlen(pw);
	
	/* Refine the salt first */
	sp = salt;

	/* If it starts with the magic string, then skip that */
	if (strncmp(sp, MD5_MAGIC, MD5_MAGIC_LEN) == 0)
		sp += MD5_MAGIC_LEN;

	/* It stops at the first '$', max 8 chars */
	for (ep = sp; *ep != '\0' && *ep != '$' && ep < (sp + 8); ep++)
		continue;

	/* get the length of the true salt */
	sl = ep - sp;

	INIT(&ctx);

	/* The password first, since that is what is most unknown */
	UPDATE(&ctx, (const unsigned char *)pw, pwl);

	/* Then our magic string */
	UPDATE(&ctx, (const unsigned char *)MD5_MAGIC, MD5_MAGIC_LEN);

	/* Then the raw salt */
	UPDATE(&ctx, (const unsigned char *)sp, sl);

	/* Then just as many characters of the MD5(pw,salt,pw) */
	INIT(&ctx1);
	UPDATE(&ctx1, (const unsigned char *)pw, pwl);
	UPDATE(&ctx1, (const unsigned char *)sp, sl);
	UPDATE(&ctx1, (const unsigned char *)pw, pwl);
	FINAL(final, &ctx1);

	for (pl = pwl; pl > 0; pl -= 16)
		UPDATE(&ctx, final, (unsigned int)(pl > 16 ? 16 : pl));

	/* Don't leave anything around in vm they could use. */
	memset(final, 0, sizeof(final));

	/* Then something really weird... */
	for (i = pwl; i != 0; i >>= 1)
		if ((i & 1) != 0)
		    UPDATE(&ctx, final, 1);
		else
		    UPDATE(&ctx, (const unsigned char *)pw, 1);

	/* Now make the output string */
	memcpy(passwd, MD5_MAGIC, MD5_MAGIC_LEN);
	strlcpy(passwd + MD5_MAGIC_LEN, sp, sl + 1);
	strlcat(passwd, "$", sizeof(passwd));

	FINAL(final, &ctx);

	/*
	 * And now, just to make sure things don't run too fast. On a 60 MHz
	 * Pentium this takes 34 msec, so you would need 30 seconds to build
	 * a 1000 entry dictionary...
	 */
	for (i = 0; i < 1000; i++) {
		INIT(&ctx1);

		if ((i & 1) != 0)
			UPDATE(&ctx1, (const unsigned char *)pw, pwl);
		else
			UPDATE(&ctx1, final, 16);

		if ((i % 3) != 0)
			UPDATE(&ctx1, (const unsigned char *)sp, sl);

		if ((i % 7) != 0)
			UPDATE(&ctx1, (const unsigned char *)pw, pwl);

		if ((i & 1) != 0)
			UPDATE(&ctx1, final, 16);
		else
			UPDATE(&ctx1, (const unsigned char *)pw, pwl);

		FINAL(final, &ctx1);
	}

	p = passwd + sl + MD5_MAGIC_LEN + 1;

	l = (final[ 0]<<16) | (final[ 6]<<8) | final[12]; nts_crypt_to64(p,l,4); p += 4;
	l = (final[ 1]<<16) | (final[ 7]<<8) | final[13]; nts_crypt_to64(p,l,4); p += 4;
	l = (final[ 2]<<16) | (final[ 8]<<8) | final[14]; nts_crypt_to64(p,l,4); p += 4;
	l = (final[ 3]<<16) | (final[ 9]<<8) | final[15]; nts_crypt_to64(p,l,4); p += 4;
	l = (final[ 4]<<16) | (final[10]<<8) | final[ 5]; nts_crypt_to64(p,l,4); p += 4;
	l =		       final[11]		; nts_crypt_to64(p,l,2); p += 2;
	*p = '\0';

	/* Don't leave anything around in vm they could use. */
	memset(final, 0, sizeof(final));
	return (passwd);
}

/*****
 *
 * sha-1
 */

/* $NetBSD: hmac_sha1.c,v 1.1 2006/10/27 18:22:56 drochner Exp $ */

/*
 * hmac_sha1 - using HMAC from RFC 2104
 */


/*	$NetBSD: sha1.h,v 1.13 2005/12/26 18:41:36 perry Exp $	*/

/*
 * SHA-1 in C
 * By Steve Reid <steve@edmweb.com>
 * 100% Public Domain
 */

#define SHA1_DIGEST_LENGTH		20
#define SHA1_DIGEST_STRING_LENGTH	41

typedef struct {
	uint32_t state[5];
	uint32_t count[2];
	u_char buffer[64];
} SHA1_CTX;

void	nts_SHA1Transform(uint32_t[5], const u_char[64]);
void	nts_SHA1Init(SHA1_CTX *);
void	nts_SHA1Update(SHA1_CTX *, const u_char *, u_int);
void	nts_SHA1Final(u_char[SHA1_DIGEST_LENGTH], SHA1_CTX *);

#define HMAC_HASH SHA1
#define HMAC_FUNC nts_hmac_sha1

#define HASH_LENGTH SHA1_DIGEST_LENGTH
#define HASH_CTX SHA1_CTX
#define HASH_Init nts_SHA1Init
#define HASH_Update nts_SHA1Update
#define HASH_Final nts_SHA1Final


/*	$NetBSD: sha1.c,v 1.3 2008/02/16 17:37:13 apb Exp $	*/
/*	$OpenBSD: sha1.c,v 1.9 1997/07/23 21:12:32 kstailey Exp $	*/

/*
 * SHA-1 in C
 * By Steve Reid <steve@edmweb.com>
 * 100% Public Domain
 *
 * Test Vectors (from FIPS PUB 180-1)
 * "abc"
 *   A9993E36 4706816A BA3E2571 7850C26C 9CD0D89D
 * "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
 *   84983E44 1C3BD26E BAAE4AA1 F95129E5 E54670F1
 * A million repetitions of "a"
 *   34AA973C D4C4DAA4 F61EEB2B DBAD2731 6534016F
 */

#define SHA1HANDSOFF		/* Copies data before messing with it. */

#define rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

/*
 * blk0() and blk() perform the initial expand.
 * I got the idea of expanding during the round function from SSLeay
 */
#if BYTE_ORDER == LITTLE_ENDIAN
# define blk0(i) (block->l[i] = (rol(block->l[i],24)&0xFF00FF00) \
    |(rol(block->l[i],8)&0x00FF00FF))
#else
# define blk0(i) block->l[i]
#endif
#define blk(i) (block->l[i&15] = rol(block->l[(i+13)&15]^block->l[(i+8)&15] \
    ^block->l[(i+2)&15]^block->l[i&15],1))

/*
 * (R0+R1), R2, R3, R4 are the different operations (rounds) used in SHA1
 */
#define R0(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk0(i)+0x5A827999+rol(v,5);w=rol(w,30);
#define R1(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk(i)+0x5A827999+rol(v,5);w=rol(w,30);
#define R2(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0x6ED9EBA1+rol(v,5);w=rol(w,30);
#define R3(v,w,x,y,z,i) z+=(((w|x)&y)|(w&x))+blk(i)+0x8F1BBCDC+rol(v,5);w=rol(w,30);
#define R4(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0xCA62C1D6+rol(v,5);w=rol(w,30);

typedef union {
    u_char c[64];
    u_int l[16];
} CHAR64LONG16;

/*
 * Hash a single 512-bit block. This is the core of the algorithm.
 */
void nts_SHA1Transform(state, buffer)
    uint32_t state[5];
    const u_char buffer[64];
{
    uint32_t a, b, c, d, e;
    CHAR64LONG16 *block;

#ifdef SHA1HANDSOFF
    CHAR64LONG16 workspace;
#endif

#ifdef SHA1HANDSOFF
    block = &workspace;
    (void)memcpy(block, buffer, 64);
#else
    block = (CHAR64LONG16 *)(void *)buffer;
#endif

    /* Copy context->state[] to working vars */
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];

    /* 4 rounds of 20 operations each. Loop unrolled. */
    R0(a,b,c,d,e, 0); R0(e,a,b,c,d, 1); R0(d,e,a,b,c, 2); R0(c,d,e,a,b, 3);
    R0(b,c,d,e,a, 4); R0(a,b,c,d,e, 5); R0(e,a,b,c,d, 6); R0(d,e,a,b,c, 7);
    R0(c,d,e,a,b, 8); R0(b,c,d,e,a, 9); R0(a,b,c,d,e,10); R0(e,a,b,c,d,11);
    R0(d,e,a,b,c,12); R0(c,d,e,a,b,13); R0(b,c,d,e,a,14); R0(a,b,c,d,e,15);
    R1(e,a,b,c,d,16); R1(d,e,a,b,c,17); R1(c,d,e,a,b,18); R1(b,c,d,e,a,19);
    R2(a,b,c,d,e,20); R2(e,a,b,c,d,21); R2(d,e,a,b,c,22); R2(c,d,e,a,b,23);
    R2(b,c,d,e,a,24); R2(a,b,c,d,e,25); R2(e,a,b,c,d,26); R2(d,e,a,b,c,27);
    R2(c,d,e,a,b,28); R2(b,c,d,e,a,29); R2(a,b,c,d,e,30); R2(e,a,b,c,d,31);
    R2(d,e,a,b,c,32); R2(c,d,e,a,b,33); R2(b,c,d,e,a,34); R2(a,b,c,d,e,35);
    R2(e,a,b,c,d,36); R2(d,e,a,b,c,37); R2(c,d,e,a,b,38); R2(b,c,d,e,a,39);
    R3(a,b,c,d,e,40); R3(e,a,b,c,d,41); R3(d,e,a,b,c,42); R3(c,d,e,a,b,43);
    R3(b,c,d,e,a,44); R3(a,b,c,d,e,45); R3(e,a,b,c,d,46); R3(d,e,a,b,c,47);
    R3(c,d,e,a,b,48); R3(b,c,d,e,a,49); R3(a,b,c,d,e,50); R3(e,a,b,c,d,51);
    R3(d,e,a,b,c,52); R3(c,d,e,a,b,53); R3(b,c,d,e,a,54); R3(a,b,c,d,e,55);
    R3(e,a,b,c,d,56); R3(d,e,a,b,c,57); R3(c,d,e,a,b,58); R3(b,c,d,e,a,59);
    R4(a,b,c,d,e,60); R4(e,a,b,c,d,61); R4(d,e,a,b,c,62); R4(c,d,e,a,b,63);
    R4(b,c,d,e,a,64); R4(a,b,c,d,e,65); R4(e,a,b,c,d,66); R4(d,e,a,b,c,67);
    R4(c,d,e,a,b,68); R4(b,c,d,e,a,69); R4(a,b,c,d,e,70); R4(e,a,b,c,d,71);
    R4(d,e,a,b,c,72); R4(c,d,e,a,b,73); R4(b,c,d,e,a,74); R4(a,b,c,d,e,75);
    R4(e,a,b,c,d,76); R4(d,e,a,b,c,77); R4(c,d,e,a,b,78); R4(b,c,d,e,a,79);

    /* Add the working vars back into context.state[] */
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;

    /* Wipe variables */
    a = b = c = d = e = 0;
}


/*
 * SHA1Init - Initialize new context
 */
void nts_SHA1Init(context)
    SHA1_CTX *context;
{
    /* SHA1 initialization constants */
    context->state[0] = 0x67452301;
    context->state[1] = 0xEFCDAB89;
    context->state[2] = 0x98BADCFE;
    context->state[3] = 0x10325476;
    context->state[4] = 0xC3D2E1F0;
    context->count[0] = context->count[1] = 0;
}

/*
 * Run your data through this.
 */
void nts_SHA1Update(context, data, len)
    SHA1_CTX *context;
    const u_char *data;
    u_int len;
{
    u_int i, j;

    j = context->count[0];
    if ((context->count[0] += len << 3) < j)
	context->count[1] += (len>>29)+1;
    j = (j >> 3) & 63;
    if ((j + len) > 63) {
	(void)memcpy(&context->buffer[j], data, (i = 64-j));
	nts_SHA1Transform(context->state, context->buffer);
	for ( ; i + 63 < len; i += 64)
	    nts_SHA1Transform(context->state, &data[i]);
	j = 0;
    } else {
	i = 0;
    }
    (void)memcpy(&context->buffer[j], &data[i], len - i);
}


/*
 * Add padding and return the message digest.
 */
void nts_SHA1Final(digest, context)
    u_char digest[20];
    SHA1_CTX* context;
{
    u_int i;
    u_char finalcount[8];

    for (i = 0; i < 8; i++) {
	finalcount[i] = (u_char)((context->count[(i >= 4 ? 0 : 1)]
	 >> ((3-(i & 3)) * 8) ) & 255);	 /* Endian independent */
    }
    nts_SHA1Update(context, (const u_char *)"\200", 1);
    while ((context->count[0] & 504) != 448)
	nts_SHA1Update(context, (const u_char *)"\0", 1);
    nts_SHA1Update(context, finalcount, 8);  /* Should cause a SHA1Transform() */

    if (digest) {
	for (i = 0; i < 20; i++)
	    digest[i] = (u_char)
		((context->state[i>>2] >> ((3-(i & 3)) * 8) ) & 255);
    }
}

/* $NetBSD: hmac.c,v 1.1 2006/10/27 18:22:56 drochner Exp $ */

/*
 * Copyright (c) 2004, Juniper Networks, Inc.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions 
 * are met: 
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.  
 * 3. Neither the name of the copyright holders nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission. 
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. 
 */
/*
 * Implement HMAC as described in RFC 2104
 *
 * You need to define the following before including this file.
 *
 * HMAC_FUNC the name of the function (hmac_sha1 or hmac_md5 etc)
 * HASH_LENGTH the size of the digest (20 for SHA1, 16 for MD5)
 * HASH_CTX the name of the HASH CTX
 * HASH_Init
 * HASH_Update
 * Hash_Final
 */

/* Don't change these */
#define HMAC_IPAD 0x36
#define HMAC_OPAD 0x5c

/* Nor this */
#ifndef HMAC_BLOCKSZ
# define HMAC_BLOCKSZ 64
#endif

/*
 * The logic here is lifted straight from RFC 2104 except that
 * rather than filling the pads with 0, copying in the key and then
 * XOR with the pad byte, we just fill with the pad byte and
 * XOR with the key.
 */
void
nts_hmac_sha1 (const unsigned char *text, size_t text_len,
	   const unsigned char *key, size_t key_len,
	   unsigned char *digest)
{
    HASH_CTX context;
    /* Inner padding key XOR'd with ipad */
    unsigned char k_ipad[HMAC_BLOCKSZ + 1];
    /* Outer padding key XOR'd with opad */
    unsigned char k_opad[HMAC_BLOCKSZ + 1];
    /* HASH(key) if needed */
    unsigned char tk[HASH_LENGTH];	
    int i;

    /*
     * If key is longer than HMAC_BLOCKSZ bytes
     * reset it to key=HASH(key)
     */
    if (key_len > HMAC_BLOCKSZ) {
	HASH_CTX      tctx;

	HASH_Init(&tctx);
	HASH_Update(&tctx, key, key_len);
	HASH_Final(tk, &tctx);

	key = tk;
	key_len = HASH_LENGTH;
    }

    /*
     * The HMAC_ transform looks like:
     *
     * HASH(K XOR opad, HASH(K XOR ipad, text))
     *
     * where K is an n byte key
     * ipad is the byte HMAC_IPAD repeated HMAC_BLOCKSZ times
     * opad is the byte HMAC_OPAD repeated HMAC_BLOCKSZ times
     * and text is the data being protected
     */

    /*
     * Fill the pads and XOR in the key
     */
    memset( k_ipad, HMAC_IPAD, sizeof k_ipad);
    memset( k_opad, HMAC_OPAD, sizeof k_opad);
    for (i = 0; i < key_len; i++) {
	k_ipad[i] ^= key[i];
	k_opad[i] ^= key[i];
    }

    /*
     * Perform inner HASH.
     * Start with inner pad,
     * then the text.
     */
    HASH_Init(&context);
    HASH_Update(&context, k_ipad, HMAC_BLOCKSZ);
    HASH_Update(&context, text, text_len);
    HASH_Final(digest, &context);

    /*
     * Perform outer HASH.
     * Start with the outer pad,
     * then the result of the inner hash.
     */
    HASH_Init(&context);
    HASH_Update(&context, k_opad, HMAC_BLOCKSZ);
    HASH_Update(&context, digest, HASH_LENGTH);
    HASH_Final(digest, &context);
}

/* $NetBSD: crypt-sha1.c,v 1.3 2006/10/27 18:22:56 drochner Exp $ */

/*
 * Copyright (c) 2004, Juniper Networks, Inc.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions 
 * are met: 
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.  
 * 3. Neither the name of the copyright holders nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission. 
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. 
 */

/*
 * The default iterations - should take >0s on a fast CPU
 * but not be insane for a slow CPU.
 */
#ifndef CRYPT_SHA1_ITERATIONS
# define CRYPT_SHA1_ITERATIONS 24680
#endif
/*
 * Support a reasonably? long salt.
 */
#ifndef CRYPT_SHA1_SALT_LENGTH
# define CRYPT_SHA1_SALT_LENGTH 64
#endif

/*
 * This may be called from crypt_sha1 or gensalt.
 *
 * The value returned will be slightly less than <hint> which defaults
 * to 24680.  The goals are that the number of iterations should take
 * non-zero amount of time on a fast cpu while not taking insanely
 * long on a slow cpu.  The current default will take about 5 seconds
 * on a 100MHz sparc, and about 0.04 seconds on a 3GHz i386.
 * The number is varied to frustrate those attempting to generate a
 * dictionary of pre-computed hashes.
 */
unsigned int
nts_crypt_sha1_iterations (unsigned int hint)
{
    static int once = 1;

    /*
     * We treat CRYPT_SHA1_ITERATIONS as a hint.
     * Make it harder for someone to pre-compute hashes for a
     * dictionary attack by not using the same iteration count for
     * every entry.
     */

    if (once) {
	int pid = getpid();
	
	srandom(time(NULL) ^ (pid * pid));
	once = 0;
    }
    if (hint == 0)
	hint = CRYPT_SHA1_ITERATIONS;
    return hint - (random() % (hint / 4));
}

/*
 * UNIX password using hmac_sha1
 * This is PBKDF1 from RFC 2898, but using hmac_sha1.
 *
 * The format of the encrypted password is:
 * $<tag>$<iterations>$<salt>$<digest>
 *
 * where:
 * 	<tag>		is "sha1"
 *	<iterations>	is an unsigned int identifying how many rounds
 * 			have been applied to <digest>.  The number
 * 			should vary slightly for each password to make
 * 			it harder to generate a dictionary of
 * 			pre-computed hashes.  See crypt_sha1_iterations.
 * 	<salt>		up to 64 bytes of random data, 8 bytes is
 * 			currently considered more than enough.
 *	<digest>	the hashed password.
 *
 * NOTE:
 * To be FIPS 140 compliant, the password which is used as a hmac key,
 * should be between 10 and 20 characters to provide at least 80bits
 * strength, and avoid the need to hash it before using as the 
 * hmac key.
 */
#define SHA1_MAGIC "$sha1"
#define SHA1_SIZE 20
char *
nts_crypt_sha1(const char *pw, const char *salt)
{
    static const char *magic = SHA1_MAGIC;
    static unsigned char hmac_buf[SHA1_SIZE];
    static char passwd[(2 * sizeof(SHA1_MAGIC)) +
		       CRYPT_SHA1_SALT_LENGTH + SHA1_SIZE];
    char *sp;
    char *ep;
    unsigned long ul;
    int sl;
    int pl;
    int dl;
    unsigned int iterations;
    unsigned int i;

    /*
     * Salt format is
     * $<tag>$<iterations>$salt[$]
     * If it does not start with $ we use our default iterations.
     */
    sp = (char *) salt;

    /* If it starts with the magic string, then skip that */
    if (!strncmp(sp, magic, strlen(magic))) {
	sp += strlen(magic);
	/* and get the iteration count */
	iterations = strtoul(sp, &ep, 10);
	if (*ep != '$')
	    return NULL;		/* invalid input */
	sp = ep + 1;			/* skip over the '$' */
    } else {
	iterations = nts_crypt_sha1_iterations(0);
    }

    /* It stops at the next '$', max CRYPT_SHA1_ITERATIONS chars */
    for (ep = sp; *ep && *ep != '$' && ep < (sp + CRYPT_SHA1_ITERATIONS); ep++)
	continue;

    /* Get the length of the actual salt */
    sl = ep - sp;
    pl = strlen(pw);

    /*
     * Now get to work...
     * Prime the pump with <salt><magic><iterations>
     */
    dl = snprintf(passwd, sizeof (passwd), "%.*s%s%u", 
		  sl, sp, magic, iterations);
    /*
     * Then hmac using <pw> as key, and repeat...
     */
    ep = (char *) pw;			/* keep gcc happy */
    nts_hmac_sha1((unsigned char *) passwd, dl, (unsigned char *) ep, pl, hmac_buf);
    for (i = 1; i < iterations; i++) {
	nts_hmac_sha1(hmac_buf, SHA1_SIZE, (unsigned char *) ep, pl, hmac_buf);
    }
    /* Now output... */
    pl = snprintf(passwd, sizeof(passwd), "%s%u$%.*s$",
		  magic, iterations, sl, sp);
    ep = passwd + pl;

    /* Every 3 bytes of hash gives 24 bits which is 4 base64 chars */
    for (i = 0; i < SHA1_SIZE - 3; i += 3) {
	ul = (hmac_buf[i+0] << 16) |
	    (hmac_buf[i+1] << 8) |
	    hmac_buf[i+2];
	nts_crypt_to64(ep, ul, 4); ep += 4;
    }
    /* Only 2 bytes left, so we pad with byte0 */
    ul = (hmac_buf[SHA1_SIZE - 2] << 16) |
	(hmac_buf[SHA1_SIZE - 1] << 8) |
	hmac_buf[0];
    nts_crypt_to64(ep, ul, 4); ep += 4;
    *ep = '\0';

    /* Don't leave anything around in vm they could use. */
    memset(hmac_buf, 0, sizeof hmac_buf);

    return passwd;
}	

/*	$NetBSD: pw_gensalt.c,v 1.6 2007/01/17 23:24:22 hubertf Exp $	*/

/*
 * Copyright 1997 Niels Provos <provos@physnet.uni-hamburg.de>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Niels Provos.
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * from OpenBSD: pwd_gensalt.c,v 1.9 1998/07/05 21:08:32 provos Exp
 */

static int nts_gensalt_old(char *salt, size_t saltsiz, const char *option);
static int nts_gensalt_new(char *salt, size_t saltsiz, const char *option);
static int nts_gensalt_md5(char *salt, size_t saltsiz, const char *option);
static int nts_gensalt_sha1(char *salt, size_t saltsiz, const char *option);
static int nts_gensalt_blowfish(char *salt, size_t saltsiz, const char *option);

static const struct pw_salt {
	const char *name;
	int (*gensalt)(char *, size_t, const char *);
} salts[] = {
	{ "old",	nts_gensalt_old },
	{ "new",	nts_gensalt_new },
	{ "md5",	nts_gensalt_md5 },
	{ "sha1",	nts_gensalt_sha1 },
	{ "blowfish",	nts_gensalt_blowfish },
	{ }
};

static int
getnum(const char *str, size_t *num)
{
	char *ep;
	unsigned long rv;

	if (str == NULL) {
		*num = 0;
		return 0;
	}

	rv = strtoul(str, &ep, 0);

	if (str == ep || *ep) {
		errno = EINVAL;
		return -1;
	}

	if (errno == ERANGE && rv == ULONG_MAX)
		return -1;
	*num = (size_t)rv;
	return 0;
}

int
/*ARGSUSED2*/
nts_gensalt_old(char *salt, size_t saltsiz, const char *option)
{
	if (saltsiz < 3) {
		errno = ENOSPC;
		return -1;
	}
	nts_crypt_to64(&salt[0], arc4random(), 2);
	salt[2] = '\0';
	return 0;
}

int
/*ARGSUSED2*/
nts_gensalt_new(char *salt, size_t saltsiz, const char* option)
{
	size_t nrounds;

	if (saltsiz < 10) {
		errno = ENOSPC;
		return -1;
	}

	if (getnum(option, &nrounds) == -1)
		return -1;

	/* Check rounds, 24 bit is max */
	if (nrounds < 7250)
		nrounds = 7250;
	else if (nrounds > 0xffffff)
		nrounds = 0xffffff;
	salt[0] = PASSWORD_EFMT1;
	nts_crypt_to64(&salt[1], (uint32_t)nrounds, 4);
	nts_crypt_to64(&salt[5], arc4random(), 4);
	salt[9] = '\0';
	return 0;
}

int
/*ARGSUSED2*/
nts_gensalt_md5(char *salt, size_t saltsiz, const char *option)
{
	if (saltsiz < 13) {  /* $1$8salt$\0 */
		errno = ENOSPC;
		return -1;
	}
	salt[0] = PASSWORD_NONDES;
	salt[1] = '1';
	salt[2] = '$';
	nts_crypt_to64(&salt[3], arc4random(), 4);
	nts_crypt_to64(&salt[7], arc4random(), 4);
	salt[11] = '$';
	salt[12] = '\0';
	return 0;
}

int
nts_gensalt_sha1(char *salt, size_t saltsiz, const char *option)
{
	int n;
	size_t nrounds;

	if (getnum(option, &nrounds) == -1)
		return -1;
	n = snprintf(salt, saltsiz, "%s%u$", SHA1_MAGIC,
	    nts_crypt_sha1_iterations(nrounds));
	/*
	 * The salt can be up to 64 bytes, but 8
	 * is considered enough for now.
	 */
	if (n + 9 >= saltsiz)
		return 0;
	nts_crypt_to64(&salt[n], arc4random(), 4);
	nts_crypt_to64(&salt[n + 4], arc4random(), 4);
	salt[n + 8] = '$';
	salt[n + 9] = '\0';
	return 0;
}

int
nts_gensalt(char *salt, size_t saltlen, const char *type, const char *option)
{
	const struct pw_salt *sp;

	for (sp = salts; sp->name; sp++)
		if (strcmp(sp->name, type) == 0)
			return (*sp->gensalt)(salt, saltlen, option);

	errno = EINVAL;
	return -1;
}

/*	$NetBSD: arc4random.c,v 1.9 2005/12/24 21:11:16 perry Exp $	*/
/*	$OpenBSD: arc4random.c,v 1.6 2001/06/05 05:05:38 pvalchev Exp $	*/

/*
 * Arc4 random number generator for OpenBSD.
 * Copyright 1996 David Mazieres <dm@lcs.mit.edu>.
 *
 * Modification and redistribution in source and binary forms is
 * permitted provided that due credit is given to the author and the
 * OpenBSD project by leaving this copyright notice intact.
 */

/*
 * This code is derived from section 17.1 of Applied Cryptography,
 * second edition, which describes a stream cipher allegedly
 * compatible with RSA Labs "RC4" cipher (the actual description of
 * which is a trade secret).  The same algorithm is used as a stream
 * cipher called "arcfour" in Tatu Ylonen's ssh package.
 *
 * Here the stream cipher has been modified always to include the time
 * when initializing the state.  That makes it impossible to
 * regenerate the same random sequence twice, so this can't be used
 * for encryption, but will generate good random numbers.
 *
 * RC4 is a registered trademark of RSA Laboratories.
 */

struct arc4_stream {
	u_int8_t i;
	u_int8_t j;
	u_int8_t s[256];
};

static int rs_initialized;
static struct arc4_stream rs;

static inline void arc4_init(struct arc4_stream *);
static inline void arc4_addrandom(struct arc4_stream *, u_char *, int);
static void arc4_stir(struct arc4_stream *);
static inline u_int8_t arc4_getbyte(struct arc4_stream *);
static inline u_int32_t arc4_getword(struct arc4_stream *);

static inline void
arc4_init(as)
	struct arc4_stream *as;
{
	int     n;

	for (n = 0; n < 256; n++)
		as->s[n] = n;
	as->i = 0;
	as->j = 0;
}

static inline void
arc4_addrandom(as, dat, datlen)
	struct arc4_stream *as;
	u_char *dat;
	int     datlen;
{
	int     n;
	u_int8_t si;

	as->i--;
	for (n = 0; n < 256; n++) {
		as->i = (as->i + 1);
		si = as->s[as->i];
		as->j = (as->j + si + dat[n % datlen]);
		as->s[as->i] = as->s[as->j];
		as->s[as->j] = si;
	}
	as->j = as->i;
}

static void
arc4_stir(as)
	struct arc4_stream *as;
{
	int     fd;
	struct {
		struct timeval tv;
		u_int rnd[(128 - sizeof(struct timeval)) / sizeof(u_int)];
	}       rdat;
	int	n;

	gettimeofday(&rdat.tv, NULL);
	fd = open("/dev/urandom", O_RDONLY);
	if (fd != -1) {
		read(fd, rdat.rnd, sizeof(rdat.rnd));
		close(fd);
	}

	/* fd < 0 or failed sysctl ?  Ah, what the heck. We'll just take
	 * whatever was on the stack... */

	arc4_addrandom(as, (void *) &rdat, sizeof(rdat));

	/*
	 * Throw away the first N words of output, as suggested in the
	 * paper "Weaknesses in the Key Scheduling Algorithm of RC4"
	 * by Fluher, Mantin, and Shamir.  (N = 256 in our case.)
	 */
	for (n = 0; n < 256 * 4; n++)
		arc4_getbyte(as);
}

static inline u_int8_t
arc4_getbyte(as)
	struct arc4_stream *as;
{
	u_int8_t si, sj;

	as->i = (as->i + 1);
	si = as->s[as->i];
	as->j = (as->j + si);
	sj = as->s[as->j];
	as->s[as->i] = sj;
	as->s[as->j] = si;
	return (as->s[(si + sj) & 0xff]);
}

static inline u_int32_t
arc4_getword(as)
	struct arc4_stream *as;
{
	u_int32_t val;
	val = arc4_getbyte(as) << 24;
	val |= arc4_getbyte(as) << 16;
	val |= arc4_getbyte(as) << 8;
	val |= arc4_getbyte(as);
	return val;
}

void
arc4random_stir()
{
	if (!rs_initialized) {
		arc4_init(&rs);
		rs_initialized = 1;
	}
	arc4_stir(&rs);
}

void
arc4random_addrandom(dat, datlen)
	u_char *dat;
	int     datlen;
{
	if (!rs_initialized)
		arc4random_stir();
	arc4_addrandom(&rs, dat, datlen);
}

u_int32_t
arc4random()
{
	if (!rs_initialized)
		arc4random_stir();
	return arc4_getword(&rs);
}
