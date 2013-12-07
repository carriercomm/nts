/* RT/NTS -- a lightweight, high performance news transit server. */
/* 
 * Copyright (c) 2011, 2012 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */
/* $Header: /cvsroot/nts/base64.c,v 1.2 2012/01/08 18:32:20 river Exp $ */

#include	<string.h>
#include	<stdlib.h>
#include	<stdio.h>

#include	"base64.h"

static char b64table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
#define	b64untable(c)							\
	( ((c) >= 'A' && (c) <= 'Z') ? ((c) - 'A')			\
	: ((c) >= 'a' && (c) <= 'z') ? (((c) - 'a') + 26)		\
	: ((c) >= '0' && (c) <= '9') ? (((c) - '0') + 52)		\
	: ((c) == '+') ? 53						\
	: ((c) == '/') ? 54						\
	: ((c) == '=') ? 0						\
	: -1)								\

void
base64_encode(inbuf, inlen, outbuf)
	unsigned char const	*inbuf;
	char			*outbuf;
	size_t			 inlen;
{
size_t	left = inlen;
	while (left > 0) {
	unsigned char	d[4] = {};
	int		todo = left > 3 ? 3 : left;

		switch (todo) {
		case 3:
			d[3] |= (inbuf[2] & 0x3F);
			d[2] |= ((inbuf[2] & 0xC0) >> 6);
		case 2:
			d[2] |= (inbuf[1] & 0x0F) << 2;
			d[1] |= ((inbuf[1] & 0xF0) >> 4);
		case 1:
			d[0] = (inbuf[0] & 0xFC) >> 2;
			d[1] |= (inbuf[0] & 0x03) << 4;
		}

		*outbuf++ = b64table[d[0]];
		*outbuf++ = b64table[d[1]];

		if (todo >= 3) {
			*outbuf++ = b64table[d[2]];
			*outbuf++ = b64table[d[3]];
		} else if (todo == 2) {
			*outbuf++ = b64table[d[2]];
			*outbuf++ = '=';
		} else if (todo == 1) {
			*outbuf++ = '=';
			*outbuf++ = '=';
		}

		left -= todo;
		inbuf += todo;
	}
}

ssize_t
base64_decode(inbuf, inlen, outbuf)
	char const		*inbuf;
	size_t			 inlen;
	unsigned char		*outbuf;
{
size_t			 left = inlen;
unsigned const char	*p = inbuf;
ssize_t			 nbytes = 0;

	while (left > 0) {
	unsigned char	d[3] = {};
	int		todo = left > 4 ? 4 : left;
	int		nout = todo >= 3 ? 3 : todo;

		switch (todo) {
		case 4:
			if (b64untable(p[3]) == -1)
				return -1;
			d[2] |= b64untable(p[3]) & 0x3F;
		case 3:
			if (b64untable(p[2]) == -1)
				return -1;
			++nbytes;
			d[2] |= (b64untable(p[2]) & 0x03) << 6;
			d[1] |= (b64untable(p[2]) & 0x3C) >> 2;
		case 2:
			if (b64untable(p[1]) == -1)
				return -1;
			++nbytes;
			d[1] |= ((b64untable(p[1]) & 0xF) << 4);
			d[0] |= (b64untable(p[1]) & 0x30) >> 4;
		case 1:
			if (b64untable(p[0]) == -1)
				return -1;
			++nbytes;
			d[0] |= b64untable(p[0]) << 2;
		}

		bcopy(d, outbuf, nout);
		outbuf += nout;
		left -= todo;
		p += todo;
	}

	return nbytes;
}

#ifdef	BASE64_TEST
int
main(argc, argv)
	char	**argv;
{
char	*buf, obuf[64] = {};
size_t	 len = strlen(argv[1]), blen = base64_encode_len(len);
	buf = calloc(1, blen);
	base64_encode(argv[1], len, buf);
	printf("len %d blen %d\n", (int) len, (int) blen);
	printf("%d [%s]\n", (int) blen, buf);
	base64_decode(buf, strlen(buf), obuf);
	printf("%d %d %d %d\n", obuf[0], obuf[1], obuf[2], obuf[3]);
	printf("[%s]\n", obuf);
	return 0;
}
#endif
