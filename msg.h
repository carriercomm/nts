/* RT/NTS -- a lightweight, high performance news transit server. */
/* 
 * Copyright (c) 2011-2013 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */

#ifndef	NTS_MSG_H
#define	NTS_MSG_H

typedef struct msg {
	const char	*m_subsys;
	const char	*m_code;
	char		 m_sev;
	const char	*m_text;
} msg_t;

#endif	/* !NTS_MSG_H */
