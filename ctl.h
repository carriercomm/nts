/* RT/NTS -- a lightweight, high performance news transit server. */
/* 
 * Copyright (c) 2011-2013 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */

#ifndef	NTS_CTL_H
#define	NTS_CTL_H

int	 ctl_init(char const *path);
int	 execute_control_command(char const *);

#endif	/* !NTS_CTL_H */
