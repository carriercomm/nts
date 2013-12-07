/* RT/NTS -- a lightweight, high performance news transit server. */
/* 
 * Copyright (c) 2011 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */
/* $Header: /cvsroot/nts/database.h,v 1.4 2011/12/30 15:57:52 river Exp $ */

#ifndef	NTS_DATABASE_H
#define NTS_DATABASE_H

#include	<db.h>

int	 db_init(void);
int	 db_run(void);
void	 db_shutdown(void);

typedef int (*db_sort_function) (DB *, DBT const *, DBT const *);
DB	*db_open(char const *name, int type, uint32_t flags1,
		uint32_t flags2, db_sort_function);
DB_TXN	*db_new_txn(uint32_t flags);
int	 db_txn_commit(DB_TXN *);
int	 db_txn_abort(DB_TXN *);

extern DB_ENV	*db_env;

#endif	/* !NTS_DATABASE_H */
