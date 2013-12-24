/* RT/NTS -- a lightweight, high performance news transit server. */
/* 
 * Copyright (c) 2011-2013 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */

#include	<time.h>
#include	<string.h>
#include	<stdlib.h>
#include	<assert.h>

#include	<db.h>

#include	"history.h"
#include	"config.h"
#include	"log.h"
#include	"database.h"
#include	"nts.h"
#include	"net.h"
#include	"thread.h"

static int	 history_get_added(DB *, DBT const *, DBT const *, DBT *);
static int	 history_compare_added(DB *, DBT const *, DBT const *);
static void	*history_clean(void *);
static void	 history_run_clean(void *);

static DB	*history_db;
static DB	*history_added_idx;
static uint64_t	 remember;

static config_schema_opt_t history_opts[] = {
	{ "remember", OPT_TYPE_DURATION, config_simple_duration, &remember },
	{ }
};

static config_schema_stanza_t history_stanza = {
	"history", 0, history_opts
};

int
history_init()
{
	config_add_stanza(&history_stanza);
	return 0;
}

int
history_run()
{
	if ((history_db = db_open("history.db", DB_HASH, 0, DB_CREATE | DB_AUTO_COMMIT, NULL)) == NULL) {
		nts_log(LOG_CRIT, "history: database open failed");
		return -1;
	}

	if ((history_added_idx = db_open("history_added.idx", DB_BTREE, DB_DUP,
					DB_CREATE | DB_AUTO_COMMIT, history_compare_added)) == NULL) {
		nts_log(LOG_CRIT, "history: failed to create secondary index");
		return -1;
	}

	history_db->associate(history_db, NULL, history_added_idx, 
			history_get_added, DB_AUTO_COMMIT);

	net_cron(3600, history_run_clean, NULL);
	return 0;
}

int
history_check(mid)
	char const	*mid;
{
DBT		key, data;
int		ret;
char		dbuf[sizeof(uint64_t)];
	
	bzero(&key, sizeof(key));
	bzero(&data, sizeof(data));

	key.data = (void *) mid;
	key.size = strlen(mid);

	data.data = dbuf;
	data.ulen = sizeof(dbuf);
	data.flags |= DB_DBT_USERMEM;

	if (ret = history_db->get(history_db, NULL, &key, &data, 0)) {
		if (ret == DB_NOTFOUND)
			return 0;

		panic("history: failed to fetch history entry: %s", db_strerror(ret));
	}

	return 1;
}

int
history_add_multiple(mids)
	char const	**mids;
{
DBT		 key, data;
int		 ret;
time_t		 now = time(NULL);
char		 dbuf[sizeof(uint64_t)];
DB_TXN		*txn;
const char	**p;

	bzero(&key, sizeof(key));
	bzero(&data, sizeof(data));

	data.data = &dbuf;
	data.size = sizeof(dbuf);

	int64put(dbuf, now);

	for (;;) {
		txn = db_new_txn(DB_TXN_WRITE_NOSYNC);

		for (p = mids; *p; p++) {
			key.data = (void *) *p;
			key.size = strlen(*p);

			if (ret = history_db->put(history_db, txn, &key, &data, DB_NOOVERWRITE)) {
				if (ret == DB_LOCK_DEADLOCK)
					goto tryagain;

				if (ret != DB_KEYEXIST)
					panic("history: failed to add history entry: %s", db_strerror(ret));
			}
		}

		txn->commit(txn, 0);
		break;

	tryagain:
		txn->abort(txn);
	}

	return 0;
}
int
history_add(mid)
	char const	*mid;
{
DBT		 key, data;
int		 ret;
time_t		 now = time(NULL);
char		 dbuf[sizeof(uint64_t)];
DB_TXN		*txn;

	bzero(&key, sizeof(key));
	bzero(&data, sizeof(data));

	key.data = (void *) mid;
	key.size = strlen(mid);

	data.data = &dbuf;
	data.size = sizeof(dbuf);

	int64put(dbuf, now);

	for (;;) {
		txn = db_new_txn(DB_TXN_WRITE_NOSYNC);

		if (ret = history_db->put(history_db, txn, &key, &data, DB_NOOVERWRITE)) {
			if (ret == DB_LOCK_DEADLOCK) {
				txn->abort(txn);
				continue;
			}

			if (ret != DB_KEYEXIST)
				panic("history: failed to add history entry: %s", db_strerror(ret));
		}

		txn->commit(txn, 0);
		break;
	}

	return 0;
}

static int
history_get_added(sdb, pkey, pdata, skey)
	DB		*sdb;
	DBT const	*pkey, *pdata;
	DBT		*skey;
{
	bzero(skey, sizeof(*skey));
	skey->data = pdata->data;
	skey->size = pdata->size;

	return 0;
}

static int
history_compare_added(db, a, b)
	DB		*db;
	DBT const	*a, *b;
{
time_t	ai = int64get(a->data), 
	bi = int64get(b->data);
	assert(a->size == sizeof(uint64_t));
	assert(b->size == sizeof(uint64_t));
	return ai - bi;
}

static void
history_run_clean(udata)
	void	*udata;
{
	thr_do_work(history_clean, NULL, NULL);
}

static void *
history_clean(udata)
	void	*udata;
{
time_t	 oldest;
DBT	 key, data, delkeys;
size_t	 expired = 0;
char	 dbuf[sizeof(uint64_t)], kbuf[sizeof(uint64_t)];
DBT	 pkey;
char	 pkbuf[1024];

#define BSZ	(1024 * 1024)

	bzero(&key, sizeof(key));
	key.data = kbuf;
	key.ulen = sizeof(kbuf);
	key.flags = DB_DBT_USERMEM;

	bzero(&data, sizeof(data));
	data.data = dbuf;
	data.ulen = sizeof(dbuf);
	data.flags |= DB_DBT_USERMEM;

	bzero(&delkeys, sizeof(delkeys));
	delkeys.data = xmalloc(BSZ);
	delkeys.ulen = BSZ;

	oldest = time(NULL) - history_remember;

	for (;;) {
	DBC		*curs;
	int		 ret;
	DB_TXN		*txn;
	void		*p;
	int		 n = 100;

		txn = db_new_txn(DB_TXN_WRITE_NOSYNC);

		if (ret = history_added_idx->cursor(history_added_idx, txn, &curs, 0))
			panic("history: cannot open cursor: %s", db_strerror(ret));

		DB_MULTIPLE_WRITE_INIT(p, &delkeys);

		for (n = 0; n < 100; n++) {
		time_t	added;

			bzero(&pkey, sizeof(pkey));
			pkey.data = pkbuf;
			pkey.ulen = sizeof(pkbuf);
			pkey.flags = DB_DBT_USERMEM;

			if (ret = curs->pget(curs, &key, &pkey, &data, DB_NEXT)) {
				if (ret == DB_LOCK_DEADLOCK) {
					curs->c_close(curs);
					goto deadlock;
				}
				if (ret == DB_NOTFOUND)
					break;
				panic("history: cannot fetch entries: %s", db_strerror(ret));
			}
			added = int64get(data.data);
			if (added >= oldest)
				break;
			DB_MULTIPLE_WRITE_NEXT(p, &delkeys, pkey.data, pkey.size);
		}
		curs->c_close(curs);
		curs = NULL;

		if (n == 0) {
			if (ret = txn->commit(txn, 0)) {
				if (ret == DB_LOCK_DEADLOCK)
					goto deadlock;
				panic("history: cannot removed expired entries: %s",
						db_strerror(ret));
			}
			break;
		}

		if (ret = history_db->del(history_db, txn, &delkeys, DB_MULTIPLE)) {
			if (ret == DB_LOCK_DEADLOCK)
				goto deadlock;
			panic("history: cannot removed expired entries: %s",
					db_strerror(ret));

		}
		if (ret = txn->commit(txn, 0)) {
			if (ret == DB_LOCK_DEADLOCK)
				goto deadlock;
			panic("history: cannot removed expired entries: %s",
					db_strerror(ret));
		}

		expired += n;
		continue;

deadlock:	;
		txn->abort(txn);
	}

	free(delkeys.data);
	nts_log(LOG_INFO, "history: expired %lu entries", (long unsigned) expired);

	return NULL;
}

void
history_shutdown()
{
	if (history_added_idx)
		history_added_idx->close(history_added_idx, 0);
	if (history_db)
		history_db->close(history_db, 0);

	history_added_idx = history_db = NULL;
}
