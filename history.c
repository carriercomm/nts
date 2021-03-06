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
#include	"historymsg.h"

static int	 history_get_msgid(DB *, DBT const *, DBT const *, DBT *);
static void	 history_clean(uv_work_t *);
static void	 history_clean_done(uv_work_t *, int);
static void	 history_run_clean(uv_timer_t *, int);

static DB		*history_db;
static DB		*history_by_msgid;
static uint64_t		 remember;
static uv_timer_t	 history_clean_timer;

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
int	ret;

	if (ret = db_create(&history_db, db_env, 0)) {
		nts_logm(HISTORY_fac, M_HISTORY_HDLERR, db_strerror(ret));
		return -1;
	}

	/* 250 = msg-id; 8 = timestamp */
	if (ret = history_db->set_re_len(history_db, 250 + 8)) {
		nts_logm(HISTORY_fac, M_HISTORY_RLNFAIL, db_strerror(ret));
		return -1;
	}

	if (ret = history_db->set_re_pad(history_db, '\0')) {
		nts_logm(HISTORY_fac, M_HISTORY_PADFAIL, db_strerror(ret));
		return -1;
	}

	if (ret = history_db->set_q_extentsize(history_db, 262144000)) {
		nts_logm(HISTORY_fac, M_HISTORY_EXTNFAIL, db_strerror(ret));
		return -1;
	}

	if (ret = history_db->open(history_db, NULL, "history.db", NULL,
			DB_QUEUE, DB_CREATE | DB_AUTO_COMMIT, 0600)) {
		nts_logm(HISTORY_fac, M_HISTORY_OPNFAIL,
			 "history.db", db_strerror(ret));
		return -1;
	}

	if (ret = db_create(&history_by_msgid, db_env, 0)) {
		nts_logm(HISTORY_fac, M_HISTORY_HDLERR, db_strerror(ret));
		return -1;
	}

	if (ret = history_by_msgid->open(history_by_msgid, NULL, "history_msgid.idx", NULL,
			DB_HASH, DB_CREATE | DB_AUTO_COMMIT, 0600)) {
		nts_logm(HISTORY_fac, M_HISTORY_OPNFAIL,
			 "history_msgid.idx", db_strerror(ret));
		return -1;
	}

	if (ret = history_db->associate(history_db, NULL, history_by_msgid, 
					history_get_msgid, DB_AUTO_COMMIT)) {
		nts_logm(HISTORY_fac, M_HISTORY_ASSCFAIL, db_strerror(ret));
		return -1;
	}

	uv_timer_init(loop, &history_clean_timer);
	uv_timer_start(&history_clean_timer, history_run_clean, 3600 * 1000, 3600 * 1000);

	return 0;
}

int
history_check(mid)
	char const	*mid;
{
DBT		key, data;
int		ret;
char		dbuf[258];
	
	bzero(&key, sizeof(key));
	bzero(&data, sizeof(data));

	key.data = (void *) mid;
	key.size = strlen(mid);

	data.data = dbuf;
	data.ulen = sizeof(dbuf);
	data.flags |= DB_DBT_USERMEM;

	for (;;) {
		if (ret = history_by_msgid->get(history_by_msgid, NULL, &key, &data, 0)) {
			if (ret == DB_LOCK_DEADLOCK)
				continue;

			if (ret == DB_NOTFOUND)
				return 0;

			panic("history: failed to fetch history entry: %s", db_strerror(ret));
		}

		return 1;
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
char		 dbuf[258];
DB_TXN		*txn;
const char	**p;
db_recno_t	 recno;

	bzero(&key, sizeof(key));
	bzero(&data, sizeof(data));

	key.data = &recno;
	key.ulen = sizeof(recno);
	key.flags = DB_DBT_USERMEM;

	data.data = &dbuf;
	data.size = sizeof(dbuf);

	int64put(dbuf, now);

	for (;;) {
		txn = db_new_txn(DB_TXN_WRITE_NOSYNC);

		for (p = mids; *p; p++) {
			assert(strlen(*p) <= 250);

			bzero(dbuf + 8, 250);
			bcopy(*p, dbuf + 8, strlen(*p));

			recno = 0;
			if (ret = history_db->put(history_db, txn, &key, &data, DB_APPEND)) {
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
DBT		 key, mkey, data;
int		 ret;
time_t		 now = time(NULL);
char		 dbuf[250 + 8];
DB_TXN		*txn;
db_recno_t	 recno = 0;

	bzero(&key, sizeof(key));
	bzero(&data, sizeof(data));

	key.data = &recno;
	key.size = sizeof(recno);
	key.ulen = sizeof(recno);
	key.flags = DB_DBT_USERMEM;

	bzero(&mkey, sizeof(mkey));
	mkey.data = (void *) mid;
	mkey.size = strlen(mid);

	data.data = &dbuf;
	data.size = sizeof(dbuf);
	data.ulen = sizeof(dbuf);
	data.flags = DB_DBT_USERMEM;

	for (;;) {
		txn = db_new_txn(DB_TXN_WRITE_NOSYNC);

		ret = history_by_msgid->get(history_by_msgid, txn, &mkey, &data, DB_RMW);
		if (ret == 0) {
			txn->abort(txn);
			return 0;
		}

		if (ret == DB_LOCK_DEADLOCK) {
			txn->abort(txn);
			continue;
		}

		if (ret && (ret != DB_NOTFOUND))
			panic("history: failed to check history entry: %s",
			      db_strerror(ret));

		bzero(dbuf, sizeof(dbuf));
		int64put(dbuf, now);

		assert(strlen(mid) <= 250);
		bcopy(mid, dbuf + 8, strlen(mid));

		if (ret = history_db->put(history_db, txn, &key, &data, DB_APPEND)) {
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
history_get_msgid(sdb, pkey, pdata, skey)
	DB		*sdb;
	DBT const	*pkey, *pdata;
	DBT		*skey;
{
	bzero(skey, sizeof(*skey));
	skey->data = pdata->data + 8;

	/* Is there a terminating \0? */
	if (memchr(skey->data, '\0', 250))
		skey->size = strlen(skey->data);
	else
		skey->size = 250;

	assert(skey->size <= 250);
	return 0;
}

static void
history_run_clean(timer, status)
	uv_timer_t	*timer;
{
uv_work_t	*req;
	req = xcalloc(1, sizeof(*req));

	uv_queue_work(loop, req, history_clean, history_clean_done);
}

static void
history_clean_done(req, status)
	uv_work_t	*req;
{
	free(req);
}

static void
history_clean(req)
	uv_work_t	*req;
{
time_t		 oldest;
DBT		 key, data, delkeys;
size_t		 expired = 0;
char		 dbuf[258];
db_recno_t	 kbuf;

#define BSZ	(258 * 100)

	bzero(&key, sizeof(key));
	key.data = &kbuf;
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

		if (ret = history_db->cursor(history_db, txn, &curs, 0))
			panic("history: cannot open cursor: %s", db_strerror(ret));

		DB_MULTIPLE_RECNO_WRITE_INIT(p, &delkeys);

		for (n = 0; n < 100; n++) {
		time_t	added;

			if (ret = curs->get(curs, &key, &data, DB_NEXT)) {
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
			DB_MULTIPLE_RECNO_WRITE_NEXT(p, &delkeys, kbuf, NULL, 0);
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
	nts_logm(HISTORY_fac, M_HISTORY_EXPIRED, (unsigned long) expired);

	return;
}

void
history_shutdown()
{
	if (history_by_msgid)
		history_by_msgid->close(history_by_msgid, 0);
	if (history_db)
		history_db->close(history_db, 0);

	history_by_msgid = history_db = NULL;
}
