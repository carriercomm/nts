/* RT/NTS -- a lightweight, high performance news transit server. */
/* 
 * Copyright (c) 2011, 2012 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */
/* $Header: /cvsroot/nts/emp.c,v 1.6 2012/01/10 03:41:09 river Exp $ */

#include	<math.h>
#include	<stdio.h>

#include	<db.h>
#include	<ev.h>

#include	"log.h"
#include	"emp.h"
#include	"config.h"
#include	"nts.h"
#include	"hash.h"
#include	"crc.h"
#include	"thread.h"

static void	emp_set_decay(conf_stanza_t *, conf_option_t *, void *, void *);
static void	emp_set_score_limit(conf_stanza_t *, conf_option_t *, void *, void *);
static void	emp_set_index(conf_stanza_t *, conf_option_t *, void *, void *);
static void	emp_set_skip_replies(conf_stanza_t *, conf_option_t *, void *, void *);
static void	phl_set_decay(conf_stanza_t *, conf_option_t *, void *, void *);
static void	phl_set_score_limit(conf_stanza_t *, conf_option_t *, void *, void *);
static void	phl_set_exempt(conf_stanza_t *, conf_option_t *, void *, void *);

static config_schema_opt_t emp_group_opts[] = {
	{ "emp-decay",		OPT_TYPE_NUMBER,		emp_set_decay },
	{ "emp-score-limit",	OPT_TYPE_BOOLEAN,		emp_set_score_limit },
	{ "phl-decay",		OPT_TYPE_NUMBER,		phl_set_decay },
	{ "phl-score-limit",	OPT_TYPE_BOOLEAN,		phl_set_score_limit },
	{ "phl-exempt",		OPT_TYPE_STRING | OPT_LIST,	phl_set_exempt },
	{ "index",		OPT_TYPE_STRING,		emp_set_index },
	{ "skip-replies",	OPT_TYPE_BOOLEAN,		emp_set_skip_replies },
	{ }
};

static config_schema_stanza_t emp_stanza = { "emp", 0, emp_group_opts };

typedef struct emp_entry {
	time_t	emp_last_decayed;
	double	emp_score;
} emp_entry_t;

typedef struct phl_entry {
	time_t	phl_last_decayed;
	double	phl_score;
} phl_entry_t;

int	do_emp_tracking;
int	do_phl_tracking;

static double	emp_decay_persec = 1.;
static double	emp_score_limit;
static int	emp_skip_replies;

static enum {
	I_BI, I_BI2, I_SBI, I_ACI
} emp_index_method = I_BI;

static double	phl_decay_persec = 1.;
static double	phl_score_limit;

static void	track_emp(article_t *);
static void	track_phl(article_t *);

static DB	*emp_db;
static DB	*emp_last_decayed_db;
static int	 emp_get_last_decayed(DB *, DBT const *, DBT const *, DBT *);
static int	 emp_compare_last_decayed(DB *, DBT const *, DBT const *);

static DB	*phl_db;
static DB	*phl_last_decayed_db;
static int	 phl_get_last_decayed(DB *, DBT const *, DBT const *, DBT *);
static int	 phl_compare_last_decayed(DB *, DBT const *, DBT const *);

static void		 start_emp_clean(struct ev_loop *, ev_periodic *, int);
static void		*run_emp_clean(void *);
static void		 emp_clean_done(void *);
static void		 emp_clean(DB *, DB *, double);
static ev_periodic	 clean_timer;

static hash_table_t	*phl_exempt_list;

static double	 emp_score_art(article_t *);

int
emp_init()
{
	config_add_stanza(&emp_stanza);
	phl_exempt_list = hash_new(64, NULL, NULL, NULL);
	return 0;
}

int
emp_run()
{
	if (do_emp_tracking) {
		if ((emp_db = db_open("emp.db", DB_HASH, 0, DB_CREATE | DB_AUTO_COMMIT, NULL)) == NULL) {
			nts_log(LOG_CRIT, "emp: EMP database open failed");
			return -1;
		}

		if ((emp_last_decayed_db = db_open("emp_last_decayed_idx.db", 
				DB_BTREE, DB_DUP, DB_CREATE | DB_AUTO_COMMIT,
				emp_compare_last_decayed)) == NULL) {
			nts_log(LOG_CRIT, "emp: EMP last seen index open failed");
			return -1;
		}

		emp_db->associate(emp_db, NULL, emp_last_decayed_db,
				emp_get_last_decayed, DB_AUTO_COMMIT);
	}

	if (do_phl_tracking) {
		if ((phl_db = db_open("phl.db", DB_HASH, 0,
				DB_CREATE | DB_AUTO_COMMIT, NULL)) == NULL) {
			nts_log(LOG_CRIT, "emp: Posting-Host/Lines (PHL) database open failed");
			return -1;
		}

		if ((phl_last_decayed_db = db_open("phl_last_decayed_idx.db",
				DB_BTREE, DB_DUP, DB_CREATE | DB_AUTO_COMMIT,
				phl_compare_last_decayed)) == NULL) {
			nts_log(LOG_CRIT, "emp: Posting-Host/Lines (PHL) last seen index open failed");
			return -1;
		}

		phl_db->associate(phl_db, NULL, phl_last_decayed_db,
				phl_get_last_decayed, DB_AUTO_COMMIT);
	}

	if (do_phl_tracking || do_emp_tracking) {
		ev_periodic_init(&clean_timer, start_emp_clean,
				1200, 3600, NULL);
		ev_periodic_start(EV_DEFAULT, &clean_timer);
	}
	return 0;
}

void
emp_track(art)
	article_t	*art;
{
	if ((do_emp_tracking || do_phl_tracking) &&
	    !(emp_skip_replies && (art->art_flags & ART_REPLY))) {
		if (do_emp_tracking)
			track_emp(art);
		if (do_phl_tracking)
			track_phl(art);
	}
}

static void
track_phl(art)
	article_t	*art;
{
phl_entry_t	 phl_entry;
DBT		 key, data;
int		 ret;
double		 art_score;
time_t		 now = time(NULL);
char		 dbuf[sizeof(uint64_t) * 2];
DB_TXN		*txn;

	if (!art->art_posting_host)
		return;

	if (hash_find(phl_exempt_list, str_begin(art->art_posting_host),
				str_length(art->art_posting_host)))
		return;

	bzero(&key, sizeof(key));
	key.size = str_length(art->art_posting_host) + sizeof(uint16_t);
	key.data = xmalloc(key.size);
	int16put(key.data, art->art_lines);

	bcopy(str_begin(art->art_posting_host), (char *)key.data + sizeof(uint16_t),
		str_length(art->art_posting_host));
	art_score = emp_score_art(art);

	bzero(&data, sizeof(data));
	data.data = dbuf;
	data.ulen = sizeof(dbuf);
	data.flags |= DB_DBT_USERMEM;

	for (;;) {
		txn = db_new_txn(DB_TXN_WRITE_NOSYNC);

		ret = phl_db->get(phl_db, txn, &key, &data, 0);
		if (ret) {
			if (ret == DB_LOCK_DEADLOCK) {
				db_txn_abort(txn);
				continue;
			}
			if (ret != DB_NOTFOUND)
				panic("emp: failed to fetch record from PHL database: %s",
					db_strerror(ret));
		} else {
			assert(data.size == sizeof(uint64_t) * 2);
			phl_entry.phl_last_decayed = int64get(data.data);
			phl_entry.phl_score = ((double) int64get(data.data + 
						sizeof(uint64_t))) / 1000;
		}

		phl_entry.phl_score += art_score;

		if (ret == 0 && (now - phl_entry.phl_last_decayed) > 0)
			phl_entry.phl_score -= (now - phl_entry.phl_last_decayed) * phl_decay_persec;

		if (phl_entry.phl_score > phl_score_limit)
			phl_entry.phl_score = phl_score_limit;
		else if (phl_entry.phl_score < 0)
			phl_entry.phl_score = 0;

		phl_entry.phl_last_decayed = now;

		if (phl_entry.phl_score) {
			data.data = dbuf;
			data.size = sizeof(dbuf);
			int64put(dbuf, phl_entry.phl_last_decayed);
			int64put(dbuf + sizeof(uint64_t), phl_entry.phl_score * 1000);
			ret = phl_db->put(phl_db, txn, &key, &data, 0);
			if (ret && (ret != DB_LOCK_DEADLOCK))
				panic("emp: failed to add PHL database entry: %s", db_strerror(ret));
		} else {
			ret = phl_db->del(phl_db, txn, &key, 0);
		}

		if (ret == DB_LOCK_DEADLOCK) {
			db_txn_abort(txn);
			continue;
		}

		if (ret = txn->commit(txn, 0)) {
			if (ret == DB_LOCK_DEADLOCK) {
				db_txn_abort(txn);
				continue;
			}

			panic("emp: failed to add PHL database entry: %s", db_strerror(ret));
		}

		art->art_phl_score = phl_entry.phl_score;
		break;
	}
	free(key.data);
}

static void
track_emp(art)
	article_t	*art;
{
uint64_t	 crc;
emp_entry_t	 emp_entry;
DBT		 key, data;
int		 ret;
double		 art_score;
time_t		 now = time(NULL);
char		 dbuf[sizeof(uint64_t) * 2];
DB_TXN		*txn;

	art_score = emp_score_art(art);
	crc = crc64(str_begin(art->art_body), str_length(art->art_body));

	bzero(&key, sizeof(key));
	key.data = &crc;
	key.size = sizeof(crc);

	bzero(&data, sizeof(data));
	data.data = dbuf;
	data.flags |= DB_DBT_USERMEM;
	data.ulen = sizeof(dbuf);

	for (;;) {
		txn = db_new_txn(DB_TXN_WRITE_NOSYNC);

		ret = emp_db->get(emp_db, txn, &key, &data, 0);
		if (ret) {
			if (ret == DB_LOCK_DEADLOCK) {
				db_txn_abort(txn);
				continue;
			}

			if (ret != DB_NOTFOUND)
				panic("emp: failed to fetch record from EMP database: %s",
					db_strerror(ret));
		} else {
			assert(data.size == sizeof(uint64_t) * 2);
			emp_entry.emp_last_decayed = int64get(data.data);
			emp_entry.emp_score = ((double) int64get(data.data + 
						sizeof(uint64_t))) / 1000;
		}

		emp_entry.emp_score += art_score;

		if (ret == 0 && (now - emp_entry.emp_last_decayed) > 0)
			emp_entry.emp_score -= (now - emp_entry.emp_last_decayed) * emp_decay_persec;

		if (emp_entry.emp_score > emp_score_limit)
			emp_entry.emp_score = emp_score_limit;
		else if (emp_entry.emp_score < 0)
			emp_entry.emp_score = 0;

		emp_entry.emp_last_decayed = now;

		if (emp_entry.emp_score) {
			data.data = dbuf;
			data.size = sizeof(dbuf);
			int64put(dbuf, emp_entry.emp_last_decayed);
			int64put(dbuf + sizeof(uint64_t), emp_entry.emp_score * 1000);
			ret = emp_db->put(emp_db, txn, &key, &data, 0);
		} else
			ret = emp_db->del(emp_db, txn, &key, 0);

		if (ret == DB_LOCK_DEADLOCK) {
			db_txn_abort(txn);
			continue;
		}

		if (ret)
			panic("emp: failed to add EMP database entry: %s", db_strerror(ret));

		art->art_emp_score = emp_entry.emp_score;
		if (ret = txn->commit(txn, 0)) {
			if (ret == DB_LOCK_DEADLOCK) {
				db_txn_abort(txn);
				continue;
			}

			panic("emp: failed to add EMP database entry: %s", db_strerror(ret));
		}
		return;
	}
}

static double
emp_score_art(art)
	article_t	*art;
{
	switch (emp_index_method) {
	case I_SBI:	if (art->art_nfollowups)
				return sqrt(art->art_nfollowups);
	case I_BI:	return sqrt(art->art_ngroups);
	case I_BI2:	return (sqrt(art->art_ngroups) + art->art_ngroups) / 2;
	case I_ACI:	return 3 + art->art_ngroups;
	}
}

static int
emp_get_last_decayed(sdb, pkey, pdata, skey)
	DB		*sdb;
	DBT const	*pkey, *pdata;
	DBT		*skey;
{
	skey->data = (void *) pdata->data;
	skey->size = sizeof(uint64_t);
	return 0;
}

static int
phl_get_last_decayed(sdb, pkey, pdata, skey)
	DB		*sdb;
	DBT const	*pkey, *pdata;
	DBT		*skey;
{
	skey->data = (void *) pdata->data;
	skey->size = sizeof(uint64_t);
	return 0;
}

static int
emp_compare_last_decayed(db, a, b)
	DB		*db;
	DBT const	*a, *b;
{
time_t	ai = int64get(a->data),
	bi = int64get(b->data);
	return ai - bi;
}

static int
phl_compare_last_decayed(db, a, b)
	DB		*db;
	DBT const	*a, *b;
{
time_t	ai = int64get(a->data),
	bi = int64get(b->data);
	return ai - bi;
}

static void
start_emp_clean(loop, w, revents)
	struct ev_loop	*loop;
	ev_periodic	*w;
{
	ev_periodic_stop(EV_DEFAULT, w);
	thr_do_work(run_emp_clean, NULL, emp_clean_done);
}

static void
emp_clean_done(udata)
	void	*udata;
{
	ev_periodic_start(EV_DEFAULT, &clean_timer);
}

static void *
run_emp_clean(udata)
	void	*udata;
{
	if (do_emp_tracking)
		emp_clean(emp_db, emp_last_decayed_db, emp_decay_persec);
	if (do_phl_tracking)
		emp_clean(phl_db, phl_last_decayed_db, phl_decay_persec);
	return NULL;
}

static void
emp_clean(pdb, sdb, decay)
	DB	*pdb, *sdb;
	double	 decay;
{
DBC	*curs = NULL;
DBT	 key, data;
DB_TXN	*txn = NULL;
int	 ret;
time_t	 now = time(NULL), oldest = now - 3600;
char	 dbuf[sizeof(uint64_t) * 2];
size_t	 i = 0;
int	 finished = 0;
int	 first = 1;

	bzero(&key, sizeof(key));
	bzero(&data, sizeof(data));
	data.data = dbuf;
	data.ulen = sizeof(dbuf);
	data.flags |= DB_DBT_USERMEM;

	for (;;) {
	time_t		last_decayed;
	double		score;

		if (!txn)
			txn = db_new_txn(0);

		if (!curs) {
			if (ret = sdb->cursor(sdb, txn, &curs, 0))
				goto error;
			if (!first) {
				if (ret = curs->get(curs, &key, &data, DB_SET_RANGE)) {
					if (ret == DB_NOTFOUND) {
						finished = 1;
						goto commit;
					} else
						goto error;
				}

				if (ret = curs->get(curs, &key, &data, DB_SET)) {
					if (ret == DB_NOTFOUND) {
						goto commit;
					} else {
						goto error;
					}
				}
			} else if (ret = curs->get(curs, &key, &data, DB_NEXT)) {
				if (ret == DB_NOTFOUND) {
					finished = 1;
					goto commit;
				} else {
					goto error;
				}
			}
		} else if (ret = curs->get(curs, &key, &data, DB_NEXT)) {
			if (ret == DB_NOTFOUND) {
				finished = 1;
				goto commit;
			} else
				goto error;
		}
		first = 0;

		assert(data.size == sizeof(uint64_t) * 2);
		last_decayed = int64get(data.data);
		score = ((double) int64get(data.data + sizeof(uint64_t))) / 1000;

		if (last_decayed >= oldest) {
			finished = 1;
			goto commit;
		}

		score -= (now - last_decayed) * decay;
		if (score < 0)
			score = 0;
		last_decayed = now;

		if (score > 0.001) {
			int64put(dbuf, last_decayed);
			int64put(dbuf + sizeof(uint64_t), score * 1000);

			bzero(&data, sizeof(data));
			data.data = dbuf;
			data.size = sizeof(dbuf);

			if (ret = pdb->put(pdb, txn, &key, &data, 0))
				goto error;
		} else {
			if (ret = curs->del(curs, 0))
				goto error;
		}

		if (i == 100)
			goto commit;

		i++;
		continue;

error:
		if (ret != DB_LOCK_DEADLOCK)
			panic("emp: database error: %s", db_strerror(ret));

deadlock:
		if (curs) {
			curs->close(curs);
			curs = NULL;
		}
		txn->abort(txn);
		txn = NULL;
		continue;

commit:
		i = 0;
		curs->close(curs);
		curs = NULL;
		if (ret = txn->commit(txn, 0)) {
			if (ret == DB_LOCK_DEADLOCK)
				goto deadlock;
			panic("emp: cannot commit transaction: %s",
					db_strerror(ret));
		}
		txn = NULL;
		/*if (finished)*/
			break;
	}
}

void
emp_shutdown()
{
	if (emp_last_decayed_db)
		emp_last_decayed_db->close(emp_last_decayed_db, 0);
	if (phl_last_decayed_db)
		phl_last_decayed_db->close(phl_last_decayed_db, 0);
	if (emp_db)
		emp_db->close(emp_db, 0);
	if (phl_db)
		phl_db->close(phl_db, 0);

	emp_last_decayed_db = phl_last_decayed_db = emp_db = phl_db = NULL;
}

/*
 * Config bits.
 */

static void
phl_set_exempt(stz, opt, udata, arg)
	conf_stanza_t	*stz;
	conf_option_t	*opt;
	void		*udata, *arg;
{
conf_val_t	*val;

	for (val = opt->co_value; val; val = val->cv_next)
		hash_insert(phl_exempt_list, val->cv_string, strlen(val->cv_string), (void *) 1);
}

static void
phl_set_decay(stz, opt, udata, arg)
	conf_stanza_t	*stz;
	conf_option_t	*opt;
	void		*udata, *arg;
{
	phl_decay_persec = (double) opt->co_value->cv_number / 60 / 60;
}

static void
phl_set_score_limit(stz, opt, udata, arg)
	conf_stanza_t	*stz;
	conf_option_t	*opt;
	void		*udata, *arg;
{
	phl_score_limit = opt->co_value->cv_number;
}
static void
emp_set_decay(stz, opt, udata, arg)
	conf_stanza_t	*stz;
	conf_option_t	*opt;
	void		*udata, *arg;
{
	emp_decay_persec = (double) opt->co_value->cv_number / 60 / 60;
}

static void
emp_set_skip_replies(stz, opt, udata, arg)
	conf_stanza_t	*stz;
	conf_option_t	*opt;
	void		*udata, *arg;
{
	emp_skip_replies = opt->co_value->cv_boolean;
}

static void
emp_set_index(stz, opt, udata, arg)
	conf_stanza_t	*stz;
	conf_option_t	*opt;
	void		*udata, *arg;
{
char	*s = opt->co_value->cv_string;
	if (strcmp(s, "bi") == 0)
		emp_index_method = I_BI;
	else if (strcmp(s, "bi2") == 0)
		emp_index_method = I_BI2;
	else if (strcmp(s, "aci") == 0)
		emp_index_method = I_ACI;
	else if (strcmp(s, "sbi") == 0)
		emp_index_method = I_SBI;
	else
		nts_log(LOG_ERR, "\"%s\", line %d: unknown index method \"%s\"",
				opt->co_file, opt->co_lineno, s);
}

static void
emp_set_score_limit(stz, opt, udata, arg)
	conf_stanza_t	*stz;
	conf_option_t	*opt;
	void		*udata, *arg;
{
	emp_score_limit = opt->co_value->cv_number;
}

