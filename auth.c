/* RT/NTS -- a lightweight, high performance news transit server. */
/* 
 * Copyright (c) 2011, 2012 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */
/* $Header: /cvsroot/nts/auth.c,v 1.5 2012/01/07 16:47:15 river Exp $ */

#include	<stdlib.h>
#include	<errno.h>
#include	<string.h>
#include	<errno.h>

#include	"auth.h"
#include	"config.h"
#include	"nts.h"
#include	"log.h"
#include	"crypt.h"

static char	*auth_pwfile;
int		 auth_enabled;
int		 allow_unauthed;
int		 insecure_auth;

static void	 auth_reload(void);

typedef enum {
	H_DES,
	H_MD5,
	H_SHA1,
	H_BF,
	H_NEWDES
} pwhash_t;

typedef struct user {
	str_t	u_username;
	str_t	u_password;
} user_t;

static user_t	*users;
static size_t	 nusers;

static user_t	*find_user(str_t username);
static void	 add_user(str_t, str_t);

static pwhash_t	 default_algo = H_BF;

static void	 auth_set_default_hash(conf_stanza_t *, conf_option_t *, void *, void *);

static config_schema_opt_t auth_opts[] = {
	{ "password-file",	OPT_TYPE_STRING,	config_simple_string,	&auth_pwfile },
	{ "allow-unauthenticated",	
				OPT_TYPE_BOOLEAN,	config_simple_boolean,	&allow_unauthed },
	{ "default-hash",	OPT_TYPE_STRING | OPT_TYPE_NUMBER | OPT_LIST,
				auth_set_default_hash },
	{ "insecure-auth",	OPT_TYPE_BOOLEAN,	config_simple_boolean,	&insecure_auth },
	{ }
};

static config_schema_stanza_t auth_stanza =
	{ "auth",	0,	auth_opts }
;

int
auth_init()
{
	config_add_stanza(&auth_stanza);
	return 0;
}

int
auth_run()
{
	if (auth_pwfile) {
		auth_enabled = 1;
		auth_reload();
	}
	return 0;
}

int
auth_check(u, p)
	str_t	u, p;
{
user_t	*user;
char	*cpw, *chash;
int	 okay = 0;

	if ((user = find_user(u)) == NULL)
		return 0;

	cpw = xmalloc(str_length(p) + 1);
	bcopy(str_begin(p), cpw, str_length(p));
	cpw[str_length(p)] = '\0';

	chash = xmalloc(str_length(user->u_password) + 1);
	bcopy(str_begin(user->u_password), chash, str_length(user->u_password));
	chash[str_length(user->u_password)] = '\0';

	if (strncmp(chash, "$plain$", 7) == 0)
		okay = (strcmp(cpw, chash + 7) == 0);
	else if (strcmp(nts_crypt(cpw, chash), chash) == 0)
		okay = 1;

	free(cpw);
	free(chash);
	return okay;
}

static int
user_compare(a, b)
	const void	*a, *b;
{
const struct str	*un = a;
user_t const		*user = b;

	return str_compare(un, user->u_username);
}

static user_t *
find_user(un)
	str_t	un;
{
	return bsearch(un, &users[0], nusers, sizeof(user_t), user_compare);
}

static str_t
next_colon(str)
	str_t	str;
{
ssize_t	end;
str_t	line;

	if (str_length(str) == 0)
		return NULL;

	if ((end = str_find(str, ":")) == -1) {
	str_t	ret = str_copy(str);
		str_remove_start(str, str_length(str));
		return ret;
	}

	line = str_copy_len(str, end);
	str_remove_start(str, end + 1);
	return line;
}

static void
auth_reload()
{
size_t	 i;
FILE	*f;
char	 line_[1024];
int	 lineno = 0;

	if ((f = fopen(auth_pwfile, "r")) == NULL) {
		nts_log(LOG_ERR, "auth: \"%s\": %s",
				auth_pwfile, strerror(errno));
		return;
	}

	for (i = 0; i < nusers; ++i) {
		str_free(users[i].u_username);
		str_free(users[i].u_password);
	}
	free(users);

	while (fgets(line_, sizeof(line_), f)) {
	str_t	line;
	str_t	username = NULL, inpw = NULL;

		line_[strlen(line_) - 1] = '\0';
		line = str_new_c(line_);

		lineno++;

		if ((username = next_colon(line)) == NULL ||
		    (inpw = next_colon(line)) == NULL) {
			nts_log(LOG_ERR, "auth: \"%s\", line %d: syntax error",
					auth_pwfile, lineno);
			goto err;
		}

		add_user(username, inpw);

err:
		str_free(line);
		str_free(username);
		str_free(inpw);
	}

	qsort(users, nusers, sizeof(*users), user_compare);
}

static void
add_user(un, pw)
	str_t	un, pw;
{
	users = xrealloc(users, sizeof(*users) * (nusers + 1));
	users[nusers].u_username = str_copy(un);
	users[nusers].u_password = str_copy(pw);
	++nusers;
}

static char crypt_nrounds[64];

str_t
auth_hash_password(pw)
	str_t	pw;
{
char	*cpw, *crypted;
char	 salt[64];

	cpw = xmalloc(str_length(pw) + 1);
	bcopy(str_begin(pw), cpw, str_length(pw));
	cpw[str_length(pw)] = '\0';

	switch (default_algo) {
	case H_BF:	nts_gensalt(salt, sizeof(salt), "blowfish", crypt_nrounds); break;
	case H_DES:	nts_gensalt(salt, sizeof(salt), "old", NULL); break;
	case H_NEWDES:	nts_gensalt(salt, sizeof(salt), "new", crypt_nrounds); break;
	case H_MD5:	nts_gensalt(salt, sizeof(salt), "md5", NULL); break;
	case H_SHA1:	nts_gensalt(salt, sizeof(salt), "sha1", crypt_nrounds); break;
	}

	crypted = nts_crypt(cpw, salt);
	free(cpw);
	return str_new_c(crypted);
}

static void
auth_set_default_hash(stz, opt, udata, arg)
	conf_stanza_t	*stz;
	conf_option_t	*opt;
	void		*udata, *arg;
{
char		*h = opt->co_value->cv_string;
conf_val_t	*nr = opt->co_value->cv_next;

	if (strcmp(h, "blowfish") == 0) {
		default_algo = H_BF;
		if (nr)
			snprintf(crypt_nrounds, sizeof(crypt_nrounds), "%d",
				(int) nr->cv_number);
		else
			sprintf(crypt_nrounds, "%d", 7);
	} else if (strcmp(h, "des") == 0) {
		default_algo = H_DES;
	} else if (strcmp(h, "newdes") == 0) {
		default_algo = H_NEWDES;
		if (nr)
			snprintf(crypt_nrounds, sizeof(crypt_nrounds), "%d",
				(int) nr->cv_number);
		else
			sprintf(crypt_nrounds, "%d", 7250);
	} else if (strcmp(h, "sha1") == 0) {
		default_algo = H_SHA1;
		if (nr)
			snprintf(crypt_nrounds, sizeof(crypt_nrounds), "%d",
				(int) nr->cv_number);
		else
			sprintf(crypt_nrounds, "%d", 24680);
	} else if (strcmp(h, "md5") == 0)
		default_algo = H_MD5;
	else
		nts_log(LOG_ERR, "\"%s\", line %d: unknown hash algorithm \"%s\"",
				opt->co_file, opt->co_lineno, h);
}
