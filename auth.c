/* RT/NTS -- a lightweight, high performance news transit server. */
/* 
 * Copyright (c) 2011-2013 River Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */

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
	char	*u_username;
	char	*u_password;
} user_t;

static user_t	*users;
static size_t	 nusers;

static user_t	*find_user(char const *username);
static void	 add_user(char const *, char const *);

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
	char const	*u, *p;
{
user_t	*user;
int	 okay = 0;

	if ((user = find_user(u)) == NULL)
		return 0;

	if (strncmp(user->u_password, "$plain$", 7) == 0)
		okay = (strcmp(p, user->u_password + 7) == 0);
	else if (strcmp(nts_crypt(p, user->u_password), user->u_password) == 0)
		okay = 1;

	return okay;
}

static int
user_compare(a, b)
	const void	*a, *b;
{
char const	*un = a;
user_t const	*user = b;

	return strcmp(un, user->u_username);
}

static user_t *
find_user(un)
	char const	*un;
{
	return bsearch(un, &users[0], nusers, sizeof(user_t), user_compare);
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
		free(users[i].u_username);
		free(users[i].u_password);
	}
	free(users);

	while (fgets(line_, sizeof(line_), f)) {
	char	*username = NULL, *inpw = NULL;
	char	*line = line_;

		line[strlen(line) - 1] = '\0';

		lineno++;

		if ((username = next_any(&line, ":")) == NULL ||
		    (inpw = next_any(&line, ":")) == NULL) {
			nts_log(LOG_ERR, "auth: \"%s\", line %d: syntax error",
					auth_pwfile, lineno);
			return;
		}

		add_user(username, inpw);
	}

	qsort(users, nusers, sizeof(*users), user_compare);
}

static void
add_user(un, pw)
	char const	*un, *pw;
{
	users = xrealloc(users, sizeof(*users) * (nusers + 1));
	users[nusers].u_username = xstrdup(un);
	users[nusers].u_password = xstrdup(pw);
	++nusers;
}

static char crypt_nrounds[64];

char *
auth_hash_password(pw)
	char const	*pw;
{
char	*crypted;
char	 salt[64];

	switch (default_algo) {
	case H_BF:	nts_gensalt(salt, sizeof(salt), "blowfish", crypt_nrounds); break;
	case H_DES:	nts_gensalt(salt, sizeof(salt), "old", NULL); break;
	case H_NEWDES:	nts_gensalt(salt, sizeof(salt), "new", crypt_nrounds); break;
	case H_MD5:	nts_gensalt(salt, sizeof(salt), "md5", NULL); break;
	case H_SHA1:	nts_gensalt(salt, sizeof(salt), "sha1", crypt_nrounds); break;
	}

	crypted = nts_crypt(pw, salt);
	return xstrdup(crypted);
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
