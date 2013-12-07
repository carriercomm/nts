dnl RT/NTS -- a lightweight, high performance news transit server.
dnl 
dnl Copyright (c) 2011 River Tarnell.
dnl
dnl Permission is granted to anyone to use this software for any purpose,
dnl including commercial applications, and to alter it and redistribute it
dnl freely. This software is provided 'as-is', without any express or implied
dnl warranty.
dnl
dnl $Header: /cvsroot/nts/configure.ac,v 1.10 2012/01/07 15:51:16 river Exp $

AC_PREREQ([2.68])
AC_INIT([RT/NTS], [1.0-CURRENT], [river@RT.UK.EU.ORG])
AC_CONFIG_SRCDIR([nts.c])
AC_CONFIG_HEADERS([setup.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_LEX
AC_PROG_YACC
AC_PROG_INSTALL

AC_CHECK_MEMBER([struct sockaddr_in.sin_len],
	AC_DEFINE([HAVE_SIN_LEN], 1, [Define if struct sockaddr_in has a sin_len member]),
	[],
	[
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>]
)

# Checks for libraries.
AC_ARG_ENABLE([ssl],
	      [AS_HELP_STRING([--disable-ssl], [don't use SSL])],
	      [if test "$enableval" = yes; then
		       use_ssl=yes
	       else
		       use_ssl=no
	       fi],
	      [use_ssl=yes])

if test "$use_ssl" = yes; then
	AC_CHECK_LIB([ssl], [SSL_CTX_new],
	     [LIBS="$LIBS -lssl"
	      AC_DEFINE([HAVE_OPENSSL], 1, [Define if OpenSSL is present])
	     ])
fi

AC_CHECK_LIB([ev], [ev_run], [], [AC_MSG_ERROR([cannot find libev])])
AC_CHECK_HEADER([ev.h], [], [AC_MSG_ERROR([cannot find ev.h])])

AC_CHECK_HEADERS([inttypes.h stdint.h])

AC_CHECK_FUNCS([strndup strlcpy strlcat setproctitle arc4random fdatasync])

AC_ARG_WITH(db-include-dir,
	[AS_HELP_STRING([--with-db-include-dir],
		       	[directory containing the Berkeley DB db.h])],
	[db_include=$withval],
	[])

AC_MSG_CHECKING([for Berkeley DB db.h])
if test -z "$db_include"; then
	# Look in a few common places.  Put /usr/include last
	# since BSD systems put the libc db.h here.
	for dir in /usr/pkg/include/db5 /usr/pkg/include/db4		\
			/opt/pkg/include/db5 /opt/pkg/include/db4 	\
			/usr/local/include /usr/include; do
		if test -e "$dir/db.h"; then
			db_include="$dir"
			break
		fi
	done
fi

if ! test -e "$db_include"/db.h; then
	AC_MSG_ERROR([cannot find db.h in $db_include])
fi

AC_MSG_RESULT([$db_include/db.h])

CPPFLAGS="$CPPFLAGS -I$db_include"

AC_MSG_CHECKING([for Berkeley DB version])
AC_TRY_RUN([#include <stdio.h>
#include <db.h>

int main() {
FILE	*f;
	if ((f = fopen("dbversion", "w")) == NULL) {
		perror("dbversion");
		return 1;
	}
	fprintf(f, "%d.%d\n", DB_VERSION_MAJOR, DB_VERSION_MINOR);
	fclose(f);
	return 0;
}],
	[db_version=`cat dbversion`
	 AC_MSG_RESULT($db_version)],
	[AC_MSG_ERROR([failed])])

AC_CHECK_LIB([db4-$db_version], [db_create], [db_lib=db4-$db_version],
	[AC_CHECK_LIB([db5-$db_version], [db_create], [db_lib=db5-$db_version],
		[AC_CHECK_LIB([db-$db_version], [db_create], [db_lib=db-$db_version],
		     [AC_MSG_ERROR([cannot find Berkeley DB library])])])])

LIBS="$LIBS -l$db_lib"

AC_MSG_CHECKING([for <sys/atomic.h>-style atomics])
AC_TRY_RUN(
	[
		#include <sys/atomic.h>
		#include <stdlib.h>
		int main() {
		int *i = NULL, *o, *n;
		do {
			o = i;
			n = i + 1;
		} while (atomic_cas_ptr(&i, o, n) != o);
		return (i+1 == n);
		}
	],

	[
		AC_MSG_RESULT([yes])
       		AC_DEFINE([HAVE_SYS_ATOMIC], 1, [Define if <sys/atomic.h> is present])
	],

	[
		AC_MSG_RESULT([no])
		AC_MSG_CHECKING([for GCC-style atomics])
		AC_TRY_RUN(
			[
				#include <stdlib.h>
				int main() {
				int *i = NULL, *o, *n;
				do {
					o = i;
					n = i + 1;
				} while (__sync_val_compare_and_swap(&i, o, n) != o);
				return (i+1 == n);
				}
			],

			[
				AC_MSG_RESULT([yes])
				AC_DEFINE([HAVE_GCC_ATOMIC], 1, [Define if GCC atomics are present])
			],

			[
				AC_MSG_RESULT([no])
			]
		)
	]
)

AC_SUBST(EXTRA_SRCS)

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
