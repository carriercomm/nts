#! /bin/sh

if ! [ -z "$LOGNAME" ]; then
	U="$LOGNAME"
elif ! [ -z "$USER" ]; then
	U="$USER"
else
	U=`whoami`
fi

D=`date '+%d-%b-%Y %H:%M:%S %Z'`
H=`hostname`

cat >vers.c <<EOF
char const *builder = "$U";
char const *buildhost = "$H";
char const *builddate = "$D";
EOF
