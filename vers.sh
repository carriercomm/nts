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
C=`git rev-parse --short HEAD 2>&1`
if [ ! -z "$C" ]; then
	C="[$C]"
fi

cat >vers.c <<EOF
char const *builder = "$U";
char const *buildhost = "$H";
char const *builddate = "$D";
char const *buildhash = "$C";
EOF
