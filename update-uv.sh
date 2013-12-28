#! /bin/sh

[ -e "nts.c" ] || {
	echo >&2 "must be run from top srcdir"
	exit 1
}

OLD=$(pwd)
TMPDIR=$(mktemp -d /tmp/libuv.XXXXXX)
trap cleanup 0
cleanup() {
	rm -rf "$TMPDIR"
}

cd "$TMPDIR"

T=$(pwd)
set -e

git clone --depth 1 git@github.com:joyent/libuv.git

rm -rf $T/uv
mkdir $T/uv

cd $T/libuv
cp -r AUTHORS LICENSE include $T/uv/
mkdir -p $T/uv/src
cp src/unix/*.[ch] src/*.[ch] $T/uv/src

cd $T/uv/

cd $T
rm -rf $OLD/uv
cp -r uv $OLD/uv
