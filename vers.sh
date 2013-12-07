#! /bin/sh
build=`cat build`
cat >vers.c <<EOF
int build_number = $build;
EOF
