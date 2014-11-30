#!/bin/bash

# Each .pipe file contains a "pipeline" of commands.  Compare the output
# of the FINAL command to <foo>.ref
#
# Variables available to the .pipe test cases:
#   $STOKEN - path to stoken executable
#   $out - the last command's output
#   $TESTDIR - path to test directory
#   $tok0 - sample v2 ctf token (no devid/pass)
#
# To regenerate all output files, use "make check TESTGEN=1"

set -ex

base="$1"
if [[ "$base" != *.pipe ]]; then
	echo "Invalid test file: $base"
	exit 1
fi
base="${base%.pipe}"

TESTDIR="${TESTDIR:-.}"
STOKEN="${STOKEN:-../stoken}"
if ! test -z "${VALGRIND}"; then
	STOKEN="${LIBTOOL:-libtool} --mode=execute ${VALGRIND} ${STOKEN}"
fi

tok0="--token=258491750817210752367175001073261277346642631755724762324173166222072472716737543"

out=""
while read x; do
	out=`eval $x`
done < ${base}.pipe

if [ "$TESTGEN" = "1" ]; then
	echo "$out" > ${base}.ref
else
	ref=`cat ${base}.ref`
	[ "$out" != "$ref" ] && exit 1
fi

exit 0
