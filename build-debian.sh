#!/bin/bash

set -ex

function build_one
{
	arg="$1"

	rm -rf tmp.deb
	mkdir tmp.deb
	pushd tmp.deb

	cp ../$tarball stoken_${ver}.orig.tar.gz
	tar zxf ../$tarball
	cd stoken-${ver}
	cp -a ../../debian .
	debuild "$arg"
	cd ..
	lintian -IE --pedantic *.changes >> ../lintian.txt || true
	popd
}

#
# MAIN
#

tarball=$(ls -1 stoken-*.tar.gz 2> /dev/null || true)
if [ -z "$tarball" -o ! -e "$tarball" ]; then
	echo "missing release tarball"
	exit 1
fi

ver=${tarball#*-}
ver=${ver%%.tar.gz}

rm -f lintian.txt
touch lintian.txt

build_one ""
echo "------------" >> lintian.txt
build_one "-S"

echo "lintian:"
cat lintian.txt

exit 0
