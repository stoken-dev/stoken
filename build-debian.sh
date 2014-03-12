#!/bin/bash

gpgkey="BC0B0D65"
builddir=tmp.debian

set -ex

function build_one
{
	arg="$1"

	rm -rf $builddir
	mkdir $builddir
	pushd $builddir

	cp ../$tarball stoken_${ver}.orig.tar.gz
	tar zxf ../$tarball
	cd stoken-${ver}
	cp -a ../../debian .
	if [ "$nosign" = "0" ]; then
		debuild "$arg"
	else
		debuild "$arg" -us -uc
	fi
	cd ..
	lintian -IE --pedantic *.changes | tee -a ../lintian.txt || true
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

if gpg --list-secret-keys $gpgkey >& /dev/null; then
	nosign=0
else
	nosign=1
fi

rm -f lintian.txt stoken*.deb
touch lintian.txt

build_one ""
cp $builddir/*.deb .
echo "------------" >> lintian.txt
build_one "-S"

echo "lintian:"
cat lintian.txt

exit 0
