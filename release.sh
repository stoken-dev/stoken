#!/bin/bash

gpgkey="BC0B0D65"

set -ex
set -o pipefail

rm -rf tmp.rel tmp.build stoken-*.tar.gz stoken-*.tar.gz.asc
git clone . tmp.rel

pushd tmp.rel
./autogen.sh
./configure
fakeroot make dist
tarball=$(ls -1 stoken-*.tar.gz)
mv $tarball ../
popd

mkdir tmp.build
pushd tmp.build
tar -zxf ../$tarball --strip 1
./configure --with-gtk
make
make distclean
./configure --with-gtk --prefix=/ CFLAGS="-Werror"
make
make install DESTDIR=`pwd`/pfx
make clean
popd

rm -rf tmp.rel tmp.build

if gpg --list-secret-keys $gpgkey >& /dev/null; then
	gpg --yes --armor --detach-sign --default-key $gpgkey $tarball
fi

exit 0
