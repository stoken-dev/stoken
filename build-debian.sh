#!/bin/bash

ver=0.5

set -ex

rm -rf tmp.deb
mkdir -p tmp.deb

make distclean || true
./autogen.sh
./configure
make dist

cd tmp.deb
cp ../stoken-${ver}.tar.gz stoken_${ver}.orig.tar.gz
tar zxf stoken_${ver}.orig.tar.gz
cd stoken-${ver}
cp -a ../../debian .
debuild -us -uc

exit 0
