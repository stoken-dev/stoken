#!/bin/bash

set -ex

# perform a single test build + check
# used for travis-ci automated builds

if [ ! -d misc ]; then
	cd ..
fi

lib="$1"
if [ "$lib" = "nettle" ]; then
	args="--without-tomcrypt --with-nettle"
elif [ "$lib" = "tomcrypt" ]; then
	args="--with-tomcrypt --without-nettle"
else
	echo "usage: $0 <tomcrypt | nettle>"
	exit 1
fi

# Apple libtool != GNU libtool
# So "make check" needs to run "glibtool --mode=execute"
if [ `uname -s` = Darwin ]; then
	export LIBTOOL=glibtool
fi

rm -rf build.$lib
mkdir build.$lib
pushd build.$lib
../configure --enable-valgrind $args
make
make check
make dist
popd

exit 0
