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

# `brew install valgrind` fails:
# https://github.com/Homebrew/homebrew-core/issues/23536
if [[ "$OSTYPE" == "darwin"* ]]; then
	../configure $args
else
	../configure --enable-valgrind $args
fi

make

# try to ferret out any possible timezone dependencies
for x in Pacific/Honolulu America/New_York Europe/Athens \
	 Asia/Calcutta Australia/Sydney; do
	TZ=$x make check
done

make dist
popd

exit 0
