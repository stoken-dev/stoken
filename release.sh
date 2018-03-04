#!/bin/sh

gpgkey="BC0B0D65"

set -ex

# autotools will search .:..:../.. for support files
# let's make sure it can't search our repo, so we know it is getting all
# required files from the release tarball
builddir=tmp.build/a/b/c/d
reldir=tmp.build/w/x/y/z
repodir=`pwd`

rm -rf tmp.build stoken-*.tar.gz stoken-*.tar.gz.asc
mkdir -p $reldir
git clone . $reldir

(
cd $reldir
./autogen.sh
./configure
fakeroot make dist
)
tarball=$(basename $(ls -1 $reldir/stoken-*.tar.gz))
mv $reldir/$tarball $repodir

mkdir -p $builddir
(
cd $builddir
tar -zxf $repodir/$tarball --strip 1
./configure --with-gtk
make
make distclean
./configure --with-gtk --prefix=/ CFLAGS="-Werror"
make
make install DESTDIR=`pwd`/pfx
make clean
)

rm -rf tmp.build

if gpg --list-secret-keys $gpgkey > /dev/null 2>&1; then
	gpg --yes --armor --detach-sign --default-key $gpgkey $tarball
fi

exit 0
