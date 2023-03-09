#!/bin/sh

gpgkey="BC0B0D65"
ppaname="cernekee/ppa"

builddir=tmp.debian
pkg=stoken

build_one() {
	arg="$1"

	rm -rf $builddir
	mydir=$(pwd)
	mkdir $builddir
	cd $builddir

	cp ../$tarball "${pkg}_${ver}.orig.tar.gz"
	mkdir "$pkg-$ver"
	cd "$pkg-$ver"
	tar --strip 1 -zxf ../../$tarball
	cp -a ../../ppa debian
	if [ "$nosign" = "0" ]; then
		debuild "$arg"
	else
		debuild "$arg" -us -uc
	fi
	cd ..
	lintian -IE --pedantic *.changes | tee -a ../lintian.txt || true
	cd $mydir
}

#
# MAIN
#

if [ ! -d misc ]; then
	cd ..
fi

release=0

while [ -n "$1" ]; do
	case "$1" in
		-r)
			release=1
			;;
		*)
			echo "usage: $0 [-r]"
			exit 1
			;;
	esac
	shift
done

tarball=$(ls -1 ${pkg}-*.tar.gz 2> /dev/null || true)
if [ -z "$tarball" -o ! -e "$tarball" ]; then
	echo "missing release tarball"
	exit 1
fi

ver=${tarball#*-}
ver=${ver%%.tar.gz}

if gpg --list-secret-keys $gpgkey > /dev/null 2>&1; then
	nosign=0
else
	nosign=1
fi

rm -f lintian.txt ${pkg}*.deb
touch lintian.txt

set -ex

dist=$(lsb_release -si)

rm -f ppa/changelog
if [ "$dist" = "Ubuntu" ]; then
	codename=$(lsb_release -sc)

	if [ $release != 1 ]; then
		today=$(date +%Y%m%d%H%M%S)
		ver="${ver}~${today}"
	fi
	uver="${ver}-1ppa1"

	dch --create --changelog ppa/changelog --package $pkg \
		--newversion "${uver}~${codename}" \
		--distribution $codename \
		"New PPA build."
else
	dch --create --changelog ppa/changelog --package $pkg \
		--newversion "${ver}-1" \
		--distribution unstable \
		"New Debian test build. (Closes: #123456)"
fi

build_one ""
cp $builddir/*.deb .
echo "------------" >> lintian.txt
build_one "-S"

set +ex

echo "--------"
echo "lintian:"
echo "--------"
cat lintian.txt
echo "--------"

if [ -n "$uver" -a "$nosign" = "0" ]; then
	echo ""
	echo "UPLOAD COMMAND:"
	echo ""
	echo "    dput ppa:$ppaname tmp.debian/*_source.changes"
	echo ""
fi

exit 0
