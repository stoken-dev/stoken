#!/bin/bash

# Sample script to encode a token as a QR code.  Requires "display" from
# ImageMagick, and qrencode.  The input token must not be protected with
# a password or device ID.

if [ -n "$1" ]; then
	if [ -e "$1" ]; then
		args="--file $1"
	else
		args="--token $1"
	fi
else
	args=""
fi

token=$(stoken export --batch --android $args 2> /dev/null)
if [ $? != 0 ]; then
	echo "usage: $0 [ { <token_string> | <sdtid_file> } ]"
	exit 1
fi

set -ex

png=$(mktemp /tmp/qr-XXXXXX.png)
qrencode -o $png -l H "$token"
display $png
rm -f $png

exit 0
