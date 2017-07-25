#!/bin/sh

set -ex

autoreconf --force --install --verbose
rm -rf autom4te*.cache
