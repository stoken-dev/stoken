#!/bin/bash

set -ex

mkdir -p m4
autoreconf --force --install --verbose
rm -rf autom4te*.cache
