#!/bin/bash

set -ex

autoreconf --force --install --verbose
rm -rf autom4te*.cache
