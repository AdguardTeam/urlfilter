#!/bin/sh

# This comment is used to simplify checking local copies of the script.  Bump
# this number every time a significant change is made to this script.
#
# AdGuard-Project-Version: 3

verbose="${VERBOSE:-0}"
readonly verbose

set -e -f -u

if [ "$verbose" -gt '0' ]; then
	set -x
fi

# TODO(a.garipov):  Add all *.md files.
markdownlint \
	./README.md \
	./cmd/README.md \
	;
