#! /bin/sh

set -x
exec cargo audit -D warnings
