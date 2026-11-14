#! /bin/sh

is=
is="${is} RUSTSEC-2026-0459"  # `libsqlite3-sys` via C SQLite CVE-2026-119375.
args="-D warnings"
for i in ${is}; do
    args="${args} --ignore ${i}"
done

set -x
# shellcheck disable=SC2086  # args requires word-splitting.
exec cargo audit ${args}
