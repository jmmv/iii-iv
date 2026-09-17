#! /bin/sh
# III-IV
# Copyright 2026 Julio Merino
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License.  You may obtain a copy
# of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
# License for the specific language governing permissions and limitations
# under the License.

set -eu

readonly PROGNAME="${0##*/}"

err() {
    echo "${PROGNAME}: E: ${*}" 1>&2
    exit 1
}

info() {
    echo "${PROGNAME}: I: ${*}" 1>&2
}

check_crate() {
    local crate="${1}"

    (
        cd "${crate}"
        info "Checking ${crate} with default features"
        cargo check --all-targets

        if grep -q '^testutils[[:space:]]*=' Cargo.toml; then
            info "Checking ${crate} with feature=testutils"
            cargo check --all-targets --features=testutils
        fi
    )
}

main() {
    [ -e ./.github ] || err "Must be run from the root of the workspace"

    local crates
    crates="$(grep '^ *"' Cargo.toml | cut -d '"' -f 2)"
    info "Expanded crates to check to $(echo ${crates})"

    for crate in ${crates}; do
        check_crate "${crate}"
    done
}

main "${@}"
