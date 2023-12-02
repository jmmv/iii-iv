#! /bin/sh
# III-IV
# Copyright 2023 Julio Merino
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

run_tests() {
    local dir="${1}"; shift
    local cargo_args="${1}"; shift
    local test_args="${1}"; shift
    local features="${1}"; shift

    (
        if [ -e ./config.env ]; then
            info "Loading ./config.env"
            . ./config.env
        fi

        cd "${dir}"

        for feature in ${features}; do
            if [ "${feature}" = default ]; then
                info "Testing ${dir} with default features"
                cargo test ${cargo_args} -- --include-ignored ${test_args}
            else
                if grep -q "^{feature} = \[" Cargo.toml; then
                    info "Testing ${dir} with feature=${feature}"
                    cargo test --features="${feature}" ${cargo_args} -- --include-ignored ${test_args}
                else
                    info "Skipping ${dir} with feature=${feature}"
                fi
            fi
        done
    )
}

usage() {
    cat <<EOF
Usage: ${PROGNAME} [-A cargo_arg] [-a test_arg] [-f feature] [crate1 .. crateN]

If no crates are specified, runs all tests from the root of the workspace.

If one or more crates are specified, runs all tests from the individual crate
directories.  The special name "all" can be used to run tests for all crates
individually.

The -A flag specifies extra arguments to "cargo test".  This flag can be used
multiple times and the values all accumulate.

The -a flag specifies extra arguments to the test programs.  This flag can be
used multiple times and the values all accumulate.

The -f flag specifies the individual features to test.  This flag can be used
multiple times and the valus all accumulate.  If not specified, all known
features are tested individually.
EOF
}

main() {
    local cargo_args=
    local test_args=
    local features=
    while getopts ':A:a:f:h' arg "${@}"; do
        case "${arg}" in
            A)
                cargo_args="${cargo_args} ${OPTARG}"
                ;;

            a)
                test_args="${test_args} ${OPTARG}"
                ;;

            f)
                features="${features} ${OPTARG}"
                ;;

            h)
                usage
                exit 0
                ;;

            :)
                err "Missing argument to option -${OPTARG} in build"
                ;;

            \?)
                err "Unknown option -${OPTARG} in build"
                ;;
        esac
    done
    shift $((OPTIND - 1))

    [ -n "${features}" ] || features="default postgres sqlite testutils"

    [ -e ./.github ] || err "Must be run from the root of the workspace"

    if [ ${#} -eq 0 ]; then
        run_tests . "${cargo_args}" "${test_args}" "${features}"
    else
        local crates=
        if [ ${#} -eq 1 -a "${1}" = all ]; then
            crates="$(grep '^ *"' Cargo.toml | cut -d '"' -f 2)"
            info "Expanded crates to test to $(echo ${crates})"
        else
            crates="${*}"
        fi

        for crate in ${crates}; do
            run_tests "${crate}" "${cargo_args}" "${test_args}" "${features}"
        done
    fi
}

main "${@}"
