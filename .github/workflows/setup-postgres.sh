#! /bin/sh
# III-IV
# Copyright 2025 Julio Merino
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

touch config.env
chmod 600 config.env

cat >>config.env <<EOF
export PGSQL_TEST_HOST=localhost
export PGSQL_TEST_PORT=5432
export PGSQL_TEST_DATABASE=iii-iv-test
export PGSQL_TEST_USERNAME=runner
export PGSQL_TEST_PASSWORD=just-for-testing
EOF

. ./config.env

sudo systemctl start postgresql
pg_isready
sudo -u postgres psql -c "CREATE USER \"${PGSQL_TEST_USERNAME}\" WITH PASSWORD '${PGSQL_TEST_PASSWORD}';"
sudo -u postgres psql -c "CREATE DATABASE \"${PGSQL_TEST_DATABASE}\" OWNER \"${PGSQL_TEST_USERNAME}\";"
