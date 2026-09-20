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

: "${USER:=$(id -un)}"

touch config.env
chmod 600 config.env

cat >>config.env <<EOF
export TEST_POSTGRES_DATABASE="${USER}-test"
export TEST_POSTGRES_USERNAME="${USER}"

# Use peer authentication.  This is the default, but be clear.
unset TEST_POSTGRES_HOST
unset TEST_POSTGRES_PORT
unset TEST_POSTGRES_PASSWORD
EOF

. ./config.env

sudo systemctl start postgresql
pg_isready
sudo -u postgres psql -c "CREATE USER \"${TEST_POSTGRES_USERNAME}\";"
sudo -u postgres psql -c "CREATE DATABASE \"${TEST_POSTGRES_DATABASE}\" OWNER \"${TEST_POSTGRES_USERNAME}\";"
