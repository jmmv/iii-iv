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

sinclude config.mk

PROD_ENV += EXAMPLE_POSTGRES_HOST="$(EXAMPLE_POSTGRES_HOST)"
PROD_ENV += EXAMPLE_POSTGRES_PORT="$(EXAMPLE_POSTGRES_PORT)"
PROD_ENV += EXAMPLE_POSTGRES_DATABASE="$(EXAMPLE_POSTGRES_DATABASE)"
PROD_ENV += EXAMPLE_POSTGRES_USERNAME="$(EXAMPLE_POSTGRES_USERNAME)"
PROD_ENV += EXAMPLE_POSTGRES_PASSWORD="$(EXAMPLE_POSTGRES_PASSWORD)"
PROD_ENV += RUST_LOG=debug

TEST_ENV += TEST_POSTGRES_HOST="$(TEST_POSTGRES_HOST)"
TEST_ENV += TEST_POSTGRES_PORT="$(TEST_POSTGRES_PORT)"
TEST_ENV += TEST_POSTGRES_DATABASE="$(TEST_POSTGRES_DATABASE)"
TEST_ENV += TEST_POSTGRES_USERNAME="$(TEST_POSTGRES_USERNAME)"
TEST_ENV += TEST_POSTGRES_PASSWORD="$(TEST_POSTGRES_PASSWORD)"
TEST_ENV += RUST_LOG=debug

.PHONY: default
default: Makefile serve

.PHONY: serve
serve:
	cargo build
	@$(PROD_ENV) ../target/debug/iii-iv-example

.PHONY: test
test:
	@$(TEST_ENV) cargo test $(TEST_ARGS) -- --include-ignored
