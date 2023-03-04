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

PROD_ENV += PGSQL_PROD_HOST="$(PGSQL_PROD_HOST)"
PROD_ENV += PGSQL_PROD_PORT="$(PGSQL_PROD_PORT)"
PROD_ENV += PGSQL_PROD_DATABASE="$(PGSQL_PROD_DATABASE)"
PROD_ENV += PGSQL_PROD_USERNAME="$(PGSQL_PROD_USERNAME)"
PROD_ENV += PGSQL_PROD_PASSWORD="$(PGSQL_PROD_PASSWORD)"
PROD_ENV += RUST_LOG=debug

TEST_ENV += PGSQL_TEST_HOST="$(PGSQL_TEST_HOST)"
TEST_ENV += PGSQL_TEST_PORT="$(PGSQL_TEST_PORT)"
TEST_ENV += PGSQL_TEST_DATABASE="$(PGSQL_TEST_DATABASE)"
TEST_ENV += PGSQL_TEST_USERNAME="$(PGSQL_TEST_USERNAME)"
TEST_ENV += PGSQL_TEST_PASSWORD="$(PGSQL_TEST_PASSWORD)"
TEST_ENV += RUST_LOG=debug

CROSS_TARGET = x86_64-unknown-linux-musl

.PHONY: default
default: Makefile serve

.PHONY: serve
serve:
	cargo build
	cp ../target/debug/iii-iv-example functions/
	@cd functions && $(PROD_ENV) func start

.PHONY: test
test:
	@$(TEST_ENV) cargo test $(TEST_ARGS) -- --include-ignored

.PHONY: functions/iii-iv-example
functions/iii-iv-example:
	cargo build --release --target=$(CROSS_TARGET)
	cp ../target/$(CROSS_TARGET)/release/iii-iv-example functions/

CLEANFILES += deploy.zip deploy.zip.dir
.PHONY: deploy.zip
deploy.zip: functions/iii-iv-example
	@$(TEST_PROD) cargo test --release --target=$(CROSS_TARGET) -- --include-ignored
	rm -rf deploy.zip.dir
	cp -r functions deploy.zip.dir
	for f in $$(cat deploy.zip.dir/.funcignore); do rm "deploy.zip.dir/$$f"; done
	rm deploy.zip.dir/.funcignore
	( cd deploy.zip.dir && zip -9 -r ../deploy.zip . )
