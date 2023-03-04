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

TEST_ENV += PGSQL_TEST_HOST="$(PGSQL_TEST_HOST)"
TEST_ENV += PGSQL_TEST_PORT="$(PGSQL_TEST_PORT)"
TEST_ENV += PGSQL_TEST_DATABASE="$(PGSQL_TEST_DATABASE)"
TEST_ENV += PGSQL_TEST_USERNAME="$(PGSQL_TEST_USERNAME)"
TEST_ENV += PGSQL_TEST_PASSWORD="$(PGSQL_TEST_PASSWORD)"
TEST_ENV += RUST_LOG=debug

.PHONY: build
build:
	cargo build
	cargo build --features=testutils

.PHONY: test
test: test-individually test-workspace

.PHONY: test-individually
test-individually:
	@set -e; \
	for crate in $$(grep '^ *"' Cargo.toml | cut -d '"' -f 2); do \
            cd $$crate; \
	    echo "cd $$crate && cargo test -- --include-ignored"; \
	    $(TEST_ENV) cargo test -- --include-ignored; \
	    if grep -q ^testutils Cargo.toml; then \
	        echo "cd $$crate && cargo test --features=testutils -- --include-ignored"; \
	        $(TEST_ENV) cargo test --features=testutils -- --include-ignored; \
	    fi; \
	    cd -; \
	done

.PHONY: test-workspace
test-workspace:
	@echo cargo test -- --include-ignored
	@$(TEST_ENV) cargo test -- --include-ignored
	@echo cargo test --features=testutils -- --include-ignored
	@$(TEST_ENV) cargo test --features=testutils -- --include-ignored

.PHONY: lint
lint:
	pre-commit run -a
	cargo clippy -- -D warnings
	cargo clippy --features=testutils -- -D warnings
	cargo fmt -- --check

.PHONY: clean
clean:
	cargo clean

.PHONY: cleandir
distclean: clean
