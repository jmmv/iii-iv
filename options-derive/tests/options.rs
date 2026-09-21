// III-IV
// Copyright 2026 Julio Merino
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License.  You may obtain a copy
// of the License at:
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
// License for the specific language governing permissions and limitations
// under the License.

//! Integration tests for the `Options` derive macro.

use iii_iv_core::{config::Options, model::SecretString};
use serial_test::serial;
use std::time::Duration;

/// Options derived from an environment namespace.
#[derive(Debug, iii_iv_options_derive::Options)]
#[options(prefix = "DERIVED")]
struct DerivedOptions {
    /// Required string option.
    required: String,

    /// Optional numeric option.
    optional: Option<u16>,

    /// Numeric option with a default.
    #[option(default = 42)]
    defaulted: u16,

    /// Duration option with a default.
    #[option(default = Duration::from_secs(60))]
    timeout: Duration,

    /// Required secret option.
    secret: SecretString,
}

#[test]
#[serial]
fn test_options() {
    temp_env::with_vars(
        [
            ("TEST_DERIVED_REQUIRED", Some("value")),
            ("TEST_DERIVED_OPTIONAL", Some("123")),
            ("TEST_DERIVED_SECRET", Some("secret")),
            ("TEST_DERIVED_TIMEOUT", Some("2m")),
        ],
        || {
            let options = DerivedOptions::from_env("TEST").unwrap();
            assert_eq!("value", options.required);
            assert_eq!(Some(123), options.optional);
            assert_eq!(42, options.defaulted);
            assert_eq!(Duration::from_secs(120), options.timeout);
            assert_eq!("secret", options.secret.as_str());
            assert_eq!(
                vec![
                    ("TEST_DERIVED_REQUIRED".to_owned(), "value".to_owned()),
                    ("TEST_DERIVED_OPTIONAL".to_owned(), "Some(123)".to_owned()),
                    ("TEST_DERIVED_DEFAULTED".to_owned(), "42".to_owned()),
                    ("TEST_DERIVED_TIMEOUT".to_owned(), "120s".to_owned()),
                    ("TEST_DERIVED_SECRET".to_owned(), "scrubbed secret".to_owned()),
                ],
                options.format_all("TEST")
            );
        },
    );
}
