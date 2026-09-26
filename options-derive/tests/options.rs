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

/// Options that require construction-time validation.
#[derive(Debug, iii_iv_options_derive::Options)]
#[options(prefix = "", constructor = Self::new)]
struct ConstructorOptions {
    /// Value checked by the constructor.
    constructor_value: u8,
}

impl ConstructorOptions {
    /// Constructs validated options.
    fn new(constructor_value: u8) -> Result<Self, String> {
        if constructor_value == 0 {
            Err("Constructor value cannot be zero".to_owned())
        } else {
            Ok(Self { constructor_value })
        }
    }
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
                    ("TEST_DERIVED_REQUIRED".to_owned(), Some("value".to_owned())),
                    ("TEST_DERIVED_OPTIONAL".to_owned(), Some("123".to_owned())),
                    ("TEST_DERIVED_DEFAULTED".to_owned(), Some("42".to_owned())),
                    ("TEST_DERIVED_TIMEOUT".to_owned(), Some("120s".to_owned())),
                    ("TEST_DERIVED_SECRET".to_owned(), Some("scrubbed secret".to_owned())),
                ],
                options.format_all("TEST")
            );
        },
    );
}

#[test]
#[serial]
fn test_options_optional_unset() {
    temp_env::with_vars(
        [
            ("TEST_DERIVED_REQUIRED", Some("value")),
            ("TEST_DERIVED_OPTIONAL", None),
            ("TEST_DERIVED_SECRET", Some("secret")),
        ],
        || {
            let options = DerivedOptions::from_env("TEST").unwrap();
            assert_eq!(
                vec![
                    ("TEST_DERIVED_REQUIRED".to_owned(), Some("value".to_owned())),
                    ("TEST_DERIVED_OPTIONAL".to_owned(), None),
                    ("TEST_DERIVED_DEFAULTED".to_owned(), Some("42".to_owned())),
                    ("TEST_DERIVED_TIMEOUT".to_owned(), Some("60s".to_owned())),
                    ("TEST_DERIVED_SECRET".to_owned(), Some("scrubbed secret".to_owned())),
                ],
                options.format_all("TEST")
            );
        },
    );
}

#[test]
#[serial]
fn test_options_constructor() {
    temp_env::with_var("TEST_CONSTRUCTOR_VALUE", Some("2"), || {
        assert_eq!(2, ConstructorOptions::from_env("TEST").unwrap().constructor_value);
    });
    temp_env::with_var("TEST_CONSTRUCTOR_VALUE", Some("0"), || {
        assert!(ConstructorOptions::from_env("TEST").unwrap_err().contains("cannot be zero"));
    });
}
