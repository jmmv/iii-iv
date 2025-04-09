// III-IV
// Copyright 2023 Julio Merino
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

//! The `Username` data type.

use crate::model::{ModelError, ModelResult};
use serde::{de::Visitor, Deserialize, Serialize};

/// Maximum length of a username as specified in the schema.
pub(crate) const USERS_MAX_USERNAME_LENGTH: usize = 32;

/// Represents a correctly-formatted (but maybe non-existent) username.
///
/// Usernames are case-insensitive and, for simplicity reasons, we force them to be all in
/// lowercase.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Username(String);

impl Username {
    /// Creates a new username from an untrusted string `s`, making sure it is valid.
    pub fn new<S: Into<String>>(s: S) -> ModelResult<Self> {
        let s = s.into();

        if s.is_empty() {
            return Err(ModelError("Username cannot be empty".to_owned()));
        }
        if s.len() > USERS_MAX_USERNAME_LENGTH {
            return Err(ModelError("Username is too long".to_owned()));
        }

        for ch in s.chars() {
            if !(ch.is_ascii_alphanumeric() || ".-_".find(ch).is_some()) {
                return Err(ModelError(format!(
                    "Unsupported character '{}' in username '{}'",
                    ch, s
                )));
            }
        }

        Ok(Self(s.to_lowercase()))
    }

    /// Creates a new username from an untrusted string `s`, without validation.  Useful for testing
    /// purposes only.
    #[cfg(any(test, feature = "testutils"))]
    pub fn new_invalid<S: Into<String>>(s: S) -> Self {
        Self(s.into())
    }

    /// Returns a string view of the username.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[cfg(any(test, feature = "testutils"))]
impl From<&'static str> for Username {
    /// Creates a new username from a hardcoded string, which must be valid.
    fn from(name: &'static str) -> Self {
        assert_eq!(name, name.to_lowercase(), "Hardcoded usernames must be lowercase");
        Username::new(name).expect("Hardcoded usernames must be valid")
    }
}

/// A deserialization visitor for a `Username`.
struct UsernameVisitor;

impl Visitor<'_> for UsernameVisitor {
    type Value = Username;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a string")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Username::new(v).map_err(|e| E::custom(e.to_string()))
    }

    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Username::new(v).map_err(|e| E::custom(e.to_string()))
    }
}

impl<'de> Deserialize<'de> for Username {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_string(UsernameVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_test::{assert_de_tokens_error, assert_tokens, Token};

    #[test]
    fn test_username_ok() {
        assert_eq!(Username::from("simple"), Username::new("simple").unwrap());
        assert_eq!(Username::from("bar_baz93.xyz-2"), Username::new("bar_Baz93.xyz-2").unwrap());
    }

    #[test]
    fn test_username_error() {
        assert!(Username::new("").is_err());
        assert!(Username::new("foo bar").is_err());
        assert!(Username::new("foo@example.com").is_err());
        assert!(Username::new("foo\u{00e9}bar").is_err());
        assert!(Username::new("name1,name2").is_err());
        assert!(Username::new("name1:name2").is_err());

        let mut long_string = "12345678901234567890123456789012".to_owned();
        assert!(Username::new(&long_string).is_ok());
        long_string.push('x');
        assert!(Username::new(&long_string).is_err());
    }

    #[test]
    fn test_username_invalid() {
        assert!(Username::new(Username::new_invalid("a b").as_str()).is_err());
    }

    #[test]
    fn test_username_case_insensitive_lowercase() {
        assert_eq!(Username::from("foo"), Username::new("Foo").unwrap());
        assert_ne!(Username::from("foo"), Username::new("fo").unwrap());

        assert_eq!("someusername", Username::new("SomeUsername").unwrap().as_str());
    }

    #[test]
    fn test_username_ser_de_ok() {
        let code = Username::new("HelloWorld").unwrap();
        assert_tokens(&code, &[Token::String("helloworld")]);
    }

    #[test]
    fn test_username_de_error() {
        assert_de_tokens_error::<Username>(
            &[Token::String("hello world")],
            "Unsupported character ' ' in username 'hello world'",
        );
    }
}
