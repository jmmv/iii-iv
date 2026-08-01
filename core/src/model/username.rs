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
use serde::{Deserialize, Serialize, de::Visitor};
use std::borrow::Cow;

/// Maximum length of a username as specified in the schema.
pub(crate) const USERS_MAX_USERNAME_LENGTH: usize = 32;

/// Represents a correctly-formatted (but maybe non-existent) username.
///
/// Usernames are case-insensitive and, for simplicity reasons, we force them to be all in
/// lowercase.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Username(Cow<'static, str>);

impl Username {
    /// Checks if a username is valid, and returns an error message if it is not.
    const fn validate(name: &str) -> Option<&'static str> {
        if name.is_empty() {
            return Some("Username cannot be empty");
        }
        if name.len() > USERS_MAX_USERNAME_LENGTH {
            return Some("Username is too long");
        }

        let bytes = name.as_bytes();
        let mut index = 0;
        while index < bytes.len() {
            let byte = bytes[index];
            if !byte.is_ascii_lowercase()
                && !byte.is_ascii_digit()
                && byte != b'.'
                && byte != b'-'
                && byte != b'_'
            {
                return Some("Unsupported character in username");
            }
            index += 1;
        }
        None
    }

    /// Creates a new username from an untrusted string `s`, making sure it is valid.
    pub fn new<S: Into<String>>(s: S) -> ModelResult<Self> {
        let s = s.into().to_lowercase();
        if let Some(error) = Username::validate(&s) {
            return Err(ModelError(error.to_owned()));
        }
        Ok(Self(Cow::Owned(s)))
    }

    /// Creates a new username from a hardcoded string, which must be valid.
    #[cfg(any(test, feature = "testutils"))]
    pub const fn from_static(name: &'static str) -> Self {
        if Username::validate(name).is_some() {
            panic!("Hardcoded usernames must be valid and lowercase");
        }
        Self(Cow::Borrowed(name))
    }

    /// Creates a new username from an untrusted string `s`, without validation.  Useful for testing
    /// purposes only.
    #[cfg(any(test, feature = "testutils"))]
    pub fn new_invalid<S: Into<String>>(s: S) -> Self {
        Self(Cow::Owned(s.into()))
    }

    /// Returns a string view of the username.
    pub fn as_str(&self) -> &str {
        self.0.as_ref()
    }
}

/// Instantiates a username from a static string.
#[cfg(any(test, feature = "testutils"))]
#[macro_export]
macro_rules! __username__ {
    ( $string:expr ) => {
        $crate::model::Username::from_static($string)
    };
}

#[cfg(any(test, feature = "testutils"))]
pub use __username__ as username;

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
    use serde_test::{Token, assert_de_tokens_error, assert_tokens};

    #[test]
    fn test_username_ok() {
        assert_eq!(Username::from("simple"), Username::new("simple").unwrap());
        assert_eq!(Username::from("bar_baz93.xyz-2"), Username::new("bar_Baz93.xyz-2").unwrap());
    }

    #[test]
    fn test_username_from_static() {
        const CONST_USERNAME: Username = username!("const-user");
        static STATIC_USERNAME: Username = username!("static-user");

        assert_eq!("const-user", CONST_USERNAME.as_str());
        assert_eq!("static-user", STATIC_USERNAME.as_str());
    }

    #[test]
    #[should_panic(expected = "Hardcoded usernames must be valid and lowercase")]
    fn test_username_from_static_error() {
        Username::from_static("Invalid username");
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
            "Unsupported character in username",
        );
    }
}
