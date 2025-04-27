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

//! The `EmailAddress` data type.

use crate::model::{ModelError, ModelResult};
use serde::de::Visitor;
use serde::{Deserialize, Serialize};

/// Maximum length of email addresses per the schema.
pub(crate) const MAX_EMAIL_LENGTH: usize = 64;

/// Represents a correctly-formatted email address.
///
/// According to the standard, the local part of an email address may be case sensitive but the
/// domain part is case insensitive.  Given that we only persist email addresses for tracing
/// purposes, this treats them as case sensitive overall.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct EmailAddress(String);

impl EmailAddress {
    /// Creates a new email address from an untrusted string `s`, making sure it is valid.
    pub fn new<S: Into<String>>(s: S) -> ModelResult<Self> {
        let s = s.into();

        if s.trim().is_empty() {
            return Err(ModelError("Email address cannot be empty".to_owned()));
        }
        if s.len() > MAX_EMAIL_LENGTH {
            return Err(ModelError("Email address is too long".to_owned()));
        }

        // Email addresses can have many formats, and attempting to validate them is futile.  Given
        // that they come from Azure AAD and thus they have been used to verify the account, we'll
        // trust that they are valid.  But we do some tiny validation anyway to make sure we at
        // least pass data around correctly.
        if !s.contains('@') || s.contains(' ') {
            return Err(ModelError(format!("Email does not look like a valid address '{}'", s)));
        }

        Ok(Self(s))
    }

    /// Creates a new email address from an untrusted string `s`, without validation.  Useful for
    /// testing purposes only.
    #[cfg(any(test, feature = "testutils"))]
    pub fn new_invalid<S: Into<String>>(s: S) -> Self {
        Self(s.into())
    }

    /// Returns a string view of the email address.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[cfg(feature = "testutils")]
impl From<&str> for EmailAddress {
    fn from(raw_email: &str) -> Self {
        Self::new(raw_email).expect("Hardcoded email addresses for testing must be valid")
    }
}

/// Visitor to deserialize an `EmailAddress` from a string.
struct EmailAddressVisitor;

impl Visitor<'_> for EmailAddressVisitor {
    type Value = EmailAddress;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str(r#"a two-letter country ISO code"#)
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        match EmailAddress::new(v) {
            Ok(code) => Ok(code),
            Err(e) => Err(E::custom(format!("{}", e))),
        }
    }

    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        match EmailAddress::new(v) {
            Ok(code) => Ok(code),
            Err(e) => Err(E::custom(format!("{}", e))),
        }
    }
}

impl<'de> Deserialize<'de> for EmailAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_string(EmailAddressVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_test::{Token, assert_de_tokens_error, assert_tokens};

    #[test]
    fn test_emailaddress_ok() {
        assert_eq!("simple@example.com", EmailAddress::new("simple@example.com").unwrap().as_str());
        assert_eq!("a!b@c", EmailAddress::new("a!b@c").unwrap().as_str());
    }

    #[cfg(feature = "testutils")]
    #[test]
    fn test_emailaddress_into() {
        assert_eq!(EmailAddress::new("a@example.com").unwrap(), "a@example.com".into());
    }

    #[test]
    fn test_emailaddress_error() {
        assert!(EmailAddress::new("").is_err());
        assert!(EmailAddress::new("foo").is_err());
        assert!(EmailAddress::new("foo!bar").is_err());

        let mut long_string =
            "@234567890123456789012345678901234567890123456789012345678901234".to_owned();
        assert!(EmailAddress::new(&long_string).is_ok());
        long_string.push('x');
        assert!(EmailAddress::new(&long_string).is_err());
    }

    #[test]
    fn test_emailaddress_invalid() {
        assert!(EmailAddress::new(EmailAddress::new_invalid("a").as_str()).is_err());
    }

    #[test]
    fn test_emailaddress_case_sensitive() {
        assert_ne!(
            EmailAddress::new("foo@example.com").unwrap(),
            EmailAddress::new("Foo@example.com").unwrap()
        );
        assert_ne!(
            EmailAddress::new("foo@example.com").unwrap(),
            EmailAddress::new("foo@Example.Com").unwrap()
        );
    }

    #[test]
    fn test_emailaddress_ser_de_ok() {
        let code = EmailAddress::new("HelloWorld@example.com").unwrap();
        assert_tokens(&code, &[Token::String("HelloWorld@example.com")]);
    }

    #[test]
    fn test_emailaddress_de_error() {
        assert_de_tokens_error::<EmailAddress>(
            &[Token::String("HelloWorld")],
            "Email does not look like a valid address 'HelloWorld'",
        );
    }
}
