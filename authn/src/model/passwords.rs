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

//! The `Password` and `HashedPassword` data types.

use iii_iv_core::model::{ModelError, ModelResult};
use serde::{Deserialize, Serialize};
use std::fmt;

/// An opaque type to hold a password, protecting it from leaking into logs.
#[derive(Deserialize, PartialEq, Serialize)]
#[serde(transparent)]
#[cfg_attr(any(test, feature = "testutils"), derive(Clone))]
pub struct Password(String);

impl Password {
    /// Creates a new password from a literal string.
    pub fn new<S: Into<String>>(s: S) -> ModelResult<Self> {
        let s = s.into();
        if s.len() > 56 {
            return Err(ModelError("Password is too long".to_owned()));
        }
        Ok(Password(s))
    }

    /// Returns a string view of the password.
    #[cfg(any(test, feature = "testutils"))]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Hashes the password after validating that it is sufficiently complex via the `validator`
    /// hook.  Consumes the password because there is no context in which keeping the password
    /// alive once we have generated its hash is correct.
    pub fn validate_and_hash(
        self,
        validator: fn(&str) -> Option<&'static str>,
    ) -> ModelResult<HashedPassword> {
        if let Some(error) = validator(&self.0) {
            return Err(ModelError(format!("Weak password: {}", error)));
        }
        let hashed =
            bcrypt::hash(self.0, 10).map_err(|e| ModelError(format!("Password error: {}", e)))?;
        Ok(HashedPassword::new(hashed))
    }

    /// Verifies if this password matches a given `hash`.
    pub fn verify(self, hash: &HashedPassword) -> ModelResult<bool> {
        bcrypt::verify(self.0, hash.as_str())
            .map_err(|e| ModelError(format!("Password error: {}", e)))
    }
}

#[cfg(any(test, feature = "testutils"))]
impl From<&'static str> for Password {
    /// Creates a new password from a hardcoded string, which must be valid.
    fn from(s: &'static str) -> Self {
        Password::new(s).expect("Hardcoded passwords must be valid")
    }
}

impl fmt::Debug for Password {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("scrubbed password")
    }
}

/// An opaque type to hold a hashed password, protecting it from leaking into logs.
#[derive(PartialEq)]
#[cfg_attr(any(test, feature = "testutils"), derive(Clone))]
pub struct HashedPassword(String);

impl HashedPassword {
    /// Creates a new hashed password from a literal string.
    pub fn new<S: Into<String>>(s: S) -> Self {
        HashedPassword(s.into())
    }

    /// Returns a string view of the hash.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for HashedPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("scrubbed hash")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_ok() {
        assert_eq!(Password::from("foo"), Password::new("foo").unwrap());
        assert_eq!("bar", Password::new("bar").unwrap().as_str());
    }

    #[test]
    fn test_password_error() {
        assert!(
            Password::new(
                "this password is way too long to be valid because of bcrypt restrictions"
            )
            .is_err()
        );
    }

    #[test]
    fn test_password_validate_and_hash() {
        let password = Password::from("abcd");
        password.clone().validate_and_hash(|_| None).unwrap();
        match password.validate_and_hash(|_| Some("the error")) {
            Err(e) => assert_eq!("Weak password: the error", e.0),
            e => panic!("{:?}", e),
        }
    }

    #[test]
    fn test_password_hash_and_verify() {
        let password1 = Password::from("first password");
        let password2 = Password::from("second password");
        let hash1 = password1.clone().validate_and_hash(|_| None).unwrap();
        let hash2 = password2.clone().validate_and_hash(|_| None).unwrap();

        assert!(hash1.as_str().starts_with("$2b$10$"));
        assert!(hash2.as_str().starts_with("$2b$10$"));
        assert!(hash1 != hash2);

        assert!(password1.clone().verify(&hash1).unwrap());
        assert!(!password2.clone().verify(&hash1).unwrap());
        assert!(!password1.verify(&hash2).unwrap());
        assert!(password2.verify(&hash2).unwrap());
    }
}
