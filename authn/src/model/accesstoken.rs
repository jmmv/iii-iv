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

//! The `AccessToken` data type.

use iii_iv_core::model::{ModelError, ModelResult};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Length of our binary tokens, in bytes.
///
/// This is not customizable because this size is replicated in the database schema and we cannot
/// simply change what it is at runtime.
const TOKEN_LENGTH: usize = 256;

/// An opaque type representing a user's access token.
///
/// Access tokens are user-readable character sequences of a fixed size.
#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct AccessToken(String);

impl AccessToken {
    /// Creates a new access token.
    pub fn new<S: Into<String>>(token: S) -> ModelResult<Self> {
        let token = token.into();
        if token.len() != TOKEN_LENGTH {
            return Err(ModelError("Invalid access token".to_owned()));
        }
        for ch in token.chars() {
            if !ch.is_ascii_alphanumeric() {
                return Err(ModelError("Invalid access token".to_owned()));
            }
        }
        Ok(Self(token))
    }

    /// Generates a new access token.
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        let mut token = String::with_capacity(TOKEN_LENGTH);
        for _ in 0..TOKEN_LENGTH {
            let i = rng.gen_range(0..(10 + 26 + 26));
            let ch = if i < 10 {
                (b'0' + i) as char
            } else if i < 10 + 26 {
                (b'a' + (i - 10)) as char
            } else {
                (b'A' + (i - 10 - 26)) as char
            };
            assert!(ch.is_alphanumeric());
            token.push(ch);
        }
        Self::new(token).expect("Auto-generated tokens must be valid")
    }

    /// Returns the string representation of the token.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for AccessToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("scrubbed access token")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_accesstoken_ok() {
        let mut raw_token = String::new();
        for _ in 0..TOKEN_LENGTH {
            raw_token.push('a');
        }
        let token = AccessToken::new(&raw_token).unwrap();
        assert_eq!(&raw_token, token.as_str());
    }

    #[test]
    fn test_accesstoken_error_too_short() {
        AccessToken::new("abcde").unwrap_err();
    }

    #[test]
    fn test_accesstoken_error_invalid_character() {
        let raw_token = "!".repeat(TOKEN_LENGTH);
        AccessToken::new(raw_token).unwrap_err();
    }

    #[test]
    fn test_accesstoken_error_too_long() {
        let mut raw_token = "b".repeat(TOKEN_LENGTH);
        AccessToken::new(raw_token.clone()).unwrap();
        raw_token.push('b');
        AccessToken::new(raw_token).unwrap_err();
    }

    #[test]
    fn test_accesstoken_generate_unique() {
        let mut raw_tokens = HashSet::<String>::default();
        for _ in 0..1000 {
            raw_tokens.insert(AccessToken::generate().as_str().to_owned());
        }
        assert_eq!(1000, raw_tokens.len());
    }
}
