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

//! Generic data types often useful in REST services.

use std::fmt;

mod emailaddress;
pub use emailaddress::EmailAddress;
#[cfg(any(test, feature = "testutils"))]
pub use emailaddress::email_address;
mod username;
pub use username::Username;
#[cfg(any(test, feature = "testutils"))]
pub use username::username;

/// An opaque string that contains sensitive data.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretString(String);

impl SecretString {
    /// Creates a new secret string.
    pub fn new(value: String) -> Self {
        Self(value)
    }

    /// Returns a string view of the secret.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the secret string.
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("scrubbed secret")
    }
}

/// Data model errors.
#[derive(Debug, PartialEq, thiserror::Error)]
#[error("{0}")]
pub struct ModelError(pub String);

/// Result type for this module.
pub type ModelResult<T> = Result<T, ModelError>;
