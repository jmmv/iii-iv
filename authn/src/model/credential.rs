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

//! Purpose-bound email credentials.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use iii_iv_core::model::Sha256Sum;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

/// Operation authorized by an emailed credential.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum CredentialPurpose {
    /// Verify the account email address.
    Activation,
    /// Set a new password and verify the account email address.
    Recovery,
}

impl CredentialPurpose {
    /// Stable database representation.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Activation => "activation",
            Self::Recovery => "recovery",
        }
    }
}

/// A secret URL-safe credential.  Debug output deliberately hides its value.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct EmailToken(String);

impl std::fmt::Debug for EmailToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EmailToken([redacted])")
    }
}

impl EmailToken {
    /// Generates a fresh 256-bit credential.
    pub fn generate() -> Self {
        Self(URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()))
    }

    /// Returns the secret value for an email link.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Computes the purpose-bound digest stored with the account.
    pub fn digest(&self, purpose: CredentialPurpose) -> Sha256Sum {
        let mut hash = Sha256::new();
        hash.update(purpose.as_str().as_bytes());
        hash.update([0]);
        hash.update(self.0.as_bytes());
        Sha256Sum::from(hash)
    }
}

/// Persisted credential metadata; never contains the secret token.
#[derive(Debug, PartialEq)]
pub struct EmailCredential {
    /// Purpose-bound token digest.
    pub digest: Sha256Sum,
    /// Time of issuance.
    pub issued_at: OffsetDateTime,
    /// Exclusive expiration time.
    pub expires_at: OffsetDateTime,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_generation_and_purpose_isolation() {
        let token = EmailToken::generate();
        assert_eq!(43, token.as_str().len());
        assert_ne!(token, EmailToken::generate());
        assert_ne!(
            token.digest(CredentialPurpose::Activation),
            token.digest(CredentialPurpose::Recovery)
        );
        assert!(!format!("{token:?}").contains(token.as_str()));
        assert_eq!(
            token,
            serde_json::from_str::<EmailToken>(&serde_json::to_string(&token).unwrap()).unwrap()
        );
    }
}
