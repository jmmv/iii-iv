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

//! Pending account activation.

use crate::model::{CredentialPurpose, EmailToken};
use iii_iv_core::model::Sha256Sum;
use std::time::Duration;
use time::OffsetDateTime;

/// A pending account activation and its validity interval.
#[derive(Debug, PartialEq)]
pub struct ActivationState {
    /// Purpose-bound digest of the activation token.
    pub code: Sha256Sum,

    /// Time at which the code was issued.
    pub issued_at: OffsetDateTime,

    /// Exclusive end of the code's validity.
    pub expires_at: OffsetDateTime,
}

impl ActivationState {
    /// Creates a code valid for the configured maximum age after issuance.
    pub fn new(code: impl Into<EmailToken>, issued_at: OffsetDateTime, max_age: Duration) -> Self {
        Self {
            code: code.into().digest(CredentialPurpose::Activation),
            issued_at,
            expires_at: issued_at + max_age,
        }
    }
}
