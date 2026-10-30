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

//! Persistent authentication failure history.

use time::OffsetDateTime;

/// Authentication operation with independent failure history.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum FailureOperation {
    /// Password login.
    Login,
}

impl FailureOperation {
    /// Returns the stable database key for this operation.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Login => "login",
        }
    }
}

/// Persisted history of rejections for one account and operation.
#[derive(Debug, PartialEq)]
pub(crate) struct FailureHistory {
    /// Number of verified rejections since the most recent reset.
    pub(crate) count: u32,

    /// Time of the most recent verified rejection.
    pub(crate) last_failure: OffsetDateTime,

    /// Exclusive end of the current lock, if any.
    pub(crate) blocked_until: Option<OffsetDateTime>,
}

impl FailureHistory {
    /// Tests whether the persisted block is still active.
    pub(crate) fn is_blocked(&self, now: OffsetDateTime) -> bool {
        self.blocked_until.is_some_and(|until| now < until)
    }
}
