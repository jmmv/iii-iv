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

//! The `LoginFailures` data type.

use time::OffsetDateTime;

/// Persisted history of verified login rejections for one account.
#[derive(Debug, PartialEq)]
pub(crate) struct LoginFailures {
    /// Number of verified rejections since the most recent reset.
    pub(crate) count: u32,

    /// Time of the most recent verified rejection.
    pub(crate) last_failure: OffsetDateTime,

    /// Exclusive end of the current lock, if any.
    pub(crate) blocked_until: Option<OffsetDateTime>,
}
