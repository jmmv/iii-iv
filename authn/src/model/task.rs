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

//! Authentication background task definitions.
//!
//! These types represent persisted tasks in the database.  Clear obsolete tasks when deploying
//! incompatible changes.

use crate::model::EmailToken;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A background task owned by the authentication service.
#[derive(Deserialize, Serialize)]
#[cfg_attr(any(test, feature = "testutils"), derive(Debug, Eq, PartialEq))]
pub enum AuthnTask {
    /// Sends the activation email for a newly-created account.
    SendActivationEmail {
        /// Activation code that was assigned to the account.
        activation_code: EmailToken,

        /// Account that needs to be activated.
        user_id: Uuid,
    },
}
