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
//! These types represent persisted tasks in the database, so changes must remain wire-compatible
//! with tasks that may still be runnable.

use iii_iv_core::model::Username;
use serde::{Deserialize, Serialize};

/// A background task owned by the authentication service.
#[derive(Deserialize, Serialize)]
#[cfg_attr(any(test, feature = "testutils"), derive(Debug, Eq, PartialEq))]
pub enum AuthnTask {
    /// Sends the activation email for a newly-created account.
    SendActivationEmail {
        /// Activation code that was assigned to the account.
        activation_code: u64,

        /// Account that needs to be activated.
        username: Username,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use iii_iv_core::model::username;

    #[test]
    fn test_serde() {
        let task = AuthnTask::SendActivationEmail {
            activation_code: 1234,
            username: username!("some-user"),
        };
        let json = serde_json::to_string(&task).unwrap();
        assert_eq!(
            r#"{"SendActivationEmail":{"activation_code":1234,"username":"some-user"}}"#,
            json
        );
        assert_eq!(task, serde_json::from_str(&json).unwrap());
    }
}
