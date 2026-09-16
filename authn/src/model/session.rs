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

//! The `Session` data type.

use crate::model::AccessToken;
use time::OffsetDateTime;
use uuid::Uuid;

/// Represents a user session.
#[cfg_attr(test, derive(Clone, Debug, PartialEq))]
pub struct Session {
    /// The access token for the session, which acts as its identifier.
    pub access_token: AccessToken,

    /// The user that owns this session.
    pub user_id: Uuid,

    /// Timestamp to represent when the session was initiated.
    pub login_time: OffsetDateTime,
}

impl Session {
    /// Creates a new session from its parts.
    pub(crate) fn new(
        access_token: AccessToken,
        user_id: Uuid,
        login_time: OffsetDateTime,
    ) -> Self {
        Self { access_token, user_id, login_time }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn test_session() {
        let token = AccessToken::generate();
        let user_id = Uuid::new_v4();
        let login_time = datetime!(2022-05-17 06:46:53 UTC);
        let session = Session::new(token.clone(), user_id, login_time);
        assert_eq!(&token, &session.access_token);
        assert_eq!(user_id, session.user_id);
        assert_eq!(login_time, session.login_time);
        assert_eq!(token, session.access_token);
    }
}
