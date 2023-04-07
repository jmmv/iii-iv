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
use iii_iv_core::model::Username;
use time::OffsetDateTime;

/// Represents a user session.
#[cfg_attr(test, derive(Clone, Debug, PartialEq))]
pub struct Session {
    /// The access token for the session, which acts as its identifier.
    access_token: AccessToken,

    /// The username for this session.
    username: Username,

    /// Timestamp to represent when the session was initiated.
    login_time: OffsetDateTime,
}

impl Session {
    /// Creates a new session from its parts.
    pub(crate) fn new(
        access_token: AccessToken,
        username: Username,
        login_time: OffsetDateTime,
    ) -> Self {
        Self { access_token, username, login_time }
    }

    /// Returns the session's access token.
    pub fn access_token(&self) -> &AccessToken {
        &self.access_token
    }

    /// Returns the session's username.
    pub fn username(&self) -> &Username {
        &self.username
    }

    /// Returns the session's login time.
    pub fn login_time(&self) -> OffsetDateTime {
        self.login_time
    }

    /// Consumes the session and extracts its access token.
    pub(crate) fn take_access_token(self) -> AccessToken {
        self.access_token
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iii_iv_core::clocks::testutils::utc_datetime;

    #[test]
    fn test_session() {
        let token = AccessToken::generate();
        let username = Username::new("foo").unwrap();
        let login_time = utc_datetime(2022, 5, 17, 6, 46, 53);
        let session = Session::new(token.clone(), username.clone(), login_time);
        assert_eq!(&token, session.access_token());
        assert_eq!(&username, session.username());
        assert_eq!(login_time, session.login_time());
        assert_eq!(token, session.take_access_token());
    }
}
