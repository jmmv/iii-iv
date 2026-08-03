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

//! The `User` data type.

use crate::model::HashedPassword;
use iii_iv_core::model::{EmailAddress, Username};
use time::OffsetDateTime;

/// Representation of a user's information.
#[derive(Debug, PartialEq)]
pub struct User {
    /// Name of the user.
    pub username: Username,

    /// Hashed password.  None if the user is not allowed to log in.
    pub password: Option<HashedPassword>,

    /// Email of the user.
    pub email: EmailAddress,

    /// Token required to activate the user if not active yet.
    pub activation_code: Option<u64>,

    /// Time of last login of the user.  None if the user has never logged in.
    pub last_login: Option<OffsetDateTime>,
}

impl User {
    /// Creates a new user with the given fields.
    pub fn new(username: Username, email: EmailAddress) -> Self {
        Self { username, password: None, email, activation_code: None, last_login: None }
    }

    /// Modifies a user to set or clear its activation code.
    pub fn with_activation_code(mut self, code: Option<u64>) -> Self {
        self.activation_code = code;
        self
    }

    /// Modifies a user to record their most recent login time.
    pub fn with_last_login(mut self, last_login: OffsetDateTime) -> Self {
        self.last_login = Some(last_login);
        self
    }

    /// Modifies a user to add a password.
    pub fn with_password(mut self, password: HashedPassword) -> Self {
        self.password = Some(password);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::hashed_password;
    use iii_iv_core::model::{email_address, username};
    use time::macros::datetime;

    #[test]
    fn test_user_fields() {
        let user = User::new(username!("foo"), email_address!("a@example.com"));
        assert_eq!(&username!("foo"), &user.username);
        assert!(user.password.is_none());
        assert_eq!(&email_address!("a@example.com"), &user.email);
        assert!(user.activation_code.is_none());
        assert!(user.last_login.is_none());

        let user = user
            .with_activation_code(Some(123))
            .with_last_login(datetime!(2022-04-02 05:38:00 UTC))
            .with_password(hashed_password!("password-hash"));
        assert_eq!(Some(123), user.activation_code);
        assert_eq!(Some(&hashed_password!("password-hash")), user.password.as_ref());
        assert_eq!(Some(datetime!(2022-04-02 05:38:00 UTC)), user.last_login);
    }
}
