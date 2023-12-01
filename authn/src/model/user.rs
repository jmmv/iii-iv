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
    username: Username,

    /// Hashed password.  None if the user is not allowed to log in.
    password: Option<HashedPassword>,

    /// Email of the user.
    email: EmailAddress,

    /// Token required to activate the user if not active yet.
    activation_code: Option<u64>,

    /// Time of last login of the user.  None if the user has never logged in.
    last_login: Option<OffsetDateTime>,
}

impl User {
    /// Creates a new user with the given fields.
    pub(crate) fn new(username: Username, email: EmailAddress) -> Self {
        Self { username, password: None, email, activation_code: None, last_login: None }
    }

    /// Modifies a user to set or clear its activation code.
    pub(crate) fn with_activation_code(mut self, code: Option<u64>) -> Self {
        self.activation_code = code;
        self
    }

    /// Modifies a user to record their most recent login time.
    pub(crate) fn with_last_login(mut self, last_login: OffsetDateTime) -> Self {
        self.last_login = Some(last_login);
        self
    }

    /// Modifies a user to add a password.
    pub(crate) fn with_password(mut self, password: HashedPassword) -> Self {
        self.password = Some(password);
        self
    }

    /// Gets the user's username.
    pub fn username(&self) -> &Username {
        &self.username
    }

    /// Gets the user's password as a hash.
    pub fn password(&self) -> Option<&HashedPassword> {
        self.password.as_ref()
    }

    /// Gets the user's email address.
    pub fn email(&self) -> &EmailAddress {
        &self.email
    }

    /// Gets the user's activation code.
    pub fn activation_code(&self) -> Option<u64> {
        self.activation_code
    }

    /// Gets the user's last login timestamp, or `None` if the user has never logged in yet.
    pub fn last_login(&self) -> Option<OffsetDateTime> {
        self.last_login
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn test_user_getters() {
        let user = User::new(Username::from("foo"), EmailAddress::from("a@example.com"));
        assert_eq!(&Username::from("foo"), user.username());
        assert!(user.password().is_none());
        assert_eq!(&EmailAddress::from("a@example.com"), user.email());
        assert!(user.activation_code().is_none());
        assert!(user.last_login().is_none());

        let user = user
            .with_activation_code(Some(123))
            .with_last_login(datetime!(2022-04-02 05:38:00 UTC))
            .with_password(HashedPassword::new("password-hash"));
        assert_eq!(Some(123), user.activation_code());
        assert_eq!(Some(&HashedPassword::new("password-hash")), user.password());
        assert_eq!(Some(datetime!(2022-04-02 05:38:00 UTC)), user.last_login());
    }
}
