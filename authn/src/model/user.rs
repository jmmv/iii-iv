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

use crate::model::{CouponName, HashedPassword};
use iii_iv_core::model::{EmailAddress, Username};
use time::OffsetDateTime;
use uuid::Uuid;

/// Representation of a user's information.
#[derive(Debug, PartialEq)]
pub struct User {
    /// Stable identifier for the user.
    pub id: Uuid,

    /// Name of the user, if the service uses usernames.
    pub username: Option<Username>,

    /// Hashed password.  None if the user is not allowed to log in.
    pub password: Option<HashedPassword>,

    /// Email of the user.
    pub email: EmailAddress,

    /// Coupon used to sign up this user, if any.
    pub coupon: Option<CouponName>,

    /// Token required to activate the user if not active yet.
    pub activation_code: Option<u64>,

    /// Time of last login of the user.  None if the user has never logged in.
    pub last_login: Option<OffsetDateTime>,
}

impl User {
    /// Creates a new user with the given fields.
    pub fn new(id: Uuid, username: Option<Username>, email: EmailAddress) -> Self {
        Self {
            id,
            username,
            password: None,
            email,
            coupon: None,
            activation_code: None,
            last_login: None,
        }
    }

    /// Modifies a user to set or clear its activation code.
    pub fn with_activation_code(mut self, code: Option<u64>) -> Self {
        self.activation_code = code;
        self
    }

    /// Modifies a user to record the coupon used during signup.
    pub fn with_coupon(mut self, coupon: CouponName) -> Self {
        self.coupon = Some(coupon);
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
    use crate::model::{coupon_name, hashed_password};
    use iii_iv_core::model::{email_address, username};
    use time::macros::datetime;

    #[test]
    fn test_user_fields() {
        let id = Uuid::new_v4();
        let user = User::new(id, Some(username!("foo")), email_address!("a@example.com"));
        assert_eq!(id, user.id);
        assert_eq!(Some(&username!("foo")), user.username.as_ref());
        assert!(user.password.is_none());
        assert_eq!(&email_address!("a@example.com"), &user.email);
        assert!(user.coupon.is_none());
        assert!(user.activation_code.is_none());
        assert!(user.last_login.is_none());

        let user = user
            .with_activation_code(Some(123))
            .with_coupon(coupon_name!("BETA100"))
            .with_last_login(datetime!(2022-04-02 05:38:00 UTC))
            .with_password(hashed_password!("password-hash"));
        assert_eq!(Some(123), user.activation_code);
        assert_eq!(Some(&coupon_name!("BETA100")), user.coupon.as_ref());
        assert_eq!(Some(&hashed_password!("password-hash")), user.password.as_ref());
        assert_eq!(Some(datetime!(2022-04-02 05:38:00 UTC)), user.last_login);
    }
}
