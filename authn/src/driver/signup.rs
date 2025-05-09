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

//! Extends the driver with the `signup` method.

use crate::db;
use crate::driver::AuthnDriver;
use crate::driver::email::send_activation_code;
use crate::model::Password;
use iii_iv_core::db::DbError;
use iii_iv_core::driver::{DriverError, DriverResult};
use iii_iv_core::model::{EmailAddress, Username};

/// Verifies that a password is sufficiently complex.
// TODO(jmmv): This should be hidden via a trait and the user of this crate should be able to
// choose or supply their own validation rules.
fn password_validator(s: &str) -> Option<&'static str> {
    if s.len() < 8 {
        return Some("Too short");
    }

    let mut alphabetic = false;
    let mut numeric = false;
    for ch in s.chars() {
        if ch.is_alphabetic() {
            alphabetic = true;
        }
        if ch.is_numeric() {
            numeric = true;
        }
    }
    if !alphabetic || !numeric {
        return Some("Must contain letters and numbers");
    }

    None
}

impl AuthnDriver {
    /// Creates a new account for a user.
    pub(crate) async fn signup(
        self,
        username: Username,
        password: Password,
        email: EmailAddress,
    ) -> DriverResult<()> {
        let mut tx = self.db.begin().await?;

        let password = password.validate_and_hash(password_validator)?;

        let user = match db::create_user(tx.ex(), username, Some(password), email).await {
            Ok(user) => user,
            Err(DbError::AlreadyExists) => {
                return Err(DriverError::AlreadyExists(
                    "Username or email address are already registered".to_owned(),
                ));
            }
            Err(e) => return Err(e.into()),
        };

        let activation_code = rand::random::<u64>();
        let user = db::set_user_activation_code(tx.ex(), user, Some(activation_code)).await?;

        // TODO(jmmv): This should leverage the queue somehow, but we need to figure out how that
        // can be done while also supporting service-specific tasks.
        send_activation_code(
            self.mailer.as_ref(),
            &self.activation_template,
            &self.base_urls,
            user.username(),
            user.email(),
            activation_code,
        )
        .await?;

        tx.commit().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::AuthnOptions;
    use crate::driver::testutils::*;

    #[tokio::test]
    async fn test_signup_ok() {
        let context = TestContext::setup(AuthnOptions::default()).await;

        let username = Username::from("hello");
        let password = Password::from("sufficiently0complex");
        let email = EmailAddress::from("foo@example.com");

        assert_eq!(
            DbError::NotFound,
            db::get_user_by_username(&mut context.ex().await, username.clone()).await.unwrap_err()
        );

        context.driver().signup(username.clone(), password, email).await.unwrap();

        let user =
            db::get_user_by_username(&mut context.ex().await, username.clone()).await.unwrap();
        assert!(user.activation_code().is_some());
        assert_eq!(
            user.activation_code(),
            context.get_latest_activation_code(user.email(), &username).await
        );
    }

    #[tokio::test]
    async fn test_signup_username_already_exists() {
        let context = TestContext::setup(AuthnOptions::default()).await;

        let username = Username::from("hello");
        let email = EmailAddress::from("other@example.com");

        db::create_user(&mut context.ex().await, username.clone(), None, email.clone())
            .await
            .unwrap();

        match context
            .driver()
            .signup(username.clone(), Password::from("the1password"), email.clone())
            .await
        {
            Err(DriverError::AlreadyExists(msg)) => assert!(msg.contains("already registered")),
            e => panic!("{:?}", e),
        }

        assert!(context.get_latest_activation_code(&email, &username).await.is_none());
    }

    #[tokio::test]
    async fn test_signup_email_already_exists() {
        let context = TestContext::setup(AuthnOptions::default()).await;

        let email = EmailAddress::from("foo@example.com");

        db::create_user(&mut context.ex().await, Username::from("some"), None, email.clone())
            .await
            .unwrap();

        match context
            .driver()
            .signup(Username::from("other"), Password::from("the1password"), email.clone())
            .await
        {
            Err(DriverError::AlreadyExists(msg)) => assert!(msg.contains("already registered")),
            e => panic!("{:?}", e),
        }

        assert!(context.get_latest_activation_code(&email, &Username::from("x")).await.is_none());
    }

    #[tokio::test]
    async fn test_signup_weak_password() {
        let context = TestContext::setup(AuthnOptions::default()).await;

        let username = Username::from("hello");
        let email = EmailAddress::from("other@example.com");

        for (password, error) in [
            ("a", "Too short"),
            ("abcdefg", "Too short"),
            ("long enough", "letters and numbers"),
            ("1234567890", "letters and numbers"),
        ] {
            match context
                .driver()
                .signup(username.clone(), Password::new(password).unwrap(), email.clone())
                .await
            {
                Err(DriverError::InvalidInput(msg)) => {
                    assert!(msg.contains("Weak password"));
                    assert!(msg.contains(error));
                }
                e => panic!("{:?}", e),
            }

            assert!(context.get_latest_activation_code(&email, &username).await.is_none());
        }
    }
}
