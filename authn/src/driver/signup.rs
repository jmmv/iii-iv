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
use crate::driver::{AuthnDriver, AuthnHooks};
use crate::model::{AuthnTask, CouponName, Password};
use iii_iv_core::db::DbError;
use iii_iv_core::driver::{DriverError, DriverResult};
use iii_iv_core::model::{EmailAddress, Username};

/// Verifies that a password is sufficiently complex.
// TODO(jmmv): This should be hidden via a trait and the user of this crate should be able to
// choose or supply their own validation rules.
pub(crate) fn password_validator(s: &str) -> Option<&'static str> {
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

impl<H: AuthnHooks> AuthnDriver<H> {
    /// Creates a new account for a user.
    pub(crate) async fn signup(
        self,
        username: Option<Username>,
        password: Password,
        email: EmailAddress,
        coupon: Option<CouponName>,
        input: H::SignupInput,
    ) -> DriverResult<()> {
        if !self.opts.open_signups && coupon.is_none() {
            return Err(DriverError::InvalidInput(
                "Signups are not open at this moment".to_owned(),
            ));
        }

        let mut tx = self.db.begin().await?;
        let now = self.clock.now_utc();

        if let Some(coupon) = coupon.as_ref() {
            let details = match db::get_coupon(tx.ex(), coupon).await {
                Ok(details) => details,
                Err(DbError::NotFound) => {
                    return Err(DriverError::InvalidInput("Invalid coupon".to_owned()));
                }
                Err(error) => return Err(error.into()),
            };
            if !details.is_valid(now) {
                return Err(DriverError::InvalidInput("Invalid coupon".to_owned()));
            }
            if let Err(error) = db::redeem_coupon(tx.ex(), coupon).await {
                return match error {
                    DbError::NotFound => {
                        Err(DriverError::InvalidInput("Invalid coupon".to_owned()))
                    }
                    error => Err(error.into()),
                };
            }
        }

        match (self.usernames, username.as_ref()) {
            (true, None) => {
                return Err(DriverError::InvalidInput("Username is required".to_owned()));
            }
            (false, Some(_)) => {
                return Err(DriverError::InvalidInput("Username is not supported".to_owned()));
            }
            _ => {}
        }

        let password = password.validate_and_hash(password_validator)?;

        let user = match db::create_user(tx.ex(), username, Some(password), email, coupon).await {
            Ok(user) => user,
            Err(DbError::AlreadyExists) => {
                return Err(DriverError::AlreadyExists(
                    "Username or email address is already registered".to_owned(),
                ));
            }
            Err(e) => return Err(e.into()),
        };

        let activation_code = rand::random::<u64>();
        let user = db::set_user_activation_code(tx.ex(), user, Some(activation_code)).await?;

        self.hooks.signup_hook(&mut tx, now, &user, input).await?;

        self.task_enqueuer
            .enqueue(tx.ex(), AuthnTask::SendActivationEmail { activation_code, user_id: user.id })
            .await?;

        tx.commit().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::testutils::*;
    use crate::driver::{AuthnOptions, NO_EXTENSIONS};
    use crate::model::{Coupon, coupon_name, password};
    use iii_iv_core::clocks::testutils::SettableClock;
    use iii_iv_core::db::DbError;
    use iii_iv_core::driver::DriverError;
    use iii_iv_core::model::{email_address, username};
    use std::sync::Arc;
    use time::macros::datetime;

    #[tokio::test]
    async fn test_signup_ok() {
        let context = TestContext::setup(AuthnOptions::default()).await;

        let username = username!("hello");
        let password = password!("sufficiently0complex");
        let email = email_address!("foo@example.com");

        assert_eq!(
            DbError::NotFound,
            db::get_user_by_username(&mut context.ex().await, username.clone()).await.unwrap_err()
        );

        context
            .driver()
            .signup(Some(username.clone()), password, email, None, NO_EXTENSIONS)
            .await
            .unwrap();

        let user =
            db::get_user_by_username(&mut context.ex().await, username.clone()).await.unwrap();
        assert!(user.activation_code.is_some());
        assert_eq!(
            user.activation_code,
            context.get_latest_activation_code(&user.email, Some(user.id)).await
        );
    }

    #[tokio::test]
    async fn test_signup_closed() {
        let opts = AuthnOptions { open_signups: false, ..Default::default() };
        let context = TestContext::setup(opts).await;

        let username = username!("hello");
        let email = email_address!("foo@example.com");
        assert_eq!(
            Err(DriverError::InvalidInput("Signups are not open at this moment".to_owned())),
            context
                .driver()
                .signup(
                    Some(username.clone()),
                    password!("sufficiently0complex"),
                    email.clone(),
                    None,
                    NO_EXTENSIONS,
                )
                .await
        );

        assert_eq!(
            DbError::NotFound,
            db::get_user_by_username(&mut context.ex().await, username).await.unwrap_err()
        );
        assert!(context.get_latest_activation_code(&email, None).await.is_none());
    }

    #[tokio::test]
    async fn test_signup_closed_with_coupon() {
        let opts = AuthnOptions { open_signups: false, ..Default::default() };
        let context = TestContext::setup(opts).await;
        let coupon =
            Coupon::new(coupon_name!("BETA100"), context.now_delta(-1), context.now_delta(1), 1)
                .unwrap();
        db::create_coupon(&mut context.ex().await, &coupon).await.unwrap();

        let username = username!("hello");
        context
            .driver()
            .signup(
                Some(username.clone()),
                password!("sufficiently0complex"),
                email_address!("foo@example.com"),
                Some(coupon.name.clone()),
                NO_EXTENSIONS,
            )
            .await
            .unwrap();

        let user = db::get_user_by_username(&mut context.ex().await, username).await.unwrap();
        assert_eq!(Some(&coupon.name), user.coupon.as_ref());
        assert_eq!(1, db::get_coupon(&mut context.ex().await, &coupon.name).await.unwrap().usages);

        assert_eq!(
            Err(DriverError::InvalidInput("Invalid coupon".to_owned())),
            context
                .driver()
                .signup(
                    Some(username!("other")),
                    password!("sufficiently0complex"),
                    email_address!("other@example.com"),
                    Some(coupon.name.clone()),
                    NO_EXTENSIONS,
                )
                .await
        );
    }

    #[tokio::test]
    async fn test_signup_invalid_coupon() {
        let context = TestContext::setup(AuthnOptions::default()).await;

        assert_eq!(
            Err(DriverError::InvalidInput("Invalid coupon".to_owned())),
            context
                .driver()
                .signup(
                    Some(username!("hello")),
                    password!("sufficiently0complex"),
                    email_address!("foo@example.com"),
                    Some(coupon_name!("UNKNOWN")),
                    NO_EXTENSIONS,
                )
                .await
        );
    }

    #[tokio::test]
    async fn test_signup_coupon_validity_window() {
        let context = TestContext::setup(AuthnOptions::default()).await;

        for coupon in [
            Coupon::new(coupon_name!("NOT-YET"), context.now_delta(1), context.now_delta(2), 1)
                .unwrap(),
            Coupon::new(coupon_name!("ENDED"), context.now_delta(-1), context.now_delta(0), 1)
                .unwrap(),
        ] {
            db::create_coupon(&mut context.ex().await, &coupon).await.unwrap();
            assert_eq!(
                Err(DriverError::InvalidInput("Invalid coupon".to_owned())),
                context
                    .driver()
                    .signup(
                        Some(username!("hello")),
                        password!("sufficiently0complex"),
                        email_address!("foo@example.com"),
                        Some(coupon.name.clone()),
                        NO_EXTENSIONS,
                    )
                    .await
            );
            assert_eq!(
                0,
                db::get_coupon(&mut context.ex().await, &coupon.name).await.unwrap().usages
            );
        }

        let coupon =
            Coupon::new(coupon_name!("STARTS-NOW"), context.now_delta(0), context.now_delta(1), 1)
                .unwrap();
        db::create_coupon(&mut context.ex().await, &coupon).await.unwrap();
        context
            .driver()
            .signup(
                Some(username!("hello")),
                password!("sufficiently0complex"),
                email_address!("foo@example.com"),
                Some(coupon.name),
                NO_EXTENSIONS,
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_signup_failure_restores_coupon_usage() {
        let context = TestContext::setup(AuthnOptions::default()).await;
        let coupon =
            Coupon::new(coupon_name!("BETA100"), context.now_delta(-1), context.now_delta(1), 1)
                .unwrap();
        db::create_coupon(&mut context.ex().await, &coupon).await.unwrap();
        db::create_user(
            &mut context.ex().await,
            Some(username!("hello")),
            None,
            email_address!("existing@example.com"),
            None,
        )
        .await
        .unwrap();

        assert!(
            context
                .driver()
                .signup(
                    Some(username!("hello")),
                    password!("sufficiently0complex"),
                    email_address!("new@example.com"),
                    Some(coupon.name.clone()),
                    NO_EXTENSIONS,
                )
                .await
                .is_err()
        );
        assert_eq!(0, db::get_coupon(&mut context.ex().await, &coupon.name).await.unwrap().usages);
    }

    #[tokio::test]
    async fn test_signup_without_username_ok() {
        let context = TestContext::setup_without_usernames(AuthnOptions::default()).await;
        let email = email_address!("foo@example.com");

        context
            .driver()
            .signup(None, password!("sufficiently0complex"), email.clone(), None, NO_EXTENSIONS)
            .await
            .unwrap();

        let user = db::get_user_by_email(&mut context.ex().await, email.clone()).await.unwrap();
        assert!(user.username.is_none());
        assert!(user.activation_code.is_some());
        assert_eq!(
            user.activation_code,
            context.get_latest_activation_code(&email, Some(user.id)).await
        );
    }

    #[tokio::test]
    async fn test_signup_username_mode_mismatch() {
        let context = TestContext::setup(AuthnOptions::default()).await;
        let result = context
            .driver()
            .signup(
                None,
                password!("sufficiently0complex"),
                email_address!("one@example.com"),
                None,
                NO_EXTENSIONS,
            )
            .await;
        assert!(matches!(result, Err(DriverError::InvalidInput(msg)) if msg.contains("required")));

        let context = TestContext::setup_without_usernames(AuthnOptions::default()).await;
        let result = context
            .driver()
            .signup(
                Some(username!("hello")),
                password!("sufficiently0complex"),
                email_address!("two@example.com"),
                None,
                NO_EXTENSIONS,
            )
            .await;
        assert!(
            matches!(result, Err(DriverError::InvalidInput(msg)) if msg.contains("not supported"))
        );
    }

    #[tokio::test]
    async fn test_signup_username_already_exists() {
        let context = TestContext::setup(AuthnOptions::default()).await;

        let username = username!("hello");
        let email = email_address!("other@example.com");

        db::create_user(&mut context.ex().await, Some(username.clone()), None, email.clone(), None)
            .await
            .unwrap();

        match context
            .driver()
            .signup(
                Some(username.clone()),
                password!("the1password"),
                email.clone(),
                None,
                NO_EXTENSIONS,
            )
            .await
        {
            Err(DriverError::AlreadyExists(msg)) => assert!(msg.contains("already registered")),
            e => panic!("{:?}", e),
        }

        assert!(context.get_latest_activation_code(&email, None).await.is_none());
    }

    #[tokio::test]
    async fn test_signup_email_already_exists() {
        let context = TestContext::setup(AuthnOptions::default()).await;

        let email = email_address!("foo@example.com");

        db::create_user(
            &mut context.ex().await,
            Some(username!("some")),
            None,
            email.clone(),
            None,
        )
        .await
        .unwrap();

        match context
            .driver()
            .signup(
                Some(username!("other")),
                password!("the1password"),
                email.clone(),
                None,
                NO_EXTENSIONS,
            )
            .await
        {
            Err(DriverError::AlreadyExists(msg)) => assert!(msg.contains("already registered")),
            e => panic!("{:?}", e),
        }

        assert!(context.get_latest_activation_code(&email, None).await.is_none());
    }

    #[tokio::test]
    async fn test_signup_weak_password() {
        let context = TestContext::setup(AuthnOptions::default()).await;

        let username = username!("hello");
        let email = email_address!("other@example.com");

        for (password, error) in [
            ("a", "Too short"),
            ("abcdefg", "Too short"),
            ("long enough", "letters and numbers"),
            ("1234567890", "letters and numbers"),
        ] {
            match context
                .driver()
                .signup(
                    Some(username.clone()),
                    Password::new(password).unwrap(),
                    email.clone(),
                    None,
                    NO_EXTENSIONS,
                )
                .await
            {
                Err(DriverError::InvalidInput(msg)) => {
                    assert!(msg.contains("Weak password"));
                    assert!(msg.contains(error));
                }
                e => panic!("{:?}", e),
            }

            assert!(context.get_latest_activation_code(&email, None).await.is_none());
        }
    }

    #[tokio::test]
    async fn test_signup_hook_failure_aborts_signup() {
        let db = Arc::from(iii_iv_core::db::sqlite::testutils::setup().await);
        let clock = Arc::from(SettableClock::new(datetime!(2023-12-01 05:50:00 UTC)));
        let context = TestContext::setup_with_hooks(
            AuthnOptions::default(),
            db.clone(),
            clock,
            "the-realm",
            true,
            FailingSignupHook,
        )
        .await;

        let username = username!("hello");
        let email = email_address!("foo@example.com");

        assert_eq!(
            DbError::NotFound,
            db::get_user_by_username(&mut context.ex().await, username.clone()).await.unwrap_err()
        );

        match context
            .driver()
            .signup(
                Some(username.clone()),
                password!("sufficiently0complex"),
                email.clone(),
                None,
                NO_EXTENSIONS,
            )
            .await
        {
            Err(DriverError::BackendError(msg)) => assert!(msg.contains("hook-failure-test")),
            e => panic!("{:?}", e),
        }

        assert_eq!(
            DbError::NotFound,
            db::get_user_by_username(&mut context.ex().await, username.clone()).await.unwrap_err()
        );

        assert!(context.get_latest_activation_code(&email, None).await.is_none());
    }

    #[tokio::test]
    async fn test_signup_hook_failure_restores_coupon_usage() {
        let db = Arc::from(iii_iv_core::db::sqlite::testutils::setup().await);
        let clock = Arc::from(SettableClock::new(datetime!(2023-12-01 05:50:00 UTC)));
        let context = TestContext::setup_with_hooks(
            AuthnOptions::default(),
            db,
            clock,
            "the-realm",
            true,
            FailingSignupHook,
        )
        .await;
        let coupon =
            Coupon::new(coupon_name!("BETA100"), context.now_delta(-1), context.now_delta(1), 1)
                .unwrap();
        db::create_coupon(&mut context.ex().await, &coupon).await.unwrap();

        assert!(
            context
                .driver()
                .signup(
                    Some(username!("hello")),
                    password!("sufficiently0complex"),
                    email_address!("foo@example.com"),
                    Some(coupon.name.clone()),
                    NO_EXTENSIONS,
                )
                .await
                .is_err()
        );
        assert_eq!(0, db::get_coupon(&mut context.ex().await, &coupon.name).await.unwrap().usages);
    }
}
