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

//! Extends the driver with the `change_password` method.

use crate::db;
use crate::driver::signup::password_validator;
use crate::driver::{AuthnDriver, AuthnHooks};
use crate::model::{AccessToken, Password};
use iii_iv_core::db::DbError;
use iii_iv_core::driver::{DriverError, DriverResult};

impl<H: AuthnHooks> AuthnDriver<H> {
    /// Changes the password for a user after verifying the old password.
    ///
    /// Invalidates all sessions for the user after successful password change.
    pub(crate) async fn change_password(
        self,
        token: AccessToken,
        old_password: Password,
        new_password: Password,
    ) -> DriverResult<()> {
        let permit = self.acquire_password_hash_capacity()?;
        let mut tx = self.db.begin().await?;
        let now = self.clock.now_utc();

        let session = self.get_session_uncached(&mut tx, now, token).await?;

        let old_hash = match session.user.password.as_ref() {
            Some(hash) => hash,
            None => {
                return Err(DriverError::Unauthorized(
                    "Password not set; cannot change".to_owned(),
                ));
            }
        };

        let (verified, permit) = self.verify_password(old_password, old_hash, permit).await?;
        if !verified {
            return Err(DriverError::InvalidInput("Invalid password".to_owned()));
        }

        if session.user.activation_code.is_some() {
            return Err(DriverError::NotActivated);
        }

        let (new_password, permit) =
            self.hash_password(new_password, password_validator, permit).await?;
        drop(permit);
        match db::update_user_password(tx.ex(), session.user.id, old_hash, new_password).await {
            Ok(()) => {}
            Err(DbError::NotFound) => {
                return Err(DriverError::InvalidInput(
                    "Password changed during update; please try again".to_owned(),
                ));
            }
            Err(e) => return Err(e.into()),
        }

        db::delete_sessions_for_user(tx.ex(), session.user.id, now).await?;

        tx.commit().await?;

        let mut cache = self.sessions_cache.lock().await;
        cache.clear();

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::AuthnOptions;
    use crate::driver::NO_EXTENSIONS;
    use crate::driver::testutils::*;
    use crate::model::{Session, password};
    use iii_iv_core::clocks::Clock;
    use iii_iv_core::clocks::testutils::SettableClock;
    use iii_iv_core::db::Db;
    use iii_iv_core::model::{EmailAddress, username};
    use std::sync::Arc;
    use std::time::Duration;
    use time::macros::datetime;

    #[tokio::test]
    async fn test_change_password_ok() {
        let context = TestContext::setup(AuthnOptions::default()).await;
        let username = username!("test");

        let token = context.do_test_login(username.clone()).await;

        let old_password = password!("test0password");
        let new_password = password!("new1password");

        context
            .driver()
            .change_password(token, old_password.clone(), new_password.clone())
            .await
            .unwrap();

        context
            .driver()
            .login(username.as_str().to_owned(), new_password, Some(Duration::from_secs(100)))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_change_password_wrong_old_password() {
        let context = TestContext::setup(AuthnOptions::default()).await;
        let username = username!("test");

        let token = context.do_test_login(username.clone()).await;

        match context
            .driver()
            .change_password(token, password!("wrong0password"), password!("new1password"))
            .await
        {
            Err(DriverError::InvalidInput(msg)) => assert!(msg.contains("Invalid password")),
            e => panic!("{:?}", e),
        }
    }

    #[tokio::test]
    async fn test_change_password_not_activated() {
        let context = TestContext::setup(AuthnOptions::default()).await;
        let username = username!("test");

        let password = password!("old0password");
        let email = EmailAddress::new("test@example.com").unwrap();
        context
            .driver()
            .signup(Some(username.clone()), password.clone(), email.clone(), None, NO_EXTENSIONS)
            .await
            .unwrap();

        let token = {
            let mut tx = context.db().begin().await.unwrap();
            let user = db::get_user_by_username(tx.ex(), username.clone()).await.unwrap();
            let access_token = AccessToken::generate();
            let now = context.driver().now_utc();
            let session =
                Session::new(access_token.clone(), user.id, now, now + Duration::from_secs(3600));
            db::put_session(tx.ex(), &session).await.unwrap();
            db::update_user(tx.ex(), user.id, context.driver().now_utc()).await.unwrap();
            tx.commit().await.unwrap();
            access_token
        };

        match context
            .driver()
            .change_password(token, password.clone(), password!("new1password"))
            .await
        {
            Err(DriverError::NotActivated) => (),
            e => panic!("{:?}", e),
        }
    }

    #[tokio::test]
    async fn test_change_password_weak_new_password() {
        let context = TestContext::setup(AuthnOptions::default()).await;
        let username = username!("test");

        let token = context.do_test_login(username.clone()).await;

        let old_password = password!("test0password");
        for (new_password_str, error) in [
            ("a", "Too short"),
            ("abcdefg", "Too short"),
            ("long enough", "letters and numbers"),
            ("1234567890", "letters and numbers"),
        ] {
            match context
                .driver()
                .change_password(
                    token.clone(),
                    old_password.clone(),
                    Password::new(new_password_str).unwrap(),
                )
                .await
            {
                Err(DriverError::InvalidInput(msg)) => {
                    assert!(msg.contains("Weak password"));
                    assert!(msg.contains(error));
                }
                e => panic!("{:?}", e),
            }
        }
    }

    #[tokio::test]
    async fn test_change_password_invalidates_sessions() {
        let context = TestContext::setup(AuthnOptions::default()).await;
        let username = username!("test");

        let token1 = context.do_test_login(username.clone()).await;
        let (session2, _, NO_EXTENSIONS) = context
            .driver()
            .login(
                username.as_str().to_owned(),
                password!("test0password"),
                Some(Duration::from_secs(100)),
            )
            .await
            .unwrap();

        let old_password = password!("test0password");
        let new_password = password!("new1password");

        context
            .driver()
            .change_password(token1.clone(), old_password.clone(), new_password.clone())
            .await
            .unwrap();

        for token in [token1, session2.access_token] {
            match db::get_session(&mut context.ex().await, &token).await {
                Err(DbError::NotFound) => (),
                e => panic!("{:?}", e),
            }
        }
    }

    #[tokio::test]
    async fn test_change_password_rejects_expired_session() {
        let opts = AuthnOptions { session_max_age: Duration::from_secs(10), ..Default::default() };
        let context = TestContext::setup(opts).await;
        let username = username!("test");
        let original_token = context.do_test_login(username).await;
        let original_session =
            db::get_session(&mut context.ex().await, &original_token).await.unwrap();
        let token = AccessToken::generate();
        let session = Session::new(
            token.clone(),
            original_session.user_id,
            context.now_delta(-10),
            context.now_delta(10),
        );
        db::put_session(&mut context.ex().await, &session).await.unwrap();

        match context
            .driver()
            .change_password(token, password!("test0password"), password!("new1password"))
            .await
        {
            Err(DriverError::Unauthorized(msg)) => assert!(msg.contains("expired")),
            e => panic!("{:?}", e),
        }
    }

    #[tokio::test]
    async fn test_change_password_visible_across_drivers_by_default() {
        let db: Arc<dyn Db + Send + Sync> =
            Arc::from(iii_iv_core::db::sqlite::testutils::setup().await);
        let clock: Arc<dyn Clock + Send + Sync> =
            Arc::from(SettableClock::new(datetime!(2023-12-01 05:50:00 UTC)));
        let first = TestContext::setup_with(
            AuthnOptions::default(),
            db.clone(),
            clock.clone(),
            "the-realm",
            true,
        )
        .await;
        let second =
            TestContext::setup_with(AuthnOptions::default(), db, clock, "the-realm", true).await;
        let username = username!("test");
        let token1 = first.do_test_login(username.clone()).await;
        let (session2, _, NO_EXTENSIONS) = second
            .driver()
            .login(
                username.as_str().to_owned(),
                password!("test0password"),
                Some(Duration::from_secs(100)),
            )
            .await
            .unwrap();

        for token in [token1.clone(), session2.access_token.clone()] {
            let mut tx = second.db().begin().await.unwrap();
            second.driver().get_session(&mut tx, second.driver().now_utc(), token).await.unwrap();
            tx.commit().await.unwrap();
        }

        first
            .driver()
            .change_password(token1.clone(), password!("test0password"), password!("new1password"))
            .await
            .unwrap();

        for token in [token1, session2.access_token] {
            let mut tx = second.db().begin().await.unwrap();
            match second.driver().get_session(&mut tx, second.driver().now_utc(), token).await {
                Err(DriverError::Unauthorized(msg)) => assert!(msg.contains("Invalid session")),
                e => panic!("{:?}", e),
            }
        }
    }

    #[tokio::test]
    async fn test_change_password_delayed_across_drivers_with_cache() {
        let opts =
            AuthnOptions { sessions_cache_ttl: Duration::from_secs(60), ..Default::default() };
        let db: Arc<dyn Db + Send + Sync> =
            Arc::from(iii_iv_core::db::sqlite::testutils::setup().await);
        let clock: Arc<dyn Clock + Send + Sync> =
            Arc::from(SettableClock::new(datetime!(2023-12-01 05:50:00 UTC)));
        let first =
            TestContext::setup_with(opts.clone(), db.clone(), clock.clone(), "the-realm", true)
                .await;
        let second = TestContext::setup_with(opts, db, clock, "the-realm", true).await;
        let username = username!("test");
        let token1 = first.do_test_login(username.clone()).await;
        let (session2, _, NO_EXTENSIONS) = second
            .driver()
            .login(
                username.as_str().to_owned(),
                password!("test0password"),
                Some(Duration::from_secs(100)),
            )
            .await
            .unwrap();

        let mut tx = second.db().begin().await.unwrap();
        second
            .driver()
            .get_session(&mut tx, second.driver().now_utc(), token1.clone())
            .await
            .unwrap();
        tx.commit().await.unwrap();

        first
            .driver()
            .change_password(token1.clone(), password!("test0password"), password!("new1password"))
            .await
            .unwrap();

        for token in [token1, session2.access_token] {
            let mut tx = second.db().begin().await.unwrap();
            second.driver().get_session(&mut tx, second.driver().now_utc(), token).await.unwrap();
            tx.commit().await.unwrap();
        }
    }

    #[tokio::test]
    async fn test_change_password_rejects_future_session() {
        let opts = AuthnOptions { session_max_skew: Duration::from_secs(10), ..Default::default() };
        let context = TestContext::setup(opts).await;
        let username = username!("test");
        let original_token = context.do_test_login(username).await;
        let original_session =
            db::get_session(&mut context.ex().await, &original_token).await.unwrap();
        let token = AccessToken::generate();
        let session = Session::new(
            token.clone(),
            original_session.user_id,
            context.now_delta(11),
            context.now_delta(111),
        );
        db::put_session(&mut context.ex().await, &session).await.unwrap();

        match context
            .driver()
            .change_password(token, password!("test0password"), password!("new1password"))
            .await
        {
            Err(DriverError::Unauthorized(msg)) => assert!(msg.contains("expired")),
            e => panic!("{:?}", e),
        }
    }

    #[tokio::test]
    async fn test_change_password_rejects_logged_out_session() {
        let context = TestContext::setup(AuthnOptions::default()).await;
        let token = context.do_test_login(username!("test")).await;
        context.driver().logout(token.clone()).await.unwrap();

        match context
            .driver()
            .change_password(token, password!("test0password"), password!("new1password"))
            .await
        {
            Err(DriverError::Unauthorized(msg)) => assert!(msg.contains("Invalid session")),
            e => panic!("{:?}", e),
        }
    }

    #[tokio::test]
    async fn test_change_password_wrong_old_password_after_change() {
        let context = TestContext::setup(AuthnOptions::default()).await;
        let username = username!("test");

        let token = context.do_test_login(username.clone()).await;

        context
            .driver()
            .change_password(token.clone(), password!("test0password"), password!("new1password"))
            .await
            .unwrap();

        match context
            .driver()
            .change_password(token, password!("test0password"), password!("another1password"))
            .await
        {
            Err(DriverError::Unauthorized(msg)) => {
                assert!(msg.contains("Invalid session"))
            }
            e => panic!("{:?}", e),
        }
    }
}
