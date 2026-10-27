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

//! Extends the driver with the `login` method.

use crate::db;
use crate::driver::{AuthnDriver, AuthnHooks, CachedSession};
use crate::model::{AccessToken, HashedPassword, Password, Session, User};
use iii_iv_core::db::{DbError, Executor};
use iii_iv_core::driver::{DriverError, DriverResult};
use iii_iv_core::model::{EmailAddress, Username};
use std::sync::Arc;
use std::time::Duration;

/// Fixed bcrypt hash used to equalize work for login attempts without a real password hash.
static DUMMY_PASSWORD_HASH: HashedPassword =
    HashedPassword::from_static("$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy");

impl<H: AuthnHooks> AuthnDriver<H> {
    /// Resolves `login` to an account without exposing expected lookup failures.
    async fn find_login_user(
        &self,
        ex: &mut Executor,
        login: String,
    ) -> DriverResult<Option<User>> {
        let user_result = if self.usernames {
            let username = match Username::new(login) {
                Ok(username) => username,
                Err(_) => return Ok(None),
            };
            db::get_user_by_username(ex, username).await
        } else {
            let email = match EmailAddress::new(login) {
                Ok(email) => email,
                Err(_) => return Ok(None),
            };
            db::get_user_by_email(ex, email).await
        };

        match user_result {
            Ok(user) if user.password.is_some() => Ok(Some(user)),
            Ok(_) => Ok(None),
            Err(DbError::NotFound) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    /// Logs a user with their configured login identifier, `password`, and an optional session age.
    pub(crate) async fn login(
        self,
        login: String,
        password: Password,
        requested_max_age: Option<Duration>,
    ) -> DriverResult<(Session, Duration, H::LoginOutput)> {
        let permit = self.acquire_password_hash_capacity()?;
        let max_age =
            requested_max_age.unwrap_or(self.opts.session_max_age).min(self.opts.session_max_age);

        let user = {
            let mut ex = self.db.ex().await?;
            self.find_login_user(&mut ex, login).await?
        };
        let hash =
            user.as_ref().and_then(|user| user.password.as_ref()).unwrap_or(&DUMMY_PASSWORD_HASH);

        let (verified, permit) = self.verify_password(password, hash, permit).await?;
        drop(permit);

        let user = user.ok_or(DriverError::Unauthenticated)?;
        if !verified {
            return Err(DriverError::Unauthenticated);
        }

        let mut tx = self.db.begin().await?;
        let current_user = match db::get_user_by_id(tx.ex(), user.id).await {
            Ok(user) => user,
            Err(DbError::NotFound) => return Err(DriverError::Unauthenticated),
            Err(error) => return Err(error.into()),
        };
        if current_user.password != user.password || current_user.activation_code.is_some() {
            return Err(DriverError::Unauthenticated);
        }

        let user = current_user;
        let now = self.clock.now_utc();
        let access_token = AccessToken::generate();
        let expiration_time = now + max_age;
        let session = Session::new(access_token.clone(), user.id, now, expiration_time);
        db::put_session(tx.ex(), &session).await?;

        db::update_user(tx.ex(), user.id, now).await?;

        let output = self.hooks.login_hook(&mut tx, now, &user).await?;

        tx.commit().await?;

        if !self.opts.sessions_cache_ttl.is_zero() {
            let mut cache = self.sessions_cache.lock().await;
            let cached_session =
                CachedSession { expires_at: expiration_time, user: Arc::from(user) };
            let previous = cache.insert(access_token, Ok(cached_session));
            assert!(previous.is_none(), "The session has not yet been returned to the client");
        }

        Ok((session, max_age, output))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::passwords::PasswordHasher;
    use crate::driver::testutils::*;
    use crate::driver::{AuthnOptions, NO_EXTENSIONS};
    use crate::model::{hashed_password, password};
    use iii_iv_core::clocks::testutils::SettableClock;
    use iii_iv_core::driver::DriverError;
    use iii_iv_core::model::{ModelResult, email_address, username};
    use std::sync::{Arc, Mutex};
    use time::OffsetDateTime;
    use time::macros::datetime;

    const TEST_SESSION_MAX_AGE: Option<Duration> = Some(Duration::from_secs(100));

    /// Password hasher that records verification calls and returns a fixed result.
    struct RecordingHasher {
        hashes: Arc<Mutex<Vec<String>>>,
        verified: bool,
    }

    impl PasswordHasher for RecordingHasher {
        fn hash(
            &self,
            _password: Password,
            _validator: fn(&str) -> Option<&'static str>,
        ) -> ModelResult<HashedPassword> {
            Ok(hashed_password!("unused"))
        }

        fn verify(&self, _password: Password, hash: HashedPassword) -> ModelResult<bool> {
            self.hashes.lock().unwrap().push(hash.as_str().to_owned());
            Ok(self.verified)
        }
    }

    /// Replaces the production hasher with a recording implementation.
    fn with_recording_hasher(
        driver: AuthnDriver<crate::driver::AuthnNoHooks>,
        verified: bool,
    ) -> (AuthnDriver<crate::driver::AuthnNoHooks>, Arc<Mutex<Vec<String>>>) {
        let hashes = Arc::new(Mutex::new(Vec::new()));
        let hasher = Arc::new(RecordingHasher { hashes: hashes.clone(), verified });
        (driver.with_password_hasher(hasher), hashes)
    }

    /// Runs an account mutation while password verification is in progress.
    struct MutatingHasher {
        action: Box<dyn Fn() + Send + Sync>,
    }

    impl PasswordHasher for MutatingHasher {
        fn hash(
            &self,
            _password: Password,
            _validator: fn(&str) -> Option<&'static str>,
        ) -> ModelResult<HashedPassword> {
            unreachable!()
        }

        fn verify(&self, _password: Password, _hash: HashedPassword) -> ModelResult<bool> {
            (self.action)();
            Ok(true)
        }
    }

    async fn do_login_rechecks_account_after_verification_test(change_password: bool) {
        let context = TestContext::setup(AuthnOptions::default()).await;

        let username = username!("hello");
        context.create_active_user(&username).await;

        let driver = context.driver();
        let db = driver.db.clone();
        let user =
            db::get_user_by_username(&mut context.ex().await, username.clone()).await.unwrap();

        let runtime = tokio::runtime::Handle::current();
        let hasher = MutatingHasher {
            action: Box::new(move || {
                runtime.block_on(async {
                    let mut ex = db.ex().await.unwrap();
                    if change_password {
                        db::update_user_password(
                            &mut ex,
                            user.id,
                            user.password.as_ref().unwrap(),
                            hashed_password!("changed"),
                        )
                        .await
                        .unwrap();
                    } else {
                        let current = db::get_user_by_id(&mut ex, user.id).await.unwrap();
                        db::set_user_activation_code(&mut ex, current, Some(42)).await.unwrap();
                    }
                })
            }),
        };

        assert_eq!(
            Err(DriverError::Unauthenticated),
            driver
                .with_password_hasher(Arc::new(hasher))
                .login(username.as_str().to_owned(), password!("password"), TEST_SESSION_MAX_AGE)
                .await,
        );
    }

    #[tokio::test]
    async fn test_login_rechecks_account_after_verification_change_password() {
        do_login_rechecks_account_after_verification_test(true).await;
    }

    #[tokio::test]
    async fn test_login_rechecks_account_after_verification_change_activation_code() {
        do_login_rechecks_account_after_verification_test(false).await;
    }

    #[tokio::test]
    async fn test_login_ok_first_time() {
        let context = TestContext::setup(AuthnOptions::default()).await;

        let username = username!("hello");
        let password = password!("password");

        let user = db::create_user(
            &mut context.ex().await,
            Some(username.clone()),
            Some(password.clone().validate_and_hash(|_| None).unwrap()),
            email_address!("some@example.com"),
            None,
        )
        .await
        .unwrap();

        let expected_hash = user.password.as_ref().unwrap().as_str().to_owned();
        let (driver, hashes) = with_recording_hasher(context.driver(), true);
        let before = context.driver().now_utc();
        let (response, _, NO_EXTENSIONS) = driver
            .login(username.as_str().to_owned(), password, TEST_SESSION_MAX_AGE)
            .await
            .unwrap();
        let after = context.driver().now_utc();

        assert_eq!(&[expected_hash], hashes.lock().unwrap().as_slice());

        let session =
            db::get_session(&mut context.ex().await, &response.access_token).await.unwrap();
        assert_eq!(user.id, session.user_id);
        assert!(session.login_time >= before && session.login_time <= after);
        let user = db::get_user_by_username(&mut context.ex().await, username).await.unwrap();
        assert!(user.last_login.unwrap() >= before && user.last_login.unwrap() <= after);
        assert_eq!(&email_address!("some@example.com"), &user.email);
    }

    #[tokio::test]
    async fn test_login_capacity_rejection_does_not_reveal_account_existence() {
        let opts = AuthnOptions { password_hash_concurrency: 1, ..Default::default() };
        let context = TestContext::setup(opts).await;
        let username = username!("hello");
        context.create_active_user(&username).await;
        let driver = context.driver();
        let _permit = driver.acquire_password_hash_capacity().unwrap();

        for login in [username.as_str(), "unknown"] {
            let result = driver
                .clone()
                .login(login.to_owned(), password!("password"), TEST_SESSION_MAX_AGE)
                .await;
            assert_eq!(Err(DriverError::Unavailable), result);
        }
    }

    #[tokio::test]
    async fn test_login_by_email_without_usernames() {
        let context = TestContext::setup_without_usernames(AuthnOptions::default()).await;
        let password = password!("password");
        let email = email_address!("some@example.com");
        let user = db::create_user(
            &mut context.ex().await,
            None,
            Some(password.clone().validate_and_hash(|_| None).unwrap()),
            email.clone(),
            None,
        )
        .await
        .unwrap();

        let expected_hash = user.password.as_ref().unwrap().as_str().to_owned();
        let (driver, hashes) = with_recording_hasher(context.driver(), true);
        let (session, _, NO_EXTENSIONS) =
            driver.login(email.as_str().to_owned(), password, TEST_SESSION_MAX_AGE).await.unwrap();

        assert_eq!(user.id, session.user_id);
        assert_eq!(&[expected_hash], hashes.lock().unwrap().as_slice());
    }

    #[tokio::test]
    async fn test_login_by_email_rejected_with_usernames() {
        let context = TestContext::setup(AuthnOptions::default()).await;
        let (driver, hashes) = with_recording_hasher(context.driver(), true);
        let result = driver
            .login("some@example.com".to_owned(), password!("password"), TEST_SESSION_MAX_AGE)
            .await;
        assert_eq!(Err(DriverError::Unauthenticated), result);
        assert_eq!(&[DUMMY_PASSWORD_HASH.as_str()], hashes.lock().unwrap().as_slice());
    }

    #[tokio::test]
    async fn test_login_invalid_email() {
        let context = TestContext::setup_without_usernames(AuthnOptions::default()).await;
        let (driver, hashes) = with_recording_hasher(context.driver(), true);

        assert_eq!(
            Err(DriverError::Unauthenticated),
            driver.login("invalid".to_owned(), password!("password"), TEST_SESSION_MAX_AGE).await
        );
        assert_eq!(&[DUMMY_PASSWORD_HASH.as_str()], hashes.lock().unwrap().as_slice());
    }

    #[tokio::test]
    async fn test_login_ok_returning() {
        let context = TestContext::setup(AuthnOptions::default()).await;

        let username = username!("hello");
        let password = password!("password");

        let user = db::create_user(
            &mut context.ex().await,
            Some(username.clone()),
            Some(password.clone().validate_and_hash(|_| None).unwrap()),
            email_address!("some@example.com"),
            None,
        )
        .await
        .unwrap();
        db::update_user(
            &mut context.ex().await,
            user.id,
            OffsetDateTime::from_unix_timestamp(1).unwrap(),
        )
        .await
        .unwrap();

        let before = context.driver().now_utc();
        let (response, _, NO_EXTENSIONS) = context
            .driver()
            .login(username.as_str().to_owned(), password, TEST_SESSION_MAX_AGE)
            .await
            .unwrap();
        let after = context.driver().now_utc();

        let session =
            db::get_session(&mut context.ex().await, &response.access_token).await.unwrap();
        assert_eq!(user.id, session.user_id);
        assert!(session.login_time >= before && session.login_time <= after);
        let user = db::get_user_by_username(&mut context.ex().await, username).await.unwrap();
        assert!(user.last_login.unwrap() >= before && user.last_login.unwrap() <= after);
        assert_eq!(&email_address!("some@example.com"), &user.email);
    }

    #[tokio::test]
    async fn test_login_unknown_user() {
        let context = TestContext::setup(AuthnOptions::default()).await;
        let (driver, hashes) = with_recording_hasher(context.driver(), true);

        assert_eq!(
            Err(DriverError::Unauthenticated),
            driver.login("foo".to_owned(), password!("bar"), TEST_SESSION_MAX_AGE).await
        );
        assert_eq!(&[DUMMY_PASSWORD_HASH.as_str()], hashes.lock().unwrap().as_slice());
    }

    #[tokio::test]
    async fn test_login_invalid_password() {
        let context = TestContext::setup(AuthnOptions::default()).await;

        let username = username!("hello");

        let user = db::create_user(
            &mut context.ex().await,
            Some(username.clone()),
            Some(Password::new("ABC").unwrap().validate_and_hash(|_| None).unwrap()),
            email_address!("some@example.com"),
            None,
        )
        .await
        .unwrap();

        let expected_hash = user.password.as_ref().unwrap().as_str().to_owned();
        let (driver, hashes) = with_recording_hasher(context.driver(), false);
        assert_eq!(
            Err(DriverError::Unauthenticated),
            driver
                .login(username.as_str().to_owned(), password!("abc"), TEST_SESSION_MAX_AGE)
                .await
        );
        assert_eq!(&[expected_hash], hashes.lock().unwrap().as_slice());
    }

    #[tokio::test]
    async fn test_login_not_allowed() {
        let context = TestContext::setup(AuthnOptions::default()).await;

        let username = username!("hello");

        db::create_user(
            &mut context.ex().await,
            Some(username.clone()),
            None,
            email_address!("some@example.com"),
            None,
        )
        .await
        .unwrap();

        let (driver, hashes) = with_recording_hasher(context.driver(), true);
        assert_eq!(
            Err(DriverError::Unauthenticated),
            driver
                .login(username.as_str().to_owned(), password!("irrelevant"), TEST_SESSION_MAX_AGE)
                .await
        );
        assert_eq!(&[DUMMY_PASSWORD_HASH.as_str()], hashes.lock().unwrap().as_slice());
    }

    #[tokio::test]
    async fn test_login_not_activated() {
        let context = TestContext::setup(AuthnOptions::default()).await;

        let username = username!("hello");
        let password = password!("password");

        let user = db::create_user(
            &mut context.ex().await,
            Some(username.clone()),
            Some(password.clone().validate_and_hash(|_| None).unwrap()),
            email_address!("some@example.com"),
            None,
        )
        .await
        .unwrap();
        db::set_user_activation_code(&mut context.ex().await, user, Some(50)).await.unwrap();
        let user =
            db::get_user_by_username(&mut context.ex().await, username.clone()).await.unwrap();

        let expected_hash = user.password.as_ref().unwrap().as_str().to_owned();
        let (driver, hashes) = with_recording_hasher(context.driver(), true);
        assert_eq!(
            Err(DriverError::Unauthenticated),
            driver.login(username.as_str().to_owned(), password, TEST_SESSION_MAX_AGE).await
        );
        assert_eq!(&[expected_hash], hashes.lock().unwrap().as_slice());
    }

    #[tokio::test]
    async fn test_login_inserts_session_into_cache() {
        let opts =
            AuthnOptions { sessions_cache_ttl: Duration::from_secs(60), ..Default::default() };
        let context = TestContext::setup(opts).await;

        let username = username!("hello");
        let password = password!("password");

        db::create_user(
            &mut context.ex().await,
            Some(username.clone()),
            Some(password.clone().validate_and_hash(|_| None).unwrap()),
            email_address!("some@example.com"),
            None,
        )
        .await
        .unwrap();

        assert_eq!(0, context.driver().sessions_cache.lock().await.len());
        let (session, _, NO_EXTENSIONS) = context
            .driver()
            .login(username.as_str().to_owned(), password, TEST_SESSION_MAX_AGE)
            .await
            .unwrap();
        let driver = context.driver();
        let cache = driver.sessions_cache.lock().await;
        assert_eq!(1, cache.len());
        assert!(cache.contains_key(&session.access_token));
    }

    #[tokio::test]
    async fn test_login_caps_requested_max_age() {
        let max_age = Duration::from_secs(10);
        let opts = AuthnOptions { session_max_age: max_age, ..Default::default() };
        let context = TestContext::setup(opts).await;
        let username = username!("hello");
        context.create_active_user(&username).await;

        let (session, actual_max_age, NO_EXTENSIONS) = context
            .driver()
            .login(
                username.as_str().to_owned(),
                password!("test0password"),
                Some(Duration::from_secs(20)),
            )
            .await
            .unwrap();

        assert_eq!(max_age, actual_max_age);
        assert_eq!(session.login_time + max_age, session.expiration_time);
    }

    #[tokio::test]
    async fn test_login_hook_failure_aborts_login() {
        let db = Arc::from(iii_iv_core::db::sqlite::testutils::setup().await);
        let clock = Arc::from(SettableClock::new(datetime!(2023-12-01 05:50:00 UTC)));
        let context = TestContext::setup_with_hooks(
            AuthnOptions::default(),
            db.clone(),
            clock,
            "the-realm",
            true,
            FailingLoginHook,
        )
        .await;

        let username = username!("hello");
        let password = password!("password");

        db::create_user(
            &mut context.ex().await,
            Some(username.clone()),
            Some(password.clone().validate_and_hash(|_| None).unwrap()),
            email_address!("some@example.com"),
            None,
        )
        .await
        .unwrap();

        let user_before =
            db::get_user_by_username(&mut context.ex().await, username.clone()).await.unwrap();
        let last_login_before = user_before.last_login;

        match context
            .driver()
            .login(username.as_str().to_owned(), password, TEST_SESSION_MAX_AGE)
            .await
        {
            Err(DriverError::BackendError(msg)) => {
                assert!(msg.contains("hook-failure-test"));
            }

            e => panic!("{:?}", e),
        }

        let user_after =
            db::get_user_by_username(&mut context.ex().await, username.clone()).await.unwrap();
        assert_eq!(last_login_before, user_after.last_login);

        assert_eq!(0, context.driver().sessions_cache.lock().await.len());
    }
}
