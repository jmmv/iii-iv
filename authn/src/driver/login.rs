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
use crate::model::{AccessToken, HashedPassword, LoginFailures, Password, Session, User};
use iii_iv_core::db::{DbError, Executor, TxExecutor};
use iii_iv_core::driver::{DriverError, DriverResult};
use iii_iv_core::model::{EmailAddress, Username};
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;

/// Fixed bcrypt hash used to equalize work for login attempts without a real password hash.
static DUMMY_PASSWORD_HASH: HashedPassword =
    HashedPassword::from_static("$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy");

impl<H: AuthnHooks> AuthnDriver<H> {
    /// Tests whether the persisted lock is still active.
    fn is_login_blocked(&self, state: &LoginFailures, now: OffsetDateTime) -> bool {
        state.blocked_until.is_some_and(|until| now < until)
    }

    /// Records a verified rejection using the configured backoff policy.
    fn record_login_failure(&self, state: &mut LoginFailures, now: OffsetDateTime) {
        if now - state.last_failure >= self.opts.login_backoff_quiet_window {
            state.count = 0;
        }
        state.count = state.count.saturating_add(1);
        state.last_failure = now;

        let threshold = self.opts.login_backoff_threshold.max(1);
        if state.count >= threshold {
            let cap = self.opts.login_backoff_max_delay;
            let mut delay = self.opts.login_backoff_initial_delay.min(cap);
            if !delay.is_zero() {
                for _ in 0..state.count - threshold {
                    delay = delay.saturating_mul(2).min(cap);
                    if delay == cap {
                        break;
                    }
                }
            }
            state.blocked_until = Some(now + delay);
        } else {
            state.blocked_until = None;
        }
    }

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
            Ok(user) => Ok(Some(user)),
            Err(DbError::NotFound) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    /// Finds an unblocked account and verifies its password without a transaction.
    ///
    /// Returns the account snapshot and verification result.  The caller must check both under
    /// the account's backoff lock before logging in or recording a rejection.
    async fn admit_user(&self, login: String, password: Password) -> DriverResult<(User, bool)> {
        let permit = self.acquire_password_hash_capacity()?;

        let user = {
            let mut ex = self.db.ex().await?;
            let user = self.find_login_user(&mut ex, login).await?;
            if let Some(user) = &user {
                if db::get_login_failures(&mut ex, user.id)
                    .await?
                    .is_some_and(|state| self.is_login_blocked(&state, self.clock.now_utc()))
                {
                    return Err(DriverError::Unauthenticated);
                }
            }
            user
        };

        let hash =
            user.as_ref().and_then(|user| user.password.as_ref()).unwrap_or(&DUMMY_PASSWORD_HASH);

        let (verified, permit) = self.verify_password(password, hash, permit).await?;
        drop(permit);

        let user = user.ok_or(DriverError::Unauthenticated)?;
        Ok((user, verified))
    }

    /// Caches the logged-in session if session caching is enabled.
    async fn maybe_cache_session(
        &self,
        user: User,
        access_token: AccessToken,
        expiration_time: OffsetDateTime,
    ) {
        if self.opts.sessions_cache_ttl.is_zero() {
            return;
        }

        let mut cache = self.sessions_cache.lock().await;
        let cached_session = CachedSession { expires_at: expiration_time, user: Arc::from(user) };
        let previous = cache.insert(access_token, Ok(cached_session));
        assert!(previous.is_none(), "The session has not yet been returned to the client");
    }

    /// Rechecks admission under the account lock and persists verified rejections.
    ///
    /// Returns the open transaction, current account, and decision timestamp on success.  The
    /// caller must finish login in this transaction so another attempt cannot bypass the lock.
    async fn authorize_user(
        &self,
        admitted_user: User,
        verified: bool,
    ) -> DriverResult<(TxExecutor, User, OffsetDateTime)> {
        let mut tx = self.db.begin().await?;
        let mut failures =
            match db::lock_login_failures(tx.ex(), admitted_user.id, self.clock.now_utc()).await {
                Ok(state) => state,
                Err(DbError::NotFound) => return Err(DriverError::Unauthenticated),
                Err(error) => return Err(error.into()),
            };
        let now = self.clock.now_utc();
        if self.is_login_blocked(&failures, now) {
            return Err(DriverError::Unauthenticated);
        }

        let user = match db::get_user_by_id(tx.ex(), admitted_user.id).await {
            Ok(user) => user,
            Err(DbError::NotFound) => return Err(DriverError::Unauthenticated),
            Err(error) => return Err(error.into()),
        };
        if !verified
            || user.password.is_none()
            || user.password != admitted_user.password
            || !user.is_active
        {
            self.record_login_failure(&mut failures, now);
            db::save_login_failures(tx.ex(), user.id, &failures).await?;
            tx.commit().await?;
            return Err(DriverError::Unauthenticated);
        }

        Ok((tx, user, now))
    }

    /// Completes login after rechecking admission under the account lock.
    async fn do_login(
        &self,
        admitted_user: User,
        verified: bool,
        max_age: Duration,
    ) -> DriverResult<(Session, H::LoginOutput)> {
        let (mut tx, user, now) = self.authorize_user(admitted_user, verified).await?;
        db::clear_login_failures(tx.ex(), user.id).await?;
        let access_token = AccessToken::generate();
        let expiration_time = now + max_age;
        let session = Session::new(access_token.clone(), user.id, now, expiration_time);
        db::put_session(tx.ex(), &session).await?;

        db::update_user(tx.ex(), user.id, now).await?;

        let output = self.hooks.login_hook(&mut tx, now, &user).await?;

        tx.commit().await?;

        self.maybe_cache_session(user, access_token, expiration_time).await;
        Ok((session, output))
    }

    /// Logs a user with their configured login identifier, `password`, and an optional session age.
    pub(crate) async fn login(
        self,
        login: String,
        password: Password,
        requested_max_age: Option<Duration>,
    ) -> DriverResult<(Session, Duration, H::LoginOutput)> {
        let max_age =
            requested_max_age.unwrap_or(self.opts.session_max_age).min(self.opts.session_max_age);

        let (user, verified) = self.admit_user(login, password).await?;
        let (session, output) = self.do_login(user, verified, max_age).await?;
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
    use iii_iv_core::db::Db;
    use iii_iv_core::driver::DriverError;
    use iii_iv_core::model::{ModelResult, email_address, username};
    use std::sync::mpsc;
    use std::sync::{Arc, Mutex};
    use time::OffsetDateTime;
    use time::macros::datetime;
    use tokio::sync::Notify;
    use uuid::Uuid;

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

    /// Executes a test action while password verification is in progress.
    struct ActionHasher {
        verified: bool,
        action: Box<dyn Fn() + Send + Sync>,
    }

    impl PasswordHasher for ActionHasher {
        fn hash(
            &self,
            _password: Password,
            _validator: fn(&str) -> Option<&'static str>,
        ) -> ModelResult<HashedPassword> {
            unreachable!()
        }

        fn verify(&self, _password: Password, _hash: HashedPassword) -> ModelResult<bool> {
            (self.action)();
            Ok(self.verified)
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
        let hasher = ActionHasher {
            verified: true,
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
    async fn test_login_backoff_progression_and_resets() {
        {
            let db = Arc::from(iii_iv_core::db::sqlite::testutils::setup().await);
            let clock = Arc::new(SettableClock::new(datetime!(2026-01-01 0:00 UTC)));
            let context = TestContext::setup_with(
                AuthnOptions::default(),
                db,
                clock.clone(),
                "the-realm",
                true,
            )
            .await;

            let user = db::create_user(
                &mut context.ex().await,
                Some(username!("hello")),
                Some(hashed_password!("real-hash")),
                email_address!("hello@example.com"),
                None,
            )
            .await
            .unwrap();

            let login = "hello";
            let (driver, hashes) = with_recording_hasher(context.driver(), false);

            for delay in [0, 0, 60, 120, 240, 480, 960] {
                assert_eq!(
                    Err(DriverError::Unauthenticated),
                    driver.clone().login(login.to_owned(), password!("bad"), None).await
                );
                let before =
                    db::get_login_failures(&mut context.ex().await, user.id).await.unwrap();
                if delay > 0 {
                    let calls = hashes.lock().unwrap().len();
                    clock.advance(Duration::from_secs(delay - 1));
                    let (correct, correct_hashes) = with_recording_hasher(context.driver(), true);
                    assert_eq!(
                        Err(DriverError::Unauthenticated),
                        correct.login(login.to_owned(), password!("correct"), None).await
                    );
                    assert!(correct_hashes.lock().unwrap().is_empty());
                    assert_eq!(calls, hashes.lock().unwrap().len());
                    assert_eq!(
                        before,
                        db::get_login_failures(&mut context.ex().await, user.id).await.unwrap()
                    );
                    clock.advance(Duration::from_secs(1));
                }
            }
            assert_eq!(
                Err(DriverError::Unauthenticated),
                driver.clone().login(login.to_owned(), password!("bad"), None).await
            );

            let state =
                db::get_login_failures(&mut context.ex().await, user.id).await.unwrap().unwrap();
            assert_eq!(1, state.count);
            assert_eq!(None, state.blocked_until);
            clock.advance(Duration::from_secs(900));
            assert_eq!(
                Err(DriverError::Unauthenticated),
                driver.login(login.to_owned(), password!("bad"), None).await
            );
            assert_eq!(
                1,
                db::get_login_failures(&mut context.ex().await, user.id)
                    .await
                    .unwrap()
                    .unwrap()
                    .count
            );

            let (correct, _) = with_recording_hasher(context.driver(), true);
            correct.login(login.to_owned(), password!("correct"), None).await.unwrap();
            assert_eq!(
                None,
                db::get_login_failures(&mut context.ex().await, user.id).await.unwrap()
            );
        }
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
        let user =
            db::get_user_by_username(&mut context.ex().await, username!("hello")).await.unwrap();
        assert_eq!(
            1,
            db::get_login_failures(&mut context.ex().await, user.id).await.unwrap().unwrap().count
        );
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
        let user =
            db::get_user_by_username(&mut context.ex().await, username!("hello")).await.unwrap();
        assert_eq!(
            1,
            db::get_login_failures(&mut context.ex().await, user.id).await.unwrap().unwrap().count
        );
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
        let mut tx = context.db().begin().await.unwrap();
        let mut failures =
            db::lock_login_failures(tx.ex(), user_before.id, context.driver().now_utc())
                .await
                .unwrap();
        context.driver().record_login_failure(&mut failures, context.driver().now_utc());
        db::save_login_failures(tx.ex(), user_before.id, &failures).await.unwrap();
        tx.commit().await.unwrap();

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
        assert_eq!(
            Some(failures),
            db::get_login_failures(&mut context.ex().await, user_before.id).await.unwrap()
        );

        assert_eq!(0, context.driver().sessions_cache.lock().await.len());
    }

    #[tokio::test]
    async fn test_progressive_delays_and_cap() {
        let driver = TestContext::setup(AuthnOptions::default()).await.driver();
        let now = datetime!(2026-01-01 0:00 UTC);
        for (count, minutes) in [(2, 1), (3, 2), (4, 4), (5, 8), (6, 16), (7, 32), (8, 60)] {
            let mut state = LoginFailures { count, last_failure: now, blocked_until: None };
            driver.record_login_failure(&mut state, now);
            assert_eq!(count.saturating_add(1), state.count);
            assert_eq!(
                if minutes == 0 { None } else { Some(now + Duration::from_secs(minutes * 60)) },
                state.blocked_until
            );
        }
    }

    #[tokio::test]
    async fn test_lock_and_quiet_boundaries() {
        let driver = TestContext::setup(AuthnOptions::default()).await.driver();
        let now = datetime!(2026-01-01 0:00 UTC);
        let mut state = LoginFailures { count: 6, last_failure: now, blocked_until: None };
        driver.record_login_failure(&mut state, now);
        let until = now + Duration::from_secs(16 * 60);
        assert!(driver.is_login_blocked(&state, now + Duration::from_secs(15 * 60)));
        assert!(driver.is_login_blocked(&state, until - Duration::from_micros(1)));
        assert!(!driver.is_login_blocked(&state, until));
        driver.record_login_failure(&mut state, until);
        assert_eq!(1, state.count);
        assert_eq!(None, state.blocked_until);

        for (elapsed, expected) in [(899, 2), (900, 1)] {
            let mut state = LoginFailures { count: 1, last_failure: now, blocked_until: None };
            driver.record_login_failure(&mut state, now + Duration::from_secs(elapsed));
            assert_eq!(expected, state.count);
        }
    }

    #[tokio::test]
    async fn test_custom_backoff_options() {
        for (threshold, initial, cap, quiet, expected) in
            [(1, 3, 10, 100, 3), (1, 20, 10, 100, 10), (1, 0, 10, 100, 0), (1, 3, 0, 100, 0)]
        {
            let opts = AuthnOptions {
                login_backoff_threshold: threshold,
                login_backoff_initial_delay: Duration::from_secs(initial),
                login_backoff_max_delay: Duration::from_secs(cap),
                login_backoff_quiet_window: Duration::from_secs(quiet),
                ..Default::default()
            };
            let context = TestContext::setup(opts).await;
            let driver = context.driver();
            let now = datetime!(2026-01-01 0:00 UTC);
            let mut state = LoginFailures { count: 0, last_failure: now, blocked_until: None };
            driver.record_login_failure(&mut state, now);
            assert_eq!(expected > 0, driver.is_login_blocked(&state, now));
            if expected > 0 {
                assert_eq!(Some(now + Duration::from_secs(expected)), state.blocked_until);
            }
        }
    }

    /// Exercises outcomes that complete while another instance is still verifying a password.
    async fn check_overlapping_logins(
        first_db: Arc<dyn Db + Send + Sync>,
        second_db: Arc<dyn Db + Send + Sync>,
    ) {
        let clock = Arc::new(SettableClock::new(datetime!(2026-01-01 0:00 UTC)));
        let first = TestContext::setup_with(
            AuthnOptions::default(),
            first_db,
            clock.clone(),
            "realm",
            true,
        )
        .await;
        let second =
            TestContext::setup_with(AuthnOptions::default(), second_db, clock, "realm", true).await;
        let username = username!("race");
        let user = db::create_user(
            &mut first.ex().await,
            Some(username.clone()),
            Some(hashed_password!("fixture")),
            email_address!("race@example.com"),
            None,
        )
        .await
        .unwrap();

        let mut tx = first.db().begin().await.unwrap();
        let now = first.driver().now_utc();
        let mut state = db::lock_login_failures(tx.ex(), user.id, now).await.unwrap();
        for _ in 0..2 {
            first.driver().record_login_failure(&mut state, now);
        }
        db::save_login_failures(tx.ex(), user.id, &state).await.unwrap();
        tx.commit().await.unwrap();

        let entered = Arc::new(Notify::new());
        let signal = entered.clone();
        let (release, receiver) = mpsc::channel();
        let receiver = Mutex::new(receiver);
        let paused = second.driver().with_password_hasher(Arc::new(ActionHasher {
            verified: true,
            action: Box::new(move || {
                signal.notify_one();
                receiver.lock().unwrap().recv_timeout(Duration::from_secs(10)).unwrap();
            }),
        }));
        let login = username.as_str().to_owned();
        let pending =
            tokio::spawn(async move { paused.login(login, password!("test"), None).await });
        entered.notified().await;

        let (driver, _) = with_recording_hasher(first.driver(), false);
        let result = driver.login(username.as_str().to_owned(), password!("test"), None).await;
        assert!(matches!(result, Err(DriverError::Unauthenticated)));

        let state_before = db::get_login_failures(&mut first.ex().await, user.id).await.unwrap();
        release.send(()).unwrap();
        assert_eq!(Err(DriverError::Unauthenticated), pending.await.unwrap());

        let state_after = db::get_login_failures(&mut first.ex().await, user.id).await.unwrap();
        assert_eq!(Some(3), state_after.as_ref().map(|state| state.count));
        assert_eq!(state_before, state_after);
    }

    #[tokio::test]
    async fn test_login_overlaps_across_sqlite_drivers() {
        let db: Arc<dyn Db + Send + Sync> =
            Arc::from(iii_iv_core::db::sqlite::testutils::setup().await);
        check_overlapping_logins(db.clone(), db.clone()).await;
        db.close().await;
    }

    #[tokio::test]
    async fn test_login_backoff_survives_database_reopen() {
        let path = std::env::temp_dir().join(format!("iii-iv-backoff-{}.sqlite", Uuid::new_v4()));
        let connection = format!("sqlite://{}?mode=rwc", path.display());
        let clock = Arc::new(SettableClock::new(datetime!(2026-01-01 0:00 UTC)));

        let user_id;
        {
            let db = Arc::new(iii_iv_core::db::sqlite::connect(&connection).await.unwrap());
            let context = TestContext::setup_with(
                AuthnOptions::default(),
                db.clone(),
                clock.clone(),
                "realm",
                true,
            )
            .await;

            let user = db::create_user(
                &mut context.ex().await,
                Some(username!("hello")),
                Some(hashed_password!("fixture")),
                email_address!("hello@example.com"),
                None,
            )
            .await
            .unwrap();
            user_id = user.id;

            let (driver, _) = with_recording_hasher(context.driver(), false);
            for _ in 0..3 {
                assert_eq!(
                    Err(DriverError::Unauthenticated),
                    driver.clone().login("hello".to_owned(), password!("bad"), None).await
                );
            }

            drop(driver);
            drop(context);
            db.close().await;
        }

        {
            let db = Arc::new(iii_iv_core::db::sqlite::connect(&connection).await.unwrap());
            let context = TestContext::setup_with(
                AuthnOptions::default(),
                db.clone(),
                clock.clone(),
                "realm",
                true,
            )
            .await;

            let (driver, hashes) = with_recording_hasher(context.driver(), true);
            assert_eq!(
                Err(DriverError::Unauthenticated),
                driver.clone().login("hello".to_owned(), password!("correct"), None).await
            );
            assert!(hashes.lock().unwrap().is_empty());
            assert_eq!(
                3,
                db::get_login_failures(&mut context.ex().await, user_id)
                    .await
                    .unwrap()
                    .unwrap()
                    .count
            );

            clock.advance(Duration::from_secs(60));

            driver.login("hello".to_owned(), password!("correct"), None).await.unwrap();
            assert_eq!(
                None,
                db::get_login_failures(&mut context.ex().await, user_id).await.unwrap()
            );

            drop(context);
            db.close().await;
        }
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn test_login_capacity_and_worker_errors_preserve_backoff() {
        let context =
            TestContext::setup(AuthnOptions { password_hash_concurrency: 1, ..Default::default() })
                .await;

        let user = db::create_user(
            &mut context.ex().await,
            Some(username!("hello")),
            Some(hashed_password!("fixture")),
            email_address!("hello@example.com"),
            None,
        )
        .await
        .unwrap();

        let (driver, _) = with_recording_hasher(context.driver(), false);
        assert_eq!(
            Err(DriverError::Unauthenticated),
            driver.clone().login("hello".to_owned(), password!("bad"), None).await
        );

        let before = db::get_login_failures(&mut context.ex().await, user.id).await.unwrap();
        let permit = driver.acquire_password_hash_capacity().unwrap();
        assert_eq!(
            Err(DriverError::Unavailable),
            driver.login("hello".to_owned(), password!("bad"), None).await
        );
        drop(permit);

        let driver = context.driver().with_password_hasher(Arc::new(ActionHasher {
            verified: false,
            action: Box::new(|| panic!("injected password worker failure")),
        }));
        assert!(matches!(
            driver.login("hello".to_owned(), password!("bad"), None).await,
            Err(DriverError::BackendError(_))
        ));
        assert_eq!(before, db::get_login_failures(&mut context.ex().await, user.id).await.unwrap());
    }
}
