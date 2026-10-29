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

//! Business logic for user authentication.
//!
//! # Login backoff
//!
//! Login rejections for known accounts are persisted across service instances and restarts.
//! The third verified rejection within a 15-minute quiet window blocks login for one minute.
//! Subsequent rejections double the delay, capped at one hour.  Blocked requests skip password
//! verification and do not extend the lock, even if the supplied password is correct.
//! Inactive and password-disabled account rejections count; unknown identifiers use dummy
//! verification without creating account state.  Capacity and infrastructure errors do not count.
//!
//! Successful active login clears the history.  After an active lock expires, 15 minutes since
//! the last verified rejection also resets history.  Consequently, ordinary sequential attempts
//! reach a 16-minute lock and then reset; the one-hour cap bounds higher persisted counts.
//! All failures retain the generic credential rejection response.

use crate::db;
use crate::model::{AccessToken, AuthnTask, User};
use async_trait::async_trait;
use futures::lock::Mutex;
use iii_iv_core::clocks::Clock;
use iii_iv_core::config::Options;
use iii_iv_core::db::{Db, DbError, TxExecutor};
use iii_iv_core::driver::{DriverError, DriverResult};
use iii_iv_queue::driver::Client;
use log::warn;
use lru_time_cache::LruCache;
use serde::Serialize;
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;
use tokio::sync::Semaphore;

mod activate;
mod change_password;
pub(crate) mod email;
mod hooks;
mod login;
mod logout;
mod passwords;
pub use hooks::{AuthnHooks, AuthnNoHooks, NO_EXTENSIONS, NoExtensions};
mod signup;
mod tasks;
pub use tasks::AuthnTaskRunner;
#[cfg(any(test, feature = "testutils"))]
pub mod testutils;

/// Default delay before retrying email deliveries.
const DEFAULT_EMAIL_RETRY_DELAY: Duration = Duration::from_secs(24 * 60 * 60);

/// Default login backoff threshold.
const DEFAULT_LOGIN_BACKOFF_THRESHOLD: u32 = 3;

/// Default login backoff quiet window.
const DEFAULT_LOGIN_BACKOFF_QUIET_WINDOW: Duration = Duration::from_secs(15 * 60);

/// Default login backoff initial delay.
const DEFAULT_LOGIN_BACKOFF_INITIAL_DELAY: Duration = Duration::from_secs(60);

/// Default login backoff max delay.
const DEFAULT_LOGIN_BACKOFF_MAX_DELAY: Duration = Duration::from_secs(60 * 60);

/// Default maximum number of password-hashing jobs that may run concurrently.
const DEFAULT_PASSWORD_HASH_CONCURRENCY: usize = 4;

/// Default number of sessions to keep cached in memory.
const DEFAULT_SESSIONS_CACHE_CAPACITY: usize = 10 * 1024;

/// Default amount of time to keep cached sessions in memory.
const DEFAULT_SESSIONS_CACHE_TTL: Duration = Duration::ZERO;

/// Default value for the `SESSION_MAX_AGE` setting when not specified.
const DEFAULT_SESSION_MAX_AGE: Duration = Duration::from_secs(24 * 60 * 60);

/// Default value for the `SESSION_MAX_SKEW` setting when not specified.
const DEFAULT_SESSION_MAX_SKEW: Duration = Duration::from_secs(60 * 60);

/// Configuration options for the authentication driver.
#[derive(Clone, Debug, Options)]
#[cfg_attr(test, derive(PartialEq))]
#[options(prefix = "AUTHN")]
pub struct AuthnOptions {
    /// Delay before retrying email deliveries.
    #[option(default = DEFAULT_EMAIL_RETRY_DELAY)]
    pub email_retry_delay: Duration,

    /// Login backoff threshold.  Zero values are accepted.
    #[option(default = DEFAULT_LOGIN_BACKOFF_THRESHOLD)]
    pub login_backoff_threshold: u32,

    /// Login backoff quiet window.  Zero values are accepted.
    #[option(default = DEFAULT_LOGIN_BACKOFF_QUIET_WINDOW)]
    pub login_backoff_quiet_window: Duration,

    /// Login backoff initial delay.  Zero values are accepted.
    #[option(default = DEFAULT_LOGIN_BACKOFF_INITIAL_DELAY)]
    pub login_backoff_initial_delay: Duration,

    /// Login backoff max delay.  Zero values are accepted.
    #[option(default = DEFAULT_LOGIN_BACKOFF_MAX_DELAY)]
    pub login_backoff_max_delay: Duration,

    /// Whether users can sign up without an invitation.
    #[option(default = true)]
    pub open_signups: bool,

    /// Maximum number of password-hashing jobs that may run concurrently.
    #[option(default = DEFAULT_PASSWORD_HASH_CONCURRENCY)]
    pub password_hash_concurrency: usize,

    /// The number of sessions to keep cached in memory.
    #[option(default = DEFAULT_SESSIONS_CACHE_CAPACITY)]
    pub sessions_cache_capacity: usize,

    /// The amount of time to keep cached sessions in memory.  Caching is disabled by default.
    /// Enabling it may delay session revocation across service instances by up to this amount of
    /// time.
    #[option(default = DEFAULT_SESSIONS_CACHE_TTL)]
    pub sessions_cache_ttl: Duration,

    /// The amount of time we consider sessions valid for.
    #[option(default = DEFAULT_SESSION_MAX_AGE)]
    pub session_max_age: Duration,

    /// The amount of time we tolerate in clock skew when validating sessions.  We should never see
    /// this, except if we end up serving requests from different machines and their clocks aren't
    /// properly synchronized.
    #[option(default = DEFAULT_SESSION_MAX_SKEW)]
    pub session_max_skew: Duration,
}

impl Default for AuthnOptions {
    fn default() -> Self {
        Self {
            email_retry_delay: DEFAULT_EMAIL_RETRY_DELAY,
            login_backoff_threshold: DEFAULT_LOGIN_BACKOFF_THRESHOLD,
            login_backoff_quiet_window: DEFAULT_LOGIN_BACKOFF_QUIET_WINDOW,
            login_backoff_initial_delay: DEFAULT_LOGIN_BACKOFF_INITIAL_DELAY,
            login_backoff_max_delay: DEFAULT_LOGIN_BACKOFF_MAX_DELAY,
            open_signups: true,
            password_hash_concurrency: DEFAULT_PASSWORD_HASH_CONCURRENCY,
            sessions_cache_ttl: DEFAULT_SESSIONS_CACHE_TTL,
            sessions_cache_capacity: DEFAULT_SESSIONS_CACHE_CAPACITY,
            session_max_age: DEFAULT_SESSION_MAX_AGE,
            session_max_skew: DEFAULT_SESSION_MAX_SKEW,
        }
    }
}

/// Interface used by the authentication driver to enqueue its background tasks.
#[async_trait]
trait AuthnTaskEnqueuer: Send + Sync {
    /// Adds `task` to the queue using the transaction represented by `ex`.
    async fn enqueue(
        &self,
        ex: &mut iii_iv_core::db::Executor,
        task: AuthnTask,
    ) -> DriverResult<()>;
}

/// Adapts authentication tasks to an application's task container.
struct QueueAuthnTaskEnqueuer<T: Serialize + Send + Sync, F> {
    /// Application queue client.
    client: Client<T>,

    /// Function that wraps an authentication task in the application's task type.
    wrap: F,
}

#[async_trait]
impl<T, F> AuthnTaskEnqueuer for QueueAuthnTaskEnqueuer<T, F>
where
    T: Serialize + Send + Sync + 'static,
    F: Fn(AuthnTask) -> T + Send + Sync,
{
    async fn enqueue(
        &self,
        ex: &mut iii_iv_core::db::Executor,
        task: AuthnTask,
    ) -> DriverResult<()> {
        let task = (self.wrap)(task);
        self.client.clone().enqueue(ex, &task).await?;
        Ok(())
    }
}

/// A successfully validated session suitable for caching.
#[derive(Clone, Debug, PartialEq)]
struct CachedSession {
    /// Absolute time at which the session stops being valid.
    expires_at: OffsetDateTime,

    /// User that owns the session.
    user: Arc<User>,
}

/// Business logic.
///
/// The public operations exposed by the driver are all "one shot": they start and commit a
/// transaction, so it's incorrect for the caller to use two separate calls.  For this reason,
/// these operations consume the driver in an attempt to minimize the possibility of executing
/// two operations.
#[derive(Clone)]
pub struct AuthnDriver<H: AuthnHooks> {
    /// The database that the driver uses for persistence.
    db: Arc<dyn Db + Send + Sync>,

    /// Clock instance to obtain the current time.
    clock: Arc<dyn Clock + Send + Sync>,

    /// Queue to schedule authentication tasks into.
    task_enqueuer: Arc<dyn AuthnTaskEnqueuer>,

    /// Authentication realm to return to requests.
    realm: &'static str,

    /// Whether accounts have usernames and use them to log in.
    usernames: bool,

    /// Options for the authentication driver.
    opts: AuthnOptions,

    /// Password-hashing implementation.
    password_hasher: Arc<dyn passwords::PasswordHasher>,

    /// Capacity shared by all password-hashing operations.
    password_hash_semaphore: Arc<Semaphore>,

    /// Cache of sessions.
    sessions_cache: Arc<Mutex<LruCache<AccessToken, DriverResult<CachedSession>>>>,

    /// Hooks to customize the behavior of the authn APIs.
    hooks: H,
}

impl<H: AuthnHooks> AuthnDriver<H> {
    /// Creates a new driver backed by the given dependencies.
    #[allow(clippy::too_many_arguments)]
    pub fn new<T, F>(
        db: Arc<dyn Db + Send + Sync>,
        clock: Arc<dyn Clock + Send + Sync>,
        queue_client: Client<T>,
        wrap_task: F,
        realm: &'static str,
        usernames: bool,
        opts: AuthnOptions,
        hooks: H,
    ) -> Self
    where
        T: Serialize + Send + Sync + 'static,
        F: Fn(AuthnTask) -> T + Send + Sync + 'static,
    {
        let task_enqueuer =
            Arc::from(QueueAuthnTaskEnqueuer { client: queue_client, wrap: wrap_task });
        Self::new_with_task_enqueuer(db, clock, task_enqueuer, realm, usernames, opts, hooks)
    }

    /// Creates a new driver with a prebuilt task enqueuer.
    fn new_with_task_enqueuer(
        db: Arc<dyn Db + Send + Sync>,
        clock: Arc<dyn Clock + Send + Sync>,
        task_enqueuer: Arc<dyn AuthnTaskEnqueuer>,
        realm: &'static str,
        usernames: bool,
        opts: AuthnOptions,
        hooks: H,
    ) -> Self {
        let sessions_cache = LruCache::with_expiry_duration_and_capacity(
            opts.sessions_cache_ttl,
            opts.sessions_cache_capacity,
        );
        let sessions_cache = Arc::from(Mutex::from(sessions_cache));
        let password_hash_semaphore = Arc::new(Semaphore::new(opts.password_hash_concurrency));

        Self {
            db,
            clock,
            task_enqueuer,
            realm,
            usernames,
            opts,
            password_hasher: Arc::new(passwords::BcryptPasswordHasher),
            password_hash_semaphore,
            sessions_cache,
            hooks,
        }
    }

    /// Obtains the current time from the driver.
    #[cfg(test)]
    pub(crate) fn now_utc(&self) -> OffsetDateTime {
        self.clock.now_utc()
    }

    /// Gets the authentication realm.
    pub(crate) fn realm(&self) -> &'static str {
        self.realm
    }

    /// Decodes the session in `token`, validates it and returns the user that owns the session.
    ///
    /// This is an internal helper for `get_session` that does not perform any caching.
    async fn get_session_uncached(
        &self,
        tx: &mut TxExecutor,
        now: OffsetDateTime,
        token: AccessToken,
    ) -> DriverResult<CachedSession> {
        let session = match db::get_session(tx.ex(), &token).await {
            Ok(session) => session,
            Err(DbError::NotFound) => {
                return Err(DriverError::Unauthenticated);
            }
            Err(e) => return Err(e.into()),
        };

        let login_time = session.login_time;
        let expires_at = session.expiration_time.min(login_time + self.opts.session_max_age);
        let expired = now >= expires_at;
        let skew = login_time > (now + self.opts.session_max_skew);
        if expired || skew {
            return Err(DriverError::Unauthenticated);
        }

        let user = Arc::from(db::get_user_by_id(tx.ex(), session.user_id).await?);
        Ok(CachedSession { expires_at, user })
    }

    /// Decodes the session in `token`, validates it and returns the user that owns the session.
    ///
    /// When caching is enabled, both OK and error results come from an internal cache.  Successful
    /// entries are always rejected at their absolute expiration time even if their cache TTL is
    /// longer.
    pub async fn get_session(
        &self,
        tx: &mut TxExecutor,
        now: OffsetDateTime,
        token: AccessToken,
    ) -> DriverResult<Arc<User>> {
        if !self.opts.sessions_cache_ttl.is_zero() {
            let mut cache = self.sessions_cache.lock().await;
            // Do not refresh the TTL on hits because that could extend cross-instance revocation
            // lag indefinitely.
            if let Some(result) = cache.peek(&token).cloned() {
                return match result {
                    Ok(session) if now >= session.expires_at => {
                        let _previous = cache.remove(&token);
                        Err(DriverError::Unauthenticated)
                    }
                    Ok(session) => Ok(session.user),
                    Err(error) => Err(error),
                };
            }
        }

        let result = self.get_session_uncached(tx, now, token.clone()).await;
        if self.opts.sessions_cache_ttl.is_zero() {
            return result.map(|session| session.user);
        }

        let mut cache = self.sessions_cache.lock().await;
        if let Some(old_result) = cache.insert(token, result.clone()) {
            if old_result.as_ref() != result.as_ref() {
                warn!(
                    "Cache insertion race detected with inconsistent values: {:?} != {:?}",
                    old_result, result
                );
            }
        }

        result.map(|session| session.user)
    }
}

#[cfg(test)]
mod tests {
    use crate::db::update_user;

    use super::testutils::*;
    use super::*;
    use crate::model::password;
    use iii_iv_core::driver::DriverError;
    use iii_iv_core::model::username;
    use serial_test::serial;

    #[test]
    #[serial(AUTHN)]
    pub fn test_options_from_env_all_all_missing() {
        temp_env::with_vars_unset(
            [
                "TEST_AUTHN_EMAIL_RETRY_DELAY",
                "TEST_AUTHN_LOGIN_BACKOFF_THRESHOLD",
                "TEST_AUTHN_LOGIN_BACKOFF_QUIET_WINDOW",
                "TEST_AUTHN_LOGIN_BACKOFF_INITIAL_DELAY",
                "TEST_AUTHN_LOGIN_BACKOFF_MAX_DELAY",
                "TEST_AUTHN_OPEN_SIGNUPS",
                "TEST_AUTHN_PASSWORD_HASH_CONCURRENCY",
                "TEST_AUTHN_SESSIONS_CACHE_CAPACITY",
                "TEST_AUTHN_SESSIONS_CACHE_TTL",
                "TEST_AUTHN_SESSION_MAX_AGE",
                "TEST_AUTHN_SESSION_MAX_SKEW",
            ],
            || {
                let opts = AuthnOptions::from_env("TEST").unwrap();
                assert_eq!(AuthnOptions::default(), opts);
                assert_eq!(4, opts.password_hash_concurrency);
                assert_eq!(Duration::ZERO, opts.sessions_cache_ttl);
            },
        );
    }

    #[test]
    #[serial(AUTHN)]
    pub fn test_options_from_env_all_optional_present() {
        temp_env::with_vars(
            [
                ("TEST_AUTHN_EMAIL_RETRY_DELAY", Some("50m")),
                ("TEST_AUTHN_LOGIN_BACKOFF_THRESHOLD", Some("5")),
                ("TEST_AUTHN_LOGIN_BACKOFF_INITIAL_DELAY", Some("2s")),
                ("TEST_AUTHN_LOGIN_BACKOFF_MAX_DELAY", Some("10s")),
                ("TEST_AUTHN_LOGIN_BACKOFF_QUIET_WINDOW", Some("30s")),
                ("TEST_AUTHN_OPEN_SIGNUPS", Some("false")),
                ("TEST_AUTHN_PASSWORD_HASH_CONCURRENCY", Some("5")),
                ("TEST_AUTHN_SESSIONS_CACHE_CAPACITY", Some("30")),
                ("TEST_AUTHN_SESSIONS_CACHE_TTL", Some("40m")),
                ("TEST_AUTHN_SESSION_MAX_AGE", Some("10m")),
                ("TEST_AUTHN_SESSION_MAX_SKEW", Some("20m")),
            ],
            || {
                let opts = AuthnOptions::from_env("TEST").unwrap();
                assert_eq!(
                    AuthnOptions {
                        email_retry_delay: Duration::from_secs(50 * 60),
                        login_backoff_threshold: 5,
                        login_backoff_quiet_window: Duration::from_secs(30),
                        login_backoff_initial_delay: Duration::from_secs(2),
                        login_backoff_max_delay: Duration::from_secs(10),
                        open_signups: false,
                        password_hash_concurrency: 5,
                        sessions_cache_capacity: 30,
                        sessions_cache_ttl: Duration::from_secs(40 * 60),
                        session_max_age: Duration::from_secs(10 * 60),
                        session_max_skew: Duration::from_secs(20 * 60),
                    },
                    opts
                );
            },
        );
    }

    /// Returns a set of options to disable session caching.
    fn opts_no_session_caching() -> AuthnOptions {
        AuthnOptions { sessions_cache_ttl: Duration::ZERO, ..Default::default() }
    }

    #[tokio::test]
    async fn test_get_session_ok() {
        let context = TestContext::setup(opts_no_session_caching()).await;
        let mut tx = context.db().begin().await.unwrap();

        let token = context.do_test_login(username!("username")).await;
        assert!(
            context.driver().get_session(&mut tx, context.clock.now_utc(), token).await.is_ok()
        );
    }

    #[tokio::test]
    async fn test_get_session_login_expired() {
        let context = TestContext::setup(opts_no_session_caching()).await;
        let mut tx = context.db().begin().await.unwrap();

        let token = context.do_test_login(username!("username")).await;
        assert!(
            context
                .driver()
                .get_session(&mut tx, context.clock.now_utc(), token.clone())
                .await
                .is_ok()
        );

        for i in [-50 * 60, 10 * 60, 24 * 3600 - 1].into_iter() {
            let now = context.now_delta(i);
            assert!(context.driver().get_session(&mut tx, now, token.clone()).await.is_ok());
        }

        for i in [-2 * 3600, 24 * 3600, 25 * 3600].into_iter() {
            let now = context.now_delta(i);
            match context.driver().get_session(&mut tx, now, token.clone()).await {
                Err(DriverError::Unauthenticated) => {}
                e => panic!("{:?}", e),
            }
        }
    }

    #[tokio::test]
    async fn test_get_session_login_requested_max_age_expired() {
        let context = TestContext::setup(opts_no_session_caching()).await;
        let username = username!("username");
        context.create_active_user(&username).await;

        let (session, _, NO_EXTENSIONS) = context
            .driver()
            .login(
                username.as_str().to_owned(),
                password!("test0password"),
                Some(Duration::from_secs(10)),
            )
            .await
            .unwrap();
        let mut tx = context.db().begin().await.unwrap();

        assert!(
            context
                .driver()
                .get_session(&mut tx, context.now_delta(9), session.access_token.clone())
                .await
                .is_ok()
        );
        match context
            .driver()
            .get_session(&mut tx, context.now_delta(10), session.access_token)
            .await
        {
            Err(DriverError::Unauthenticated) => {}
            e => panic!("{:?}", e),
        }
    }

    #[tokio::test]
    async fn test_get_session_login_future() {
        let context = TestContext::setup(opts_no_session_caching()).await;
        let mut tx = context.db().begin().await.unwrap();

        let token = context.do_test_login(username!("username")).await;
        assert!(
            context
                .driver()
                .get_session(&mut tx, context.clock.now_utc(), token.clone())
                .await
                .is_ok()
        );

        assert!(
            context
                .driver()
                .get_session(&mut tx, context.now_delta(20 * 3600), token.clone())
                .await
                .is_ok()
        );

        match context
            .driver()
            .get_session(&mut tx, context.now_delta(-2 * 3600), token.clone())
            .await
        {
            Err(DriverError::Unauthenticated) => {}
            e => panic!("{:?}", e),
        }

        match context.driver().get_session(&mut tx, context.now_delta(-48 * 3600), token).await {
            Err(DriverError::Unauthenticated) => {}
            e => panic!("{:?}", e),
        }
    }

    #[tokio::test]
    async fn test_get_session_caches_ok_results() {
        // Configure a cache with just one entry and "infinite" duration so that we can precisely
        // control when entries get evicted.
        let opts = AuthnOptions {
            sessions_cache_capacity: 1,
            sessions_cache_ttl: Duration::from_secs(900),
            ..Default::default()
        };
        let context = TestContext::setup(opts).await;

        let now = context.clock.now_utc();
        let last_login1 = now;
        let last_login2 = context.clock.now_utc() + Duration::from_secs(10 * 3600);

        let token = context.do_test_login(username!("user")).await;
        let other = context.do_test_login(username!("other")).await;

        let mut tx = context.db().begin().await.unwrap();

        // Insert a user with a specific login timestamp.
        let user = context.driver().get_session(&mut tx, now, token.clone()).await.unwrap();
        assert_eq!(last_login1, user.last_login.unwrap());

        // Modify the cached user's last login to an arbitrary value.
        update_user(tx.ex(), user.id, last_login2).await.unwrap();

        // Re-fetch the user session, which should come from the cache and not see the updated
        // database value.
        let user = context.driver().get_session(&mut tx, now, token.clone()).await.unwrap();
        assert_eq!(last_login1, user.last_login.unwrap());

        // Log in a second user to push the original user's session out of the cache.
        let _other = context.driver().get_session(&mut tx, now, other).await.unwrap();

        // Re-fetch the user session, which should now see the modified values.
        let user = context.driver().get_session(&mut tx, now, token).await.unwrap();
        assert_eq!(last_login2, user.last_login.unwrap());
    }

    #[tokio::test]
    async fn test_get_session_cached_result_expires() {
        let opts = AuthnOptions {
            sessions_cache_ttl: Duration::from_secs(48 * 60 * 60),
            ..Default::default()
        };
        let context = TestContext::setup(opts).await;
        let token = context.do_test_login(username!("user")).await;
        let mut tx = context.db().begin().await.unwrap();

        assert!(
            context
                .driver()
                .get_session(&mut tx, context.now_delta(24 * 3600 - 1), token.clone())
                .await
                .is_ok()
        );

        match context.driver().get_session(&mut tx, context.now_delta(24 * 3600), token).await {
            Err(DriverError::Unauthenticated) => {}
            e => panic!("{:?}", e),
        }
    }

    #[tokio::test]
    async fn test_get_session_caches_errors() {
        // Configure a cache with just one entry and "infinite" duration so that we can precisely
        // control when entries get evicted.
        let opts = AuthnOptions {
            sessions_cache_capacity: 1,
            sessions_cache_ttl: Duration::from_secs(900),
            ..Default::default()
        };
        let context = TestContext::setup(opts).await;

        let now = context.clock.now_utc();
        let future = context.clock.now_utc() + Duration::from_secs(25 * 3600);

        let token = context.do_test_login(username!("user")).await;
        let other = context.do_test_login(username!("other")).await;

        let mut tx = context.db().begin().await.unwrap();

        // Fetch a session for a user, triggering an error.
        let err = context.driver().get_session(&mut tx, future, token.clone()).await.unwrap_err();
        assert_eq!(DriverError::Unauthenticated, err);

        // Try to fetch the session for the same user again, now with a valid "now" value.
        // The previous error should have been cached.
        let err = context.driver().get_session(&mut tx, now, token.clone()).await.unwrap_err();
        assert_eq!(DriverError::Unauthenticated, err);

        // Log in a second user to push the original user's session out of the cache.
        let _other = context.driver().get_session(&mut tx, now, other).await.unwrap();

        // Re-fetch the user session, which should now work.
        let _user = context.driver().get_session(&mut tx, now, token.clone()).await.unwrap();
    }
}
