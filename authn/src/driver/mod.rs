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

use crate::db;
use crate::model::{AccessToken, User};
use derivative::Derivative;
use futures::lock::Mutex;
use iii_iv_core::clocks::Clock;
use iii_iv_core::db::{Db, DbError, TxExecutor};
use iii_iv_core::driver::{DriverError, DriverResult};
use iii_iv_core::env::get_optional_var;
use iii_iv_core::rest::BaseUrls;
use iii_iv_smtp::driver::SmtpMailer;
use iii_iv_smtp::model::EmailTemplate;
use log::warn;
use lru_time_cache::LruCache;
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;

mod activate;
pub(crate) mod email;
mod login;
mod logout;
mod signup;
#[cfg(any(test, feature = "testutils"))]
pub mod testutils;

/// Default number of sessions to keep cached in memory.
const DEFAULT_SESSIONS_CACHE_CAPACITY: usize = 10 * 1024;

/// Default amount of time to keep cached sessions in memory.
const DEFAULT_SESSIONS_CACHE_TTL_SECONDS: u64 = 60;

/// Default value for the `SESSION_MAX_AGE` setting when not specified.
const DEFAULT_SESSION_MAX_AGE_SECONDS: u64 = 24 * 60 * 60;

/// Default value for the `SESSION_MAX_SKEW` setting when not specified.
const DEFAULT_SESSION_MAX_SKEW_SECONDS: u64 = 60 * 60;

/// Configuration options for the authentication driver.
#[derive(Clone, Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct AuthnOptions {
    /// The number of sessions to keep cached in memory.
    pub sessions_cache_capacity: usize,

    /// The mount of time to keep cached sessions in memory.
    pub sessions_cache_ttl: Duration,

    /// The amount of time we consider sessions valid for.
    pub session_max_age: Duration,

    /// The amount of time we tolerate in clock skew when validating sessions.  We should never see
    /// this, except if we end up serving requests from different machines and their clocks aren't
    /// properly synchronized.
    pub session_max_skew: Duration,
}

impl Default for AuthnOptions {
    fn default() -> Self {
        Self {
            sessions_cache_ttl: Duration::from_secs(DEFAULT_SESSIONS_CACHE_TTL_SECONDS),
            sessions_cache_capacity: DEFAULT_SESSIONS_CACHE_CAPACITY,
            session_max_age: Duration::from_secs(DEFAULT_SESSION_MAX_AGE_SECONDS),
            session_max_skew: Duration::from_secs(DEFAULT_SESSION_MAX_SKEW_SECONDS),
        }
    }
}

impl AuthnOptions {
    /// Creates a new set of options from environment variables.
    pub fn from_env(prefix: &str) -> Result<Self, String> {
        Ok(Self {
            sessions_cache_capacity: get_optional_var::<usize>(prefix, "SESSIONS_CACHE_CAPACITY")?
                .unwrap_or(DEFAULT_SESSIONS_CACHE_CAPACITY),
            sessions_cache_ttl: get_optional_var::<Duration>(prefix, "SESSIONS_CACHE_TTL")?
                .unwrap_or_else(|| Duration::from_secs(DEFAULT_SESSIONS_CACHE_TTL_SECONDS)),
            session_max_age: get_optional_var::<Duration>(prefix, "SESSION_MAX_AGE")?
                .unwrap_or_else(|| Duration::from_secs(DEFAULT_SESSION_MAX_AGE_SECONDS)),
            session_max_skew: get_optional_var::<Duration>(prefix, "SESSION_MAX_SKEW")?
                .unwrap_or_else(|| Duration::from_secs(DEFAULT_SESSION_MAX_SKEW_SECONDS)),
        })
    }
}

/// Business logic.
///
/// The public operations exposed by the driver are all "one shot": they start and commit a
/// transaction, so it's incorrect for the caller to use two separate calls.  For this reason,
/// these operations consume the driver in an attempt to minimize the possibility of executing
/// two operations.
#[derive(Derivative)]
#[derivative(Clone(bound = ""))]
pub struct AuthnDriver {
    /// The database that the driver uses for persistence.
    db: Arc<dyn Db + Send + Sync>,

    /// Clock instance to obtain the current time.
    clock: Arc<dyn Clock + Send + Sync>,

    /// Service to send email notifications with.
    mailer: Arc<dyn SmtpMailer + Send + Sync>,

    /// Email template to use for activation emails.
    activation_template: Arc<EmailTemplate>,

    /// Base URLs of the running service.
    base_urls: Arc<BaseUrls>,

    /// Authentication realm to return to requests.
    realm: &'static str,

    /// Options for the authentication driver.
    opts: AuthnOptions,

    /// Cache of sessions.
    sessions_cache: Arc<Mutex<LruCache<AccessToken, DriverResult<Arc<User>>>>>,
}

impl AuthnDriver {
    /// Creates a new driver backed by the given dependencies.
    pub fn new(
        db: Arc<dyn Db + Send + Sync>,
        clock: Arc<dyn Clock + Send + Sync>,
        mailer: Arc<dyn SmtpMailer + Send + Sync>,
        activation_template: EmailTemplate,
        base_urls: Arc<BaseUrls>,
        realm: &'static str,
        opts: AuthnOptions,
    ) -> Self {
        let sessions_cache = LruCache::with_expiry_duration_and_capacity(
            opts.sessions_cache_ttl,
            opts.sessions_cache_capacity,
        );
        let sessions_cache = Arc::from(Mutex::from(sessions_cache));

        Self {
            db,
            clock,
            mailer,
            activation_template: Arc::from(activation_template),
            base_urls,
            realm,
            opts,
            sessions_cache,
        }
    }

    /// Returns a reference to the authentication options provided at creation time.
    pub(crate) fn opts(&self) -> &AuthnOptions {
        &self.opts
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
    ) -> DriverResult<User> {
        let session = match db::get_session(tx.ex(), &token).await {
            Ok(session) => session,
            Err(DbError::NotFound) => {
                return Err(DriverError::Unauthorized("Invalid session".to_owned()))
            }
            Err(e) => return Err(e.into()),
        };

        let whoami = db::get_user_by_username(tx.ex(), session.username().clone()).await?;

        let login_time = session.login_time();
        let expired = login_time < (now - self.opts.session_max_age);
        let skew = login_time > (now + self.opts.session_max_skew);
        if expired || skew {
            return Err(DriverError::Unauthorized(
                "Session expired; please log in again".to_owned(),
            ));
        }

        Ok(whoami)
    }

    /// Decodes the session in `token`, validates it and returns the user that owns the session.
    ///
    /// Both OK and error results come from an internal cache, which should have been configured to
    /// evict entries relatively quickly.  In general, the cache should only hold entries for the
    /// predicted length of a frontend interaction.
    pub async fn get_session(
        &self,
        tx: &mut TxExecutor,
        now: OffsetDateTime,
        token: AccessToken,
    ) -> DriverResult<Arc<User>> {
        {
            let mut cache = self.sessions_cache.lock().await;
            if let Some(result) = cache.get(&token) {
                return result.clone();
            }
        }

        let result = self.get_session_uncached(tx, now, token.clone()).await.map(Arc::from);

        let mut cache = self.sessions_cache.lock().await;
        if let Some(old_result) = cache.insert(token, result.clone()) {
            if old_result.as_ref() != result.as_ref() {
                warn!(
                    "Cache insertion race detected with inconsistent values: {:?} != {:?}",
                    old_result, result
                );
            }
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use crate::db::update_user;

    use super::testutils::*;
    use super::*;
    use iii_iv_core::driver::DriverError;
    use iii_iv_core::model::Username;

    #[test]
    pub fn test_options_from_env_all_all_missing() {
        temp_env::with_vars_unset(
            [
                "PREFIX_SESSIONS_CACHE_CAPACITY",
                "PREFIX_SESSIONS_CACHE_TTL",
                "PREFIX_SESSION_MAX_AGE",
                "PREFIX_SESSION_MAX_SKEW",
            ],
            || {
                let opts = AuthnOptions::from_env("PREFIX").unwrap();
                assert_eq!(AuthnOptions::default(), opts);
            },
        );
    }

    #[test]
    pub fn test_options_from_env_all_optional_present() {
        temp_env::with_vars(
            [
                ("PREFIX_SESSIONS_CACHE_CAPACITY", Some("30")),
                ("PREFIX_SESSIONS_CACHE_TTL", Some("40m")),
                ("PREFIX_SESSION_MAX_AGE", Some("10m")),
                ("PREFIX_SESSION_MAX_SKEW", Some("20m")),
            ],
            || {
                let opts = AuthnOptions::from_env("PREFIX").unwrap();
                assert_eq!(
                    AuthnOptions {
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

        let token = context.do_test_login(Username::from("username")).await;
        assert!(context
            .driver()
            .get_session(&mut tx, context.clock.now_utc(), token)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn test_get_session_login_expired() {
        let context = TestContext::setup(opts_no_session_caching()).await;
        let mut tx = context.db().begin().await.unwrap();

        let token = context.do_test_login(Username::from("username")).await;
        assert!(context
            .driver()
            .get_session(&mut tx, context.clock.now_utc(), token.clone())
            .await
            .is_ok());

        for i in [-50 * 60, 10 * 60, 23 * 3600].into_iter() {
            let now = context.now_delta(i);
            assert!(context.driver().get_session(&mut tx, now, token.clone()).await.is_ok());
        }

        for i in [-2 * 3600, 25 * 3600].into_iter() {
            let now = context.now_delta(i);
            match context.driver().get_session(&mut tx, now, token.clone()).await {
                Err(DriverError::Unauthorized(msg)) => assert!(msg.contains("expired")),
                e => panic!("{:?}", e),
            }
        }
    }

    #[tokio::test]
    async fn test_get_session_login_future() {
        let context = TestContext::setup(opts_no_session_caching()).await;
        let mut tx = context.db().begin().await.unwrap();

        let token = context.do_test_login(Username::from("username")).await;
        assert!(context
            .driver()
            .get_session(&mut tx, context.clock.now_utc(), token.clone())
            .await
            .is_ok());

        assert!(context
            .driver()
            .get_session(&mut tx, context.now_delta(20 * 3600), token.clone())
            .await
            .is_ok());

        match context
            .driver()
            .get_session(&mut tx, context.now_delta(-2 * 3600), token.clone())
            .await
        {
            Err(DriverError::Unauthorized(msg)) => assert!(msg.contains("expired")),
            e => panic!("{:?}", e),
        }

        match context.driver().get_session(&mut tx, context.now_delta(-48 * 3600), token).await {
            Err(DriverError::Unauthorized(msg)) => assert!(msg.contains("expired")),
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

        let token = context.do_test_login(Username::from("user")).await;
        let other = context.do_test_login(Username::from("other")).await;

        let mut tx = context.db().begin().await.unwrap();

        // Insert a user with a specific login timestamp.
        let user = context.driver().get_session(&mut tx, now, token.clone()).await.unwrap();
        assert_eq!(last_login1, user.last_login().unwrap());

        // Modify the cached user's last login to an arbitrary value.
        update_user(tx.ex(), Username::from("user"), last_login2).await.unwrap();

        // Re-fetch the user session, which should come from the cache and not see the updated
        // database value.
        let user = context.driver().get_session(&mut tx, now, token.clone()).await.unwrap();
        assert_eq!(last_login1, user.last_login().unwrap());

        // Log in a second user to push the original user's session out of the cache.
        let _other = context.driver().get_session(&mut tx, now, other).await.unwrap();

        // Re-fetch the user session, which should now see the modified values.
        let user = context.driver().get_session(&mut tx, now, token).await.unwrap();
        assert_eq!(last_login2, user.last_login().unwrap());
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

        let token = context.do_test_login(Username::from("user")).await;
        let other = context.do_test_login(Username::from("other")).await;

        let mut tx = context.db().begin().await.unwrap();

        // Fetch a session for a user, triggering an error.
        let err = context.driver().get_session(&mut tx, future, token.clone()).await.unwrap_err();
        assert!(format!("{}", err).contains("expired"));

        // Try to fetch the session for the same user again, now with a valid "now" value.
        // The previous error should have been cached.
        let err = context.driver().get_session(&mut tx, now, token.clone()).await.unwrap_err();
        assert!(format!("{}", err).contains("expired"));

        // Log in a second user to push the original user's session out of the cache.
        let _other = context.driver().get_session(&mut tx, now, other).await.unwrap();

        // Re-fetch the user session, which should now work.
        let _user = context.driver().get_session(&mut tx, now, token.clone()).await.unwrap();
    }
}
