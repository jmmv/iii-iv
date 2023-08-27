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
use iii_iv_core::clocks::Clock;
use iii_iv_core::db::{Db, DbError, TxExecutor};
use iii_iv_core::driver::{DriverError, DriverResult};
use iii_iv_core::env::get_optional_var;
use iii_iv_core::rest::BaseUrls;
use iii_iv_lettre::{EmailTemplate, SmtpMailer};
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

/// Default value for the `SESSION_MAX_AGE` setting when not specified.
const DEFAULT_SESSION_MAX_AGE_SECONDS: u64 = 24 * 60 * 60;

/// Default value for the `SESSION_MAX_SKEW` setting when not specified.
const DEFAULT_SESSION_MAX_SKEW_SECONDS: u64 = 60 * 60;

/// Configuration options for the authentication driver.
#[derive(Clone)]
pub struct AuthnOptions {
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
            session_max_age: Duration::from_secs(DEFAULT_SESSION_MAX_AGE_SECONDS),
            session_max_skew: Duration::from_secs(DEFAULT_SESSION_MAX_SKEW_SECONDS),
        }
    }
}

impl AuthnOptions {
    /// Creates a new set of options from environment variables.
    pub fn from_env(prefix: &str) -> Result<Self, String> {
        Ok(Self {
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
        Self {
            db,
            clock,
            mailer,
            activation_template: Arc::from(activation_template),
            base_urls,
            realm,
            opts,
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
    pub async fn get_session(
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
}

#[cfg(test)]
mod tests {
    use crate::driver::testutils::*;
    use iii_iv_core::driver::DriverError;
    use iii_iv_core::model::Username;
    use time::OffsetDateTime;

    #[tokio::test]
    async fn test_get_session_ok() {
        let context = TestContext::setup().await;
        let mut tx = context.db().begin().await.unwrap();

        let token = context.do_test_login(Username::from("username")).await;
        assert!(context
            .driver()
            .get_session(&mut tx, OffsetDateTime::from_unix_timestamp(100000).unwrap(), token)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn test_get_session_login_expired() {
        let context = TestContext::setup().await;
        let mut tx = context.db().begin().await.unwrap();

        let token = context.do_test_login(Username::from("username")).await;
        assert!(context
            .driver()
            .get_session(
                &mut tx,
                OffsetDateTime::from_unix_timestamp(100000).unwrap(),
                token.clone()
            )
            .await
            .is_ok());

        for i in [98000_i64, 100500, 180000].iter() {
            assert!(context
                .driver()
                .get_session(
                    &mut tx,
                    OffsetDateTime::from_unix_timestamp(*i).unwrap(),
                    token.clone()
                )
                .await
                .is_ok());
        }

        for i in [0_i64, 90000, 200000].iter() {
            match context
                .driver()
                .get_session(
                    &mut tx,
                    OffsetDateTime::from_unix_timestamp(*i).unwrap(),
                    token.clone(),
                )
                .await
            {
                Err(DriverError::Unauthorized(msg)) => assert!(msg.contains("expired")),
                e => panic!("{:?}", e),
            }
        }
    }

    #[tokio::test]
    async fn test_get_session_login_future() {
        let context = TestContext::setup().await;
        let mut tx = context.db().begin().await.unwrap();

        let token = context.do_test_login(Username::from("username")).await;
        assert!(context
            .driver()
            .get_session(
                &mut tx,
                OffsetDateTime::from_unix_timestamp(100000).unwrap(),
                token.clone()
            )
            .await
            .is_ok());

        assert!(context
            .driver()
            .get_session(
                &mut tx,
                OffsetDateTime::from_unix_timestamp(100500).unwrap(),
                token.clone()
            )
            .await
            .is_ok());

        match context
            .driver()
            .get_session(
                &mut tx,
                OffsetDateTime::from_unix_timestamp(90000).unwrap(),
                token.clone(),
            )
            .await
        {
            Err(DriverError::Unauthorized(msg)) => assert!(msg.contains("expired")),
            e => panic!("{:?}", e),
        }

        match context
            .driver()
            .get_session(&mut tx, OffsetDateTime::from_unix_timestamp(0).unwrap(), token)
            .await
        {
            Err(DriverError::Unauthorized(msg)) => assert!(msg.contains("expired")),
            e => panic!("{:?}", e),
        }
    }
}
