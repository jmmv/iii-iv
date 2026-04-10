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

//! Utilities to help testing services that integrate with the `authn` features.

use super::AuthnNoHooks;
#[cfg(test)]
use super::{NO_EXTENSIONS, NoExtensions};
use crate::db;
use crate::driver::email::testutils::{get_latest_activation_code, make_test_activation_template};
use crate::driver::{AuthnDriver, AuthnHooks, AuthnOptions};
use crate::model::{AccessToken, password};
#[cfg(test)]
use async_trait::async_trait;
use iii_iv_core::clocks::Clock;
use iii_iv_core::db::Db;
#[cfg(test)]
use iii_iv_core::driver::{DriverError, DriverResult};
use iii_iv_core::model::EmailAddress;
use iii_iv_core::model::Username;
use iii_iv_core::rest::BaseUrls;
use iii_iv_smtp::driver::testutils::RecorderSmtpMailer;
use std::sync::Arc;

#[cfg(test)]
use {
    iii_iv_core::clocks::testutils::SettableClock, iii_iv_core::db::Executor, std::time::Duration,
    time::OffsetDateTime, time::macros::datetime,
};

/// State of a running test.
pub struct TestContext<H: AuthnHooks> {
    /// The clock used by the test.
    #[cfg(test)]
    pub(super) clock: Arc<dyn Clock + Send + Sync>,

    /// The SMTP mailer to capture authentication flow request messages.
    mailer: Arc<RecorderSmtpMailer>,

    /// The driver to handle authentication flows.
    driver: AuthnDriver<H>,
}

impl TestContext<AuthnNoHooks> {
    /// Initializes the driver using an in-memory database, a monotonic clock and a mock
    /// messenger that captures outgoing notifications.
    #[cfg(test)]
    pub(crate) async fn setup(opts: AuthnOptions) -> Self {
        let db = Arc::from(iii_iv_core::db::sqlite::testutils::setup().await);
        let clock = Arc::from(SettableClock::new(datetime!(2023-12-01 05:50:00 UTC)));
        Self::setup_with(opts, db, clock, "the-realm").await
    }

    /// Initializes the test context using the given already-initialized objects.
    pub async fn setup_with(
        opts: AuthnOptions,
        db: Arc<dyn Db + Send + Sync>,
        clock: Arc<dyn Clock + Send + Sync>,
        realm: &'static str,
    ) -> Self {
        TestContext::setup_with_hooks(opts, db, clock, realm, AuthnNoHooks).await
    }
}

impl<H: AuthnHooks> TestContext<H> {
    /// Initializes the test context using the given already-initialized objects and custom hooks.
    pub(crate) async fn setup_with_hooks(
        opts: AuthnOptions,
        db: Arc<dyn Db + Send + Sync>,
        clock: Arc<dyn Clock + Send + Sync>,
        realm: &'static str,
        hooks: H,
    ) -> Self {
        db::init_schema(&mut db.ex().await.unwrap()).await.unwrap();
        let mailer = Arc::from(RecorderSmtpMailer::default());
        let base_urls = Arc::from(BaseUrls::from_strs(
            "http://localhost:1234/",
            Some("http://no-frontend.example.com"),
        ));
        let driver = AuthnDriver::new(
            db,
            clock.clone(),
            mailer.clone(),
            make_test_activation_template(),
            base_urls,
            realm,
            opts,
            hooks,
        );

        #[cfg(not(test))]
        let context = TestContext { mailer, driver };
        #[cfg(test)]
        let context = TestContext { clock, mailer, driver };
        context
    }

    /// Syntactic sugar to create a user ifor testing purposes.
    pub async fn create_active_user(&self, username: &Username) {
        let password = password!("test0password");

        let email = EmailAddress::new(format!("{}@example.com", username.as_str())).unwrap();
        self.driver
            .clone()
            .signup(username.clone(), password.clone(), email.clone(), H::SignupInput::default())
            .await
            .unwrap();
        let activation_code =
            get_latest_activation_code(&self.mailer, &email, username).await.unwrap();
        self.driver.clone().activate(username.clone(), activation_code).await.unwrap();
    }

    /// Syntactic sugar to create and log a user in for testing purposes.
    pub async fn do_test_login(&self, username: Username) -> AccessToken {
        let password = password!("test0password");
        self.create_active_user(&username).await;

        let (response, _output) = self.driver.clone().login(username, password).await.unwrap();
        response.take_access_token()
    }

    /// Gets access to the database used by this test context.
    #[cfg(test)]
    pub(crate) fn db(&self) -> &dyn Db {
        self.driver.db.as_ref()
    }

    /// Gets a direct executor against the database.
    #[cfg(test)]
    pub(crate) async fn ex(&self) -> Executor {
        self.driver.db.ex().await.unwrap()
    }

    /// Gets a copy of the driver in this test context.
    pub fn driver(&self) -> AuthnDriver<H> {
        self.driver.clone()
    }

    /// Gets the latest activation code sent to `email` which, if any, should be for the username
    /// given in `exp_username`.
    #[cfg(test)]
    pub(crate) async fn get_latest_activation_code(
        &self,
        email: &EmailAddress,
        exp_username: &Username,
    ) -> Option<u64> {
        get_latest_activation_code(&self.mailer, email, exp_username).await
    }

    /// Returns "now" with an offset in seconds, which can be positive or negative.
    #[cfg(test)]
    pub(crate) fn now_delta(&self, secs: i64) -> OffsetDateTime {
        if secs > 0 {
            self.clock.now_utc() + Duration::from_secs(secs as u64)
        } else {
            self.clock.now_utc() - Duration::from_secs((-secs) as u64)
        }
    }
}

#[cfg(test)]
#[derive(Clone, Default)]
pub(super) struct FailingLoginHook;

#[cfg(test)]
#[async_trait]
impl AuthnHooks for FailingLoginHook {
    type LoginOutput = NoExtensions;

    async fn login_hook(
        &self,
        _tx: &mut iii_iv_core::db::TxExecutor,
        _now: OffsetDateTime,
        _user: &crate::model::User,
    ) -> DriverResult<Self::LoginOutput> {
        Err(DriverError::BackendError("hook-failure-test".into()))
    }

    type SignupInput = NoExtensions;

    async fn signup_hook(
        &self,
        _tx: &mut iii_iv_core::db::TxExecutor,
        _now: OffsetDateTime,
        _user: &crate::model::User,
        _input: Self::SignupInput,
    ) -> DriverResult<()> {
        Ok(())
    }
}

#[cfg(test)]
#[derive(Clone, Default)]
pub(super) struct FailingSignupHook;

#[cfg(test)]
#[async_trait]
impl AuthnHooks for FailingSignupHook {
    type LoginOutput = NoExtensions;

    async fn login_hook(
        &self,
        _tx: &mut iii_iv_core::db::TxExecutor,
        _now: OffsetDateTime,
        _user: &crate::model::User,
    ) -> DriverResult<Self::LoginOutput> {
        Ok(NO_EXTENSIONS)
    }

    type SignupInput = NoExtensions;

    async fn signup_hook(
        &self,
        _tx: &mut iii_iv_core::db::TxExecutor,
        _now: OffsetDateTime,
        _user: &crate::model::User,
        _input: Self::SignupInput,
    ) -> DriverResult<()> {
        Err(DriverError::BackendError("hook-failure-test".into()))
    }
}
