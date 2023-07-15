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

use crate::db::{AuthnTx, SqliteAuthnTx};
use crate::driver::email::testutils::{get_latest_activation_code, make_test_activation_template};
use crate::driver::testutils::TestDriver;
use crate::driver::{AuthnDriver, AuthnOptions};
use crate::model::{AccessToken, HashedPassword, Password, User};
use crate::rest::app;
use axum::Router;
use iii_iv_core::clocks::testutils::MonotonicClock;
use iii_iv_core::db::{BareTx, Db, DbError};
use iii_iv_core::model::{EmailAddress, Username};
use iii_iv_core::rest::BaseUrls;
use iii_iv_lettre::testutils::RecorderSmtpMailer;
use iii_iv_sqlite::SqliteDb;
use std::sync::Arc;
use time::OffsetDateTime;

/// State of a running test.
pub(crate) struct TestContext {
    app: Router,
    db: SqliteDb<SqliteAuthnTx>,
    whoami: String,
    whoami_password: Password,
    mailer: RecorderSmtpMailer,
    driver: TestDriver,
}

impl TestContext {
    /// Creates the `whoami` user by directly modifying the backing database. The user is marked
    /// as active.
    pub(crate) async fn create_whoami_user(&mut self) -> User {
        let password = self.whoami_password.clone().validate_and_hash(|_| None).unwrap();

        let mut tx = self.db.begin().await.unwrap();
        let user = User::new(self.whoami(), EmailAddress::from("whoami@example.com"))
            .with_password(password)
            .with_last_login(OffsetDateTime::from_unix_timestamp(100100).unwrap());
        tx.create_user(
            user.username().clone(),
            user.password().map(HashedPassword::clone),
            user.email().clone(),
        )
        .await
        .unwrap();
        tx.update_user(user.username().clone(), user.last_login().unwrap()).await.unwrap();
        tx.commit().await.unwrap();
        user
    }

    /// Consumes the context and transforms it into the app router.
    pub(crate) fn into_app(self) -> Router {
        self.app
    }

    /// Gets a clone of the app router.
    pub(crate) fn app(&self) -> Router {
        self.app.clone()
    }

    /// Creates the `whoami` user by directly modifying the backing database. The user is marked
    /// as inactive with a pending activation `code`.
    pub(crate) async fn create_inactive_whoami_user(&mut self, code: u32) -> User {
        let mut user = self.create_whoami_user().await;
        assert!(user.activation_code().is_none());

        let mut tx = self.db.begin().await.unwrap();
        user = tx.set_user_activation_code(user, Some(code)).await.unwrap();
        tx.commit().await.unwrap();
        user
    }

    /// Checks if the user with `username` exists by directly querying the backing database.
    pub(crate) async fn user_exists(&mut self, username: &Username) -> bool {
        let mut tx = self.db.begin().await.unwrap();
        match tx.get_user_by_username(username.clone()).await {
            Ok(_) => true,
            Err(DbError::NotFound) => false,
            Err(e) => panic!("{:?}", e),
        }
    }

    /// Checks if the user with `username` exists and is active by directly querying the backing
    /// database.
    pub(crate) async fn user_is_active(&mut self, username: &Username) -> bool {
        let mut tx = self.db.begin().await.unwrap();
        let user = tx.get_user_by_username(username.clone()).await.unwrap();
        user.activation_code().is_none()
    }

    /// Checks if the session with `token` exists by directly querying the backing database.
    pub(crate) async fn session_exists(&mut self, token: &AccessToken) -> bool {
        let mut tx = self.db.begin().await.unwrap();
        match tx.get_session(token).await {
            Ok(_) => true,
            Err(DbError::NotFound) => false,
            Err(e) => panic!("{:?}", e),
        }
    }

    /// Logs the `whoami` user in and returns its access token.
    pub(crate) async fn access_token(&self) -> AccessToken {
        let response = self
            .driver
            .clone()
            .login(Username::new(self.whoami.clone()).unwrap(), self.whoami_password.clone())
            .await
            .unwrap();
        response.take_access_token()
    }

    /// Returns the "who am I" identifier of the running test. Panics if this context was built
    /// with an invalid value using the `TestContextBuilder::with_invalid_whoami` method.
    pub(crate) fn whoami(&self) -> Username {
        Username::new(&self.whoami).expect("Cannot query invalid whoami")
    }

    /// Returns the password generated for the "who am I" user of the running test.
    pub(crate) fn whoami_password(&self) -> &Password {
        &self.whoami_password
    }

    /// Gets the latest activation code sent to `email` which, if any, should be for the username
    /// given in `exp_username`.
    pub(crate) async fn get_latest_activation_code(
        &self,
        email: &EmailAddress,
        exp_username: &Username,
    ) -> Option<u32> {
        get_latest_activation_code(&self.mailer, email, exp_username).await
    }
}

/// Builder pattern for the test context.
#[must_use]
pub(crate) struct TestContextBuilder {
    whoami: String,
    activated_template: Option<&'static str>,
}

impl TestContextBuilder {
    /// Initializes a new builder with the default test settings.
    pub(crate) fn new() -> Self {
        Self { whoami: "whoami".to_owned(), activated_template: None }
    }

    /// Overrides the default activated template.
    pub(crate) fn with_activated_template(mut self, template: &'static str) -> Self {
        self.activated_template = Some(template);
        self
    }

    /// Overrides the default test user's identifier.  The identifier needn't be valid.
    pub(crate) fn with_whoami<S: Into<String>>(mut self, whoami: S) -> Self {
        self.whoami = whoami.into();
        self
    }

    /// Sets up the test environment with the configured settings.
    pub(crate) async fn build(self) -> TestContext {
        let db = iii_iv_sqlite::testutils::setup().await;

        let clock = MonotonicClock::new(100000);

        let mailer = RecorderSmtpMailer::default();

        let driver = AuthnDriver::new(
            db.clone(),
            clock,
            mailer.clone(),
            make_test_activation_template(),
            Arc::from(BaseUrls::from_strs("http://localhost:1234/", None)),
            "the-realm",
            AuthnOptions::default(),
        );
        let app = Router::new().nest("/api/test", app(driver.clone(), self.activated_template));

        let whoami_password = Password::new(format!("random-{}", rand::random::<u32>())).unwrap();

        TestContext { app, db, whoami: self.whoami, whoami_password, mailer, driver }
    }
}
