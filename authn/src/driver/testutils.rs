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

use crate::db;
use crate::driver::email::testutils::{get_latest_activation_code, make_test_activation_template};
use crate::driver::{AuthnDriver, AuthnOptions};
use crate::model::{AccessToken, Password};
use iii_iv_core::clocks::testutils::MonotonicClock;
use iii_iv_core::db::Db;
use iii_iv_core::model::EmailAddress;
use iii_iv_core::model::Username;
use iii_iv_core::rest::BaseUrls;
use iii_iv_lettre::testutils::RecorderSmtpMailer;
use std::sync::Arc;

/// State of a running test.
pub(crate) struct TestContext {
    pub(crate) db: Arc<dyn Db + Send + Sync>,
    mailer: Arc<RecorderSmtpMailer>,
    driver: AuthnDriver,
}

impl TestContext {
    /// Initializes the driver using an in-memory database, a monotonic clock and a mock
    /// messenger that captures outgoing notifications.
    pub(crate) async fn setup() -> Self {
        let db = Arc::from(iii_iv_core::db::sqlite::testutils::setup().await);
        db::init_schema(&mut db.ex()).await.unwrap();
        let clock = Arc::from(MonotonicClock::new(100000));
        let mailer = Arc::from(RecorderSmtpMailer::default());
        let base_urls = Arc::from(BaseUrls::from_strs(
            "http://localhost:1234/",
            Some("http://no-frontend.example.com"),
        ));
        let driver = AuthnDriver::new(
            db.clone(),
            clock,
            mailer.clone(),
            make_test_activation_template(),
            base_urls,
            "the-realm",
            AuthnOptions::default(),
        );

        TestContext { db, mailer, driver }
    }

    /// Syntactic sugar to create and log a user in for testing purposes.
    pub(crate) async fn do_test_login(&self, username: Username) -> AccessToken {
        let password = Password::from("test0password");

        let email = EmailAddress::new(format!("{}@example.com", username.as_str())).unwrap();
        self.driver
            .clone()
            .signup(username.clone(), password.clone(), email.clone())
            .await
            .unwrap();
        let activation_code =
            get_latest_activation_code(&self.mailer, &email, &username).await.unwrap();
        self.driver.clone().activate(username.clone(), activation_code).await.unwrap();

        let response = self.driver.clone().login(username, password).await.unwrap();
        response.take_access_token()
    }

    /// Gets a copy of the driver in this test context.
    pub(crate) fn driver(&self) -> AuthnDriver {
        self.driver.clone()
    }

    /// Gets the latest activation code sent to `email` which, if any, should be for the username
    /// given in `exp_username`.
    pub(crate) async fn get_latest_activation_code(
        &self,
        email: &EmailAddress,
        exp_username: &Username,
    ) -> Option<u64> {
        get_latest_activation_code(&self.mailer, email, exp_username).await
    }
}
