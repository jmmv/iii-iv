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

use crate::db::SqliteAuthnTx;
use crate::driver::email::Messenger;
use crate::driver::{AuthnDriver, DriverResult};
use crate::model::{AccessToken, Password};
use async_trait::async_trait;
use iii_iv_core::clocks::testutils::MonotonicClock;
use iii_iv_core::db::Db;
use iii_iv_core::model::EmailAddress;
use iii_iv_core::model::Username;
use iii_iv_sqlite::SqliteDb;
use std::collections::HashMap;
use std::str;
use std::sync::{Arc, Mutex};

use super::AuthnOptions;

/// Representation of possible email message types.
enum MockEmailMessage {
    /// A message with the arguments given to `send_activation_code`.
    ActivationCode(String, Username, u32),
}

/// A `Messenger` that captures the last message sent to every email address.
#[derive(Clone, Default)]
pub(crate) struct MockMessenger {
    /// Mapping of the last email message sent to each email address.
    inboxes: Arc<Mutex<HashMap<EmailAddress, MockEmailMessage>>>,
}

impl MockMessenger {
    /// Gets the latest activation code sent to `email` which, if any, should be for the username
    /// given in `exp_username`.
    pub(crate) fn get_latest_activation_code(
        &self,
        exp_base_url: &str,
        email: &EmailAddress,
        exp_username: &Username,
    ) -> Option<u32> {
        let inboxes = self.inboxes.lock().unwrap();
        if let Some(message) = inboxes.get(email) {
            match message {
                MockEmailMessage::ActivationCode(base_url, username, code) => {
                    assert_eq!(exp_base_url, base_url);
                    assert_eq!(exp_username, username);
                    return Some(*code);
                }
            }
        }
        None
    }
}

#[async_trait]
impl Messenger for MockMessenger {
    async fn send_activation_code(
        &self,
        base_url: &str,
        username: &Username,
        email: &EmailAddress,
        code: u32,
    ) -> DriverResult<()> {
        let mut inboxes = self.inboxes.lock().unwrap();
        inboxes
            .entry(email.clone())
            .and_modify(|e| {
                *e = MockEmailMessage::ActivationCode(base_url.to_owned(), username.clone(), code)
            })
            .or_insert_with(|| {
                MockEmailMessage::ActivationCode(base_url.to_owned(), username.clone(), code)
            });
        Ok(())
    }
}

/// Driver parameterized with mocks and stubs for testing.
pub(crate) type TestDriver = AuthnDriver<MonotonicClock, SqliteDb<SqliteAuthnTx>, MockMessenger>;

/// State of a running test.
pub(crate) struct TestContext {
    db: SqliteDb<SqliteAuthnTx>,
    messenger: MockMessenger,
    driver: TestDriver,
}

impl TestContext {
    /// Initializes the driver using an in-memory database, a monotonic clock and a mock
    /// messenger that captures outgoing notifications.
    pub(crate) async fn setup() -> Self {
        let db = iii_iv_sqlite::testutils::setup().await;
        let clock = MonotonicClock::new(100000);
        let messenger = MockMessenger::default();
        let driver = AuthnDriver::new(
            db.clone(),
            clock,
            messenger.clone(),
            "http://localhost:1234/".to_owned(),
            "the-realm",
            AuthnOptions::default(),
        );

        TestContext { db, messenger, driver }
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
        let activation_code = self
            .messenger
            .get_latest_activation_code("http://localhost:1234/", &email, &username)
            .unwrap();
        self.driver.clone().activate(username.clone(), activation_code).await.unwrap();

        let response = self.driver.clone().login(username, password).await.unwrap();
        response.take_access_token()
    }

    /// Gets direct access to the database backing this test context.
    pub(crate) async fn tx(&self) -> SqliteAuthnTx {
        self.db.begin().await.unwrap()
    }

    /// Gets a copy of the driver in this test context.
    pub(crate) fn driver(&self) -> TestDriver {
        self.driver.clone()
    }

    /// Gets the latest activation code sent to `email` which, if any, should be for the username
    /// given in `exp_username`.
    pub(crate) fn get_latest_activation_code(
        &self,
        email: &EmailAddress,
        exp_username: &Username,
    ) -> Option<u32> {
        self.messenger.get_latest_activation_code("http://localhost:1234/", email, exp_username)
    }
}
