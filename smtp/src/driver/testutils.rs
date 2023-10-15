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

//! Test utilities for email handling.

use crate::driver::SmtpMailer;
use async_trait::async_trait;
use futures::lock::Mutex;
use iii_iv_core::driver::{DriverError, DriverResult};
use iii_iv_core::model::EmailAddress;
use lettre::Message;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

#[cfg(test)]
use {
    super::SmtpDriver,
    crate::db::init_schema,
    iii_iv_core::clocks::testutils::SettableClock,
    iii_iv_core::db::{sqlite, Db, Executor},
    time::macros::datetime,
};

/// Mailer that captures outgoing messages.
#[derive(Clone, Default)]
pub struct RecorderSmtpMailer {
    /// Storage for captured messages.
    pub inboxes: Arc<Mutex<HashMap<EmailAddress, Vec<Message>>>>,

    /// Addresses for which to fail sending a message to.
    errors: Arc<Mutex<HashSet<EmailAddress>>>,
}

impl RecorderSmtpMailer {
    /// Makes trying to send errors to `email` fail with an error.
    pub async fn inject_error_for<E: Into<EmailAddress>>(&self, email: E) {
        let mut errors = self.errors.lock().await;
        errors.insert(email.into());
    }

    /// Expects that no messages were sent.
    pub async fn expect_no_messages(&self) {
        let inboxes = self.inboxes.lock().await;
        assert_eq!(0, inboxes.len(), "Expected to find no messages");
    }

    /// Expects that messages were sent to `exp_to` and nobody else, and returns the list of
    /// messages to that recipient.
    pub async fn expect_one_inbox(&self, exp_to: &EmailAddress) -> Vec<Message> {
        let inboxes = self.inboxes.lock().await;
        assert_eq!(1, inboxes.len(), "Expected to find just one message in one inbox");
        let (to, messages) = inboxes.iter().next().unwrap();
        assert_eq!(exp_to, to);
        messages.clone()
    }

    /// Expects that only one message was sent to `exp_to` and nobody else, and returns the
    /// message.
    pub async fn expect_one_message(&self, exp_to: &EmailAddress) -> Message {
        let mut messages = self.expect_one_inbox(exp_to).await;
        assert_eq!(1, messages.len(), "Expected to find just one message for {}", exp_to.as_str());
        messages.pop().unwrap()
    }
}

#[async_trait]
impl SmtpMailer for RecorderSmtpMailer {
    async fn send(&self, message: Message) -> DriverResult<()> {
        let to = EmailAddress::from(
            message.headers().get_raw("To").expect("To header must have been present"),
        );

        {
            let errors = self.errors.lock().await;
            if errors.contains(&to) {
                return Err(DriverError::BackendError(format!(
                    "Sending email to {} failed",
                    to.as_str()
                )));
            }
        }

        let mut inboxes = self.inboxes.lock().await;
        inboxes.entry(to).or_insert_with(Vec::default).push(message);
        Ok(())
    }
}

/// Container for the state required to run a driver test.
#[cfg(test)]
pub(crate) struct TestContext {
    pub(crate) driver: SmtpDriver<RecorderSmtpMailer>,
    pub(crate) db: Arc<dyn Db + Send + Sync>,
    pub(crate) clock: Arc<SettableClock>,
    pub(crate) mailer: RecorderSmtpMailer,
}

#[cfg(test)]
impl TestContext {
    pub(crate) async fn setup(max_daily_emails: Option<usize>) -> Self {
        let _can_fail = env_logger::builder().is_test(true).try_init();

        let db = Arc::from(sqlite::testutils::setup().await);
        let mut ex = db.ex().await.unwrap();
        init_schema(&mut ex).await.unwrap();

        let clock = Arc::from(SettableClock::new(datetime!(2023-10-17 06:00:00 UTC)));

        let mailer = RecorderSmtpMailer::default();

        let driver = SmtpDriver {
            transport: mailer.clone(),
            db: db.clone(),
            clock: clock.clone(),
            max_daily_emails,
        };

        Self { driver, db, clock, mailer }
    }

    pub(crate) async fn ex(&mut self) -> Executor {
        self.db.ex().await.unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iii_iv_core::model::EmailAddress;
    use std::panic::catch_unwind;

    /// Creates a new message where the only thing that matters is toe `to` field.
    fn new_message(to: &EmailAddress) -> Message {
        Message::builder()
            .from("from@example.com".parse().unwrap())
            .to(to.as_str().parse().unwrap())
            .subject("Test")
            .body("Body".to_owned())
            .unwrap()
    }

    #[tokio::test]
    async fn test_recorder_inject_error() {
        let to1 = EmailAddress::from("to1@example.com");
        let to2 = EmailAddress::from("to2@example.com");
        let to3 = EmailAddress::from("to3@example.com");

        let mailer = RecorderSmtpMailer::default();
        mailer.inject_error_for(to2.clone()).await;

        mailer.send(new_message(&to1)).await.unwrap();
        mailer.send(new_message(&to2)).await.unwrap_err();
        mailer.send(new_message(&to3)).await.unwrap();

        let inboxes = mailer.inboxes.lock().await;
        assert!(inboxes.contains_key(&to1));
        assert!(!inboxes.contains_key(&to2));
        assert!(inboxes.contains_key(&to3));
    }

    #[tokio::test]
    async fn test_recorder_expect_no_messages_ok() {
        let mailer = RecorderSmtpMailer::default();
        mailer.expect_no_messages().await;
    }

    #[tokio::test]
    async fn test_recorder_expect_no_messages_fail() {
        #[tokio::main(flavor = "current_thread")]
        async fn do_test() {
            let to1 = EmailAddress::from("to1@example.com");
            let mailer = RecorderSmtpMailer::default();
            mailer.send(new_message(&to1)).await.unwrap();
            mailer.expect_no_messages().await; // Will panic.
        }
        assert!(catch_unwind(do_test).is_err());
    }

    #[tokio::test]
    async fn test_recorder_expect_one_inbox_ok() {
        let to = EmailAddress::from("to@example.com");
        let message = new_message(&to);
        let exp_formatted = message.formatted();

        let mailer = RecorderSmtpMailer::default();
        mailer.send(message.clone()).await.unwrap();
        mailer.send(message).await.unwrap();

        let messages = mailer.expect_one_inbox(&to).await;
        assert_eq!(
            vec![exp_formatted.clone(), exp_formatted],
            messages.iter().map(Message::formatted).collect::<Vec<Vec<u8>>>(),
        );
    }

    #[test]
    fn test_recorder_expect_one_inbox_too_many_recipients() {
        #[tokio::main(flavor = "current_thread")]
        async fn do_test() {
            let to1 = EmailAddress::from("to1@example.com");
            let to2 = EmailAddress::from("to2@example.com");

            let mailer = RecorderSmtpMailer::default();
            mailer.send(new_message(&to1)).await.unwrap();
            mailer.send(new_message(&to2)).await.unwrap();

            let _ = mailer.expect_one_inbox(&to1).await; // Will panic.
        }
        assert!(catch_unwind(do_test).is_err());
    }

    #[tokio::test]
    async fn test_recorder_expect_one_message_ok() {
        let to = EmailAddress::from("to@example.com");
        let message = new_message(&to);
        let exp_formatted = message.formatted();

        let mailer = RecorderSmtpMailer::default();
        mailer.send(message).await.unwrap();

        assert_eq!(exp_formatted, mailer.expect_one_message(&to).await.formatted());
    }

    #[test]
    fn test_recorder_expect_one_message_too_many_recipients() {
        #[tokio::main(flavor = "current_thread")]
        async fn do_test() {
            let to1 = EmailAddress::from("to1@example.com");
            let to2 = EmailAddress::from("to2@example.com");

            let mailer = RecorderSmtpMailer::default();
            mailer.send(new_message(&to1)).await.unwrap();
            mailer.send(new_message(&to2)).await.unwrap();

            let _ = mailer.expect_one_message(&to1).await; // Will panic.
        }
        assert!(catch_unwind(do_test).is_err());
    }

    #[test]
    fn test_recorder_expect_one_message_too_many_messages() {
        #[tokio::main(flavor = "current_thread")]
        async fn do_test() {
            let to = EmailAddress::from("to@example.com");

            let mailer = RecorderSmtpMailer::default();
            mailer.send(new_message(&to)).await.unwrap();
            mailer.send(new_message(&to)).await.unwrap();

            let _ = mailer.expect_one_message(&to).await; // Will panic.
        }
        assert!(catch_unwind(do_test).is_err());
    }
}
