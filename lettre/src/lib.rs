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

//! Utilities to send messages over email.

// Keep these in sync with other top-level files.
#![warn(anonymous_parameters, bad_style, clippy::missing_docs_in_private_items, missing_docs)]
#![warn(unused, unused_extern_crates, unused_import_braces, unused_qualifications)]
#![warn(unsafe_code)]

use async_trait::async_trait;
use derivative::Derivative;
use iii_iv_core::driver::{DriverError, DriverResult};
use iii_iv_core::env::get_required_var;
pub use lettre::message::{Mailbox, Message};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Tokio1Executor};

/// Options to establish an SMTP connection.
#[derive(Derivative)]
#[derivative(Debug)]
#[cfg_attr(test, derivative(PartialEq))]
pub struct SmtpOptions {
    /// SMTP server to use.
    pub relay: String,

    /// Username for logging into the SMTP server.
    pub username: String,

    /// Password for logging into the SMTP server.
    #[derivative(Debug = "ignore")]
    pub password: String,
}

impl SmtpOptions {
    /// Initializes a set of options from environment variables whose name is prefixed with the
    /// given `prefix`.
    ///
    /// This will use variables such as `<prefix>_RELAY`, `<prefix>_USERNAME` and
    /// `<prefix>_PASSWORD`.
    pub fn from_env(prefix: &str) -> Result<Self, String> {
        Ok(Self {
            relay: get_required_var::<String>(prefix, "RELAY")?,
            username: get_required_var::<String>(prefix, "USERNAME")?,
            password: get_required_var::<String>(prefix, "PASSWORD")?,
        })
    }
}

/// Trait to abstract the integration with the mailer.
#[async_trait]
pub trait SmtpMailer {
    /// Sends a message over SMTP.
    async fn send(&self, message: Message) -> DriverResult<()>;
}

/// Mailer backed by a real SMTP connection using `lettre`.
#[derive(Clone)]
pub struct LettreSmtpMailer(AsyncSmtpTransport<Tokio1Executor>);

impl LettreSmtpMailer {
    /// Establishes a connection to the SMTP server.
    pub fn connect(opts: SmtpOptions) -> Result<Self, String> {
        let creds = Credentials::new(opts.username, opts.password);
        let mailer = AsyncSmtpTransport::<Tokio1Executor>::relay(&opts.relay)
            .map_err(|e| format!("{}", e))?
            .credentials(creds)
            .build();
        Ok(LettreSmtpMailer(mailer))
    }
}

#[async_trait]
impl SmtpMailer for LettreSmtpMailer {
    async fn send(&self, message: Message) -> DriverResult<()> {
        self.0
            .send(message)
            .await
            .map_err(|e| DriverError::BackendError(format!("SMTP communication failed: {}", e)))?;
        Ok(())
    }
}

/// Test utilities for email handling.
#[cfg(any(test, feature = "testutils"))]
pub mod testutils {
    use super::*;
    use futures::lock::Mutex;
    use iii_iv_core::model::EmailAddress;
    use std::collections::{HashMap, HashSet};
    use std::sync::Arc;

    /// Given an SMTP `message`, parses it and extracts its headers and body.
    pub fn parse_message(message: &Message) -> (HashMap<String, String>, String) {
        let text = String::from_utf8(message.formatted()).unwrap();
        let (raw_headers, encoded_body) = text
            .split_once("\r\n\r\n")
            .unwrap_or_else(|| panic!("Message seems to have the wrong format: {}", text));

        let mut headers = HashMap::default();
        for raw_header in raw_headers.split("\r\n") {
            let (key, value) = raw_header
                .split_once(": ")
                .unwrap_or_else(|| panic!("Header seems to have the wrong format: {}", raw_header));
            let previous = headers.insert(key.to_owned(), value.to_owned());
            assert!(previous.is_none(), "Duplicate header {}", raw_header);
        }

        let decoded_body =
            quoted_printable::decode(encoded_body, quoted_printable::ParseMode::Strict).unwrap();
        let body = String::from_utf8(decoded_body).unwrap().replace("\r\n", "\n");

        (headers, body)
    }

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
            assert_eq!(
                1,
                messages.len(),
                "Expected to find just one message for {}",
                exp_to.as_str()
            );
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutils::*;
    use iii_iv_core::model::EmailAddress;
    use std::{env, panic::catch_unwind};

    #[test]
    pub fn test_smtp_options_from_env_all_present() {
        let overrides = [
            ("SMTP_RELAY", Some("the-relay")),
            ("SMTP_USERNAME", Some("the-username")),
            ("SMTP_PASSWORD", Some("the-password")),
        ];
        temp_env::with_vars(overrides, || {
            let opts = SmtpOptions::from_env("SMTP").unwrap();
            assert_eq!(
                SmtpOptions {
                    relay: "the-relay".to_owned(),
                    username: "the-username".to_owned(),
                    password: "the-password".to_owned()
                },
                opts
            );
        });
    }

    #[test]
    pub fn test_smtp_options_from_env_missing() {
        let overrides = [
            ("MISSING_RELAY", Some("the-relay")),
            ("MISSING_USERNAME", Some("the-username")),
            ("MISSING_PASSWORD", Some("the-password")),
        ];
        for (var, _) in overrides {
            temp_env::with_vars(overrides, || {
                env::remove_var(var);
                let err = SmtpOptions::from_env("MISSING").unwrap_err();
                assert!(err.contains(&format!("{} not present", var)));
            });
        }
    }

    #[tokio::test]
    pub async fn test_parse_message() {
        let exp_body = "
This is a sample message with a line that should be longer than 72 characters to test line wraps.

There is also a second paragraph with = quoted printable characters.
";
        let message = Message::builder()
            .from("From someone <from@example.com>".parse().unwrap())
            .to("to@example.com".parse().unwrap())
            .subject("This: is the: subject line")
            .body(exp_body.to_owned())
            .unwrap();

        // Make sure the encoding of the message is quoted-printable.  This isn't strictly required
        // because I suppose `parse_message` might succeed anyway, but it's good to encode our
        // assumption in a test.
        let text = String::from_utf8(message.formatted()).unwrap();
        assert!(text.contains("=3D"));

        let (headers, body) = parse_message(&message);

        assert!(headers.len() >= 3);
        assert_eq!("\"From someone\" <from@example.com>", headers.get("From").unwrap());
        assert_eq!("to@example.com", headers.get("To").unwrap());
        assert_eq!("This: is the: subject line", headers.get("Subject").unwrap());

        assert_eq!(exp_body, body);
    }

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
    pub async fn test_recorder_inject_error() {
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
    pub async fn test_recorder_expect_one_inbox_ok() {
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
    pub fn test_recorder_expect_one_inbox_too_many_recipients() {
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
    pub async fn test_recorder_expect_one_message_ok() {
        let to = EmailAddress::from("to@example.com");
        let message = new_message(&to);
        let exp_formatted = message.formatted();

        let mailer = RecorderSmtpMailer::default();
        mailer.send(message).await.unwrap();

        assert_eq!(exp_formatted, mailer.expect_one_message(&to).await.formatted());
    }

    #[test]
    pub fn test_recorder_expect_one_message_too_many_recipients() {
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
    pub fn test_recorder_expect_one_message_too_many_messages() {
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
