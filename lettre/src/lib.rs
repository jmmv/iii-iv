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
use iii_iv_core::model::EmailAddress;
use lettre::transport::smtp::authentication::Credentials;
pub use lettre::Message;
use lettre::{AsyncSmtpTransport, AsyncTransport, Tokio1Executor};

/// Options to establish an SMTP connection.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct SmtpOptions {
    /// SMTP server to use.
    pub relay: String,

    /// Username for logging into the SMTP server.
    pub username: String,

    /// Password for logging into the SMTP server.
    #[derivative(Debug = "ignore")]
    pub password: String,
}

/// Trait to abstract the integration with the mailer.
#[async_trait]
pub trait SmtpMailer {
    /// Sends a message over SMTP.
    async fn send(&self, message: Message) -> DriverResult<()>;
}

/// Mailer backed by a real SMTP connection using `lettre`.
#[derive(Clone)]
pub struct LettreSmtpMailer {
    /// SMTP transport.
    mailer: AsyncSmtpTransport<Tokio1Executor>,
}

#[async_trait]
impl SmtpMailer for LettreSmtpMailer {
    async fn send(&self, message: Message) -> DriverResult<()> {
        self.mailer
            .send(message)
            .await
            .map_err(|e| DriverError::BackendError(format!("SMTP communication failed: {}", e)))?;
        Ok(())
    }
}

/// A `Messenger` that talks to an SMTP server to send human-readable messages to users.
#[derive(Clone)]
pub struct SmtpMessenger<M>
where
    M: SmtpMailer + Clone + Send + Sync,
{
    /// Abstract mailer.
    mailer: M,
}

impl<M> SmtpMessenger<M>
where
    M: SmtpMailer + Clone + Send + Sync,
{
    /// Establishes a connection to the SMTP server.
    pub fn connect(opts: SmtpOptions) -> SmtpMessenger<LettreSmtpMailer> {
        let creds = Credentials::new(opts.username, opts.password);
        let mailer = AsyncSmtpTransport::<Tokio1Executor>::relay(&opts.relay)
            .unwrap()
            .credentials(creds)
            .build();
        let mailer = LettreSmtpMailer { mailer };
        SmtpMessenger { mailer }
    }

    /// Creates an email message from the given parts.
    pub async fn send(
        &self,
        from: &str,
        reply_to: &str,
        to: &EmailAddress,
        subject: &str,
        body: String,
    ) -> DriverResult<()> {
        let message = Message::builder()
            .from(from.parse().unwrap())
            .reply_to(reply_to.parse().unwrap())
            .to(to.as_str().parse().unwrap())
            .subject(subject)
            .body(body)
            .unwrap();
        self.mailer.send(message).await
    }
}

/// Test utilities for email handling.
#[cfg(feature = "testutils")]
pub mod testutils {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// Mailer that captures outgoing messages.
    #[derive(Clone)]
    pub struct RecorderSmtpMailer {
        /// Storage for captured messages.
        pub messages: Arc<Mutex<Vec<Message>>>,
    }

    #[async_trait]
    impl SmtpMailer for RecorderSmtpMailer {
        async fn send(&self, message: Message) -> DriverResult<()> {
            let mut messages = self.messages.lock().unwrap();
            messages.push(message);
            Ok(())
        }
    }

    /// Creates a mock messenger for testing purposes.
    pub fn setup() -> (Arc<Mutex<Vec<Message>>>, SmtpMessenger<RecorderSmtpMailer>) {
        let messages = Arc::from(Mutex::from(vec![]));
        let mailer = RecorderSmtpMailer { messages: messages.clone() };
        let messenger = SmtpMessenger { mailer };
        (messages, messenger)
    }
}
