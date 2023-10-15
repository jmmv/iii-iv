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

use async_trait::async_trait;
use derivative::Derivative;
use iii_iv_core::driver::{DriverError, DriverResult};
use iii_iv_core::env::get_required_var;
pub use lettre::message::{Mailbox, Message};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Tokio1Executor};

#[cfg(any(test, feature = "testutils"))]
pub mod testutils;

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_smtp_options_from_env_all_present() {
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
    fn test_smtp_options_from_env_missing() {
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
}
