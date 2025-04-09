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

use crate::db::{count_email_log, put_email_log, update_email_log};
use async_trait::async_trait;
use derivative::Derivative;
use iii_iv_core::clocks::Clock;
use iii_iv_core::db::Db;
use iii_iv_core::driver::{DriverError, DriverResult};
use iii_iv_core::env::{get_optional_var, get_required_var};
use lettre::message::Message;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Tokio1Executor};
use std::sync::Arc;

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

    /// Maximum number of messages to send per day, if any.
    pub max_daily_emails: Option<usize>,
}

impl SmtpOptions {
    /// Initializes a set of options from environment variables whose name is prefixed with the
    /// given `prefix`.
    ///
    /// This will use variables such as `<prefix>_RELAY`, `<prefix>_USERNAME`, `<prefix>_PASSWORD`
    /// and `<prefix>_MAX_DAILY_EMAILS`.
    pub fn from_env(prefix: &str) -> Result<Self, String> {
        Ok(Self {
            relay: get_required_var::<String>(prefix, "RELAY")?,
            username: get_required_var::<String>(prefix, "USERNAME")?,
            password: get_required_var::<String>(prefix, "PASSWORD")?,
            max_daily_emails: get_optional_var::<usize>(prefix, "MAX_DAILY_EMAILS")?,
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
    fn connect(relay: &str, username: String, password: String) -> Result<Self, String> {
        let creds = Credentials::new(username, password);
        let mailer = AsyncSmtpTransport::<Tokio1Executor>::relay(relay)
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

/// Encapsulates logic to send email messages while respecting quotas.
#[derive(Clone)]
pub struct SmtpDriver<T> {
    /// The SMTP transport with which to send email messages.
    transport: T,

    /// The database with which to track sent messages.
    db: Arc<dyn Db + Send + Sync>,

    /// The clock from which to obtain the current time.
    clock: Arc<dyn Clock + Send + Sync>,

    /// Maximum number of messages to send per day, if any.
    max_daily_emails: Option<usize>,
}

impl<T> SmtpDriver<T> {
    /// Creates a new driver with the given values.
    pub fn new(
        transport: T,
        db: Arc<dyn Db + Send + Sync>,
        clock: Arc<dyn Clock + Send + Sync>,
        max_daily_emails: Option<usize>,
    ) -> Self {
        Self { transport, db, clock, max_daily_emails }
    }

    /// Obtains a reference to the wrapped SMTP transport.
    pub fn get_transport(&self) -> &T {
        &self.transport
    }
}

#[async_trait]
impl<T> SmtpMailer for SmtpDriver<T>
where
    T: SmtpMailer + Send + Sync,
{
    /// Sends an email message after recording it and accounting for it for quota purposes.
    async fn send(&self, message: Message) -> DriverResult<()> {
        let mut tx = self.db.begin().await?;
        let now = self.clock.now_utc();

        // We must insert into the table first, before counting, to grab an exclusive transaction
        // lock.  Otherwise the count will be stale by the time we use it.
        let id = put_email_log(tx.ex(), &message, now).await?;

        if let Some(max_daily_emails) = self.max_daily_emails {
            let daily_emails = count_email_log(tx.ex(), now.date()).await? - 1;
            if daily_emails >= max_daily_emails {
                let msg = format!(
                    "Too many emails sent today ({} >= {})",
                    daily_emails, max_daily_emails,
                );
                update_email_log(tx.ex(), id, &msg).await?;
                return Err(DriverError::NoSpace(msg));
            }
        }

        // Commit the transaction _before_ trying to send the email.  This is intentional to ignore
        // errors from the server because we don't know if errors are counted towards the daily
        // quota.  Furthermore, this avoids sequencing email submissions if the server is slow.
        tx.commit().await?;

        let result = self.transport.send(message).await;

        match result {
            Ok(()) => update_email_log(&mut self.db.ex().await?, id, "OK").await?,
            Err(ref e) => update_email_log(&mut self.db.ex().await?, id, &format!("{}", e)).await?,
        }

        result
    }
}

/// Creates a new SMTP driver that sends email messages via the service configured in `opts`.
///
/// `db` and `clock` are used to keep track of the messages that have been sent for quota
/// accounting purposes.
pub fn new_prod_driver(
    opts: SmtpOptions,
    db: Arc<dyn Db + Send + Sync>,
    clock: Arc<dyn Clock + Send + Sync>,
) -> Result<SmtpDriver<LettreSmtpMailer>, String> {
    let transport = LettreSmtpMailer::connect(&opts.relay, opts.username, opts.password)?;
    Ok(SmtpDriver::new(transport, db, clock, opts.max_daily_emails))
}

#[cfg(test)]
mod tests {
    use super::testutils::*;
    use super::*;
    use crate::db::get_email_log;
    use futures::future;
    use std::time::Duration;

    #[test]
    fn test_smtp_options_from_env_all_required_present() {
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
                    password: "the-password".to_owned(),
                    max_daily_emails: None,
                },
                opts
            );
        });
    }

    #[test]
    fn test_smtp_options_from_env_all_required_and_optional_present() {
        let overrides = [
            ("SMTP_RELAY", Some("the-relay")),
            ("SMTP_USERNAME", Some("the-username")),
            ("SMTP_PASSWORD", Some("the-password")),
            ("SMTP_MAX_DAILY_EMAILS", Some("123")),
        ];
        temp_env::with_vars(overrides, || {
            let opts = SmtpOptions::from_env("SMTP").unwrap();
            assert_eq!(
                SmtpOptions {
                    relay: "the-relay".to_owned(),
                    username: "the-username".to_owned(),
                    password: "the-password".to_owned(),
                    max_daily_emails: Some(123),
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
            // Keep all variables except one.
            let mut overrides = overrides;
            for (k, v) in &mut overrides {
                if *k == var {
                    *v = None::<&str>;
                }
            }

            temp_env::with_vars(overrides, || {
                let err = SmtpOptions::from_env("MISSING").unwrap_err();
                assert!(err.contains(&format!("{} not present", var)));
            });
        }
    }

    /// Creates a new email message with hardcoded values.
    fn new_message() -> Message {
        Message::builder()
            .from("from@example.com".parse().unwrap())
            .to("to@example.com".parse().unwrap())
            .subject("Foo")
            .body("Bar".to_owned())
            .unwrap()
    }

    #[tokio::test]
    async fn test_send_ok() {
        let mut context = TestContext::setup(None).await;
        let exp_message = new_message();

        context.driver.send(exp_message.clone()).await.unwrap();

        let message = context.mailer.expect_one_message(&"to@example.com".into()).await;
        assert_eq!(exp_message.formatted(), message.formatted());

        let log = get_email_log(&mut context.ex().await).await.unwrap();
        assert_eq!(1, log.len());
        assert_eq!(exp_message.formatted(), log[0].1);
        assert_eq!(Some("OK"), log[0].2.as_deref());
    }

    #[tokio::test]
    async fn test_send_error() {
        let mut context = TestContext::setup(None).await;
        let exp_message = new_message();

        context.mailer.inject_error_for("to@example.com").await;
        let err = context.driver.send(exp_message.clone()).await.unwrap_err();
        assert_eq!("Sending email to to@example.com failed", &format!("{}", err));

        context.mailer.expect_no_messages().await;

        let log = get_email_log(&mut context.ex().await).await.unwrap();
        assert_eq!(1, log.len());
        assert_eq!(exp_message.formatted(), log[0].1);
        assert_eq!(Some("Sending email to to@example.com failed"), log[0].2.as_deref());
    }

    #[tokio::test]
    async fn test_daily_limit_enforced_and_clears_every_day() {
        let mut context = TestContext::setup(Some(50)).await;
        let exp_message = new_message();

        for _ in 0..50 {
            put_email_log(&mut context.ex().await, &exp_message, context.clock.now_utc())
                .await
                .unwrap();
        }

        let err = context.driver.send(exp_message.clone()).await.unwrap_err();
        assert_eq!("Too many emails sent today (50 >= 50)", &format!("{}", err));
        context.mailer.expect_no_messages().await;

        // Advance the clock to reach just the 23rd hour of the same day.
        let current_hour = u64::from(context.clock.now_utc().hour());
        context.clock.advance(Duration::from_secs((23 - current_hour) * 60 * 60));

        let err = context.driver.send(exp_message.clone()).await.unwrap_err();
        assert_eq!("Too many emails sent today (50 >= 50)", &format!("{}", err));
        context.mailer.expect_no_messages().await;

        // Push the clock into the next day.
        context.clock.advance(Duration::from_secs(60 * 60));

        context.driver.send(exp_message.clone()).await.unwrap();
        let message = context.mailer.expect_one_message(&"to@example.com".into()).await;
        assert_eq!(exp_message.formatted(), message.formatted());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_daily_limit_concurrency() {
        let context = TestContext::setup(Some(10)).await;
        let exp_message = new_message();

        let mut futures = Vec::with_capacity(1000);
        for _ in 0..1000 {
            futures.push(async {
                match context.driver.send(exp_message.clone()).await {
                    Ok(()) => true,
                    Err(_) => false,
                }
            });
        }

        let mut count_ok = 0;
        let mut count_err = 0;
        for ok in future::join_all(futures.into_iter()).await {
            if ok {
                count_ok += 1;
            } else {
                count_err += 1;
            }
        }
        assert_eq!(10, count_ok);
        assert_eq!(990, count_err);

        let inbox = context.mailer.expect_one_inbox(&"to@example.com".into()).await;
        assert_eq!(10, inbox.len());
    }
}
