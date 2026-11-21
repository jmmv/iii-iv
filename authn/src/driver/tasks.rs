// III-IV
// Copyright 2026 Julio Merino
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

//! Execution of authentication background tasks.

use crate::db;
use crate::driver::AuthnOptions;
use crate::driver::email::make_activation_code_message;
use crate::model::{AuthnTask, CredentialPurpose, EmailToken};
use iii_iv_core::clocks::Clock;
use iii_iv_core::db::{Db, DbError};
use iii_iv_core::rest::BaseUrlsOptions;
use iii_iv_queue::model::{ExecError, ExecResult};
use iii_iv_smtp::driver::SmtpMailer;
use iii_iv_smtp::model::EmailTemplate;
use std::sync::Arc;
use uuid::Uuid;

/// Executor for authentication background tasks.
#[derive(Clone)]
pub struct AuthnTaskRunner {
    /// Email template to use for activation emails.
    activation_template: Arc<EmailTemplate>,

    /// Application-owned recovery email and reset URL template.
    recovery_email: (Arc<EmailTemplate>, String),

    /// Base URLs of the running service.
    base_urls: Arc<BaseUrlsOptions>,

    /// Database that stores authentication state.
    db: Arc<dyn Db + Send + Sync>,

    /// Clock for credential expiration checks.
    clock: Arc<dyn Clock + Send + Sync>,

    /// Delay before retrying email deliveries.
    email_retry_delay: std::time::Duration,

    /// Service to send email notifications with.
    mailer: Arc<dyn SmtpMailer + Send + Sync>,
}

impl AuthnTaskRunner {
    /// Creates an authentication task runner backed by the given dependencies.
    ///
    /// The activation template supports `activate_url`, `email`, `user`, `user_id`, and `username`
    /// substitutions.  `user` is the username when present and the email address otherwise, while
    /// `username` is empty for username-free services.
    ///
    /// The required `recovery_email` tuple contains the plain-text email template and the frontend
    /// reset URL template.  The URL supports `user_id` and `token` substitutions, while the email
    /// supports `reset_url` and the same account substitutions as the activation template.
    pub fn new(
        db: Arc<dyn Db + Send + Sync>,
        clock: Arc<dyn Clock + Send + Sync>,
        mailer: Arc<dyn SmtpMailer + Send + Sync>,
        activation_template: EmailTemplate,
        recovery_email: (EmailTemplate, String),
        base_urls: Arc<BaseUrlsOptions>,
        opts: &AuthnOptions,
    ) -> Self {
        Self {
            activation_template: Arc::from(activation_template),
            recovery_email: (Arc::new(recovery_email.0), recovery_email.1),
            base_urls,
            db,
            clock,
            email_retry_delay: opts.email_retry_delay,
            mailer,
        }
    }

    /// Sends an account activation email if the activation request is still current.
    async fn send_activation_email(
        &self,
        user_id: Uuid,
        activation_code: EmailToken,
    ) -> ExecResult {
        let mut tx = self.db.begin().await?;
        let user = match db::lock_user(tx.ex(), user_id).await {
            Ok(user) => user,
            Err(DbError::NotFound) => {
                return Ok(Some("Skipped activation email for missing user".to_owned()));
            }
            Err(e) => return Err(e.into()),
        };

        let state = db::get_user_activation(tx.ex(), user.id).await?;
        if !state.is_some_and(|state| {
            state.code == activation_code.digest(CredentialPurpose::Activation)
                && self.clock.now_utc() < state.expires_at
        }) {
            return Ok(Some("Skipped obsolete activation email".to_owned()));
        }

        let message = make_activation_code_message(
            &self.activation_template,
            &self.base_urls,
            &user,
            activation_code,
        )
        .map_err(|e| ExecError::Failed(format!("Failed to build activation email: {}", e)))?;

        // Keep the account locked through SMTP log updates so deletion cannot leave new logs.
        let result = self.mailer.send_in_transaction(&mut tx, message).await;
        tx.commit().await?;
        result.map_err(|e| {
            ExecError::RetryAfterDelay(
                self.email_retry_delay,
                format!("Failed to send activation email: {}", e),
            )
        })?;
        Ok(None)
    }

    /// Sends the recovery link only while its credential remains usable.
    async fn send_recovery_email(&self, user_id: Uuid, token: EmailToken) -> ExecResult {
        let mut tx = self.db.begin().await?;
        let user = match db::lock_user(tx.ex(), user_id).await {
            Ok(user) => user,
            Err(DbError::NotFound) => {
                return Ok(Some("Skipped recovery email for missing user".to_owned()));
            }
            Err(error) => return Err(error.into()),
        };
        let state = db::get_email_credential(tx.ex(), user_id, CredentialPurpose::Recovery).await?;
        let Some(state) = state.filter(|state| {
            user.password.is_some()
                && state.digest == token.digest(CredentialPurpose::Recovery)
                && self.clock.now_utc() < state.expires_at
        }) else {
            return Ok(Some("Skipped obsolete recovery email".to_owned()));
        };
        let (template, url_template) = &self.recovery_email;
        let user_id = user_id.to_string();
        let url = iii_iv_core::template::apply(
            url_template,
            &[("user_id", user_id.as_str()), ("token", token.as_str())],
        );
        let username = user.username.as_ref().map(|name| name.as_str()).unwrap_or("");
        let display_name = if username.is_empty() { user.email.as_str() } else { username };
        let message = template
            .apply(
                &user.email,
                &[
                    ("reset_url", url.as_str()),
                    ("email", user.email.as_str()),
                    ("user", display_name),
                    ("user_id", user_id.as_str()),
                    ("username", username),
                ],
            )
            .map_err(|_| ExecError::Failed("Failed to build recovery email".to_owned()))?;
        // Serialize delivery and SMTP logging with deletion of the account.
        let result = self.mailer.send_in_transaction(&mut tx, message).await;
        tx.commit().await?;
        result.map_err(|_| {
            let remaining = (state.expires_at - self.clock.now_utc()).max(time::Duration::ZERO);
            ExecError::RetryAfterDelay(
                self.email_retry_delay.min(remaining.unsigned_abs() / 2),
                "Failed to send recovery email".to_owned(),
            )
        })?;
        Ok(None)
    }

    /// Executes an authentication task.
    pub async fn run(&self, task: AuthnTask) -> ExecResult {
        match task {
            AuthnTask::SendActivationEmail { activation_code, user_id } => {
                self.send_activation_email(user_id, activation_code).await
            }

            AuthnTask::SendPasswordRecoveryEmail { user_id, token } => {
                self.send_recovery_email(user_id, token).await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::testutils::TestContext;
    use crate::driver::{AuthnNoHooks, AuthnOptions};
    use crate::model::ActivationState;
    use iii_iv_core::db::Db;
    use iii_iv_core::model::{email_address, username};
    use iii_iv_queue::model::ExecError;
    use iii_iv_smtp::model::testutils::parse_message;
    use std::time::Duration;
    use time::macros::datetime;

    /// Creates a test context with a non-default email retry delay.
    async fn setup() -> TestContext<AuthnNoHooks> {
        let opts =
            AuthnOptions { email_retry_delay: Duration::from_secs(1234), ..Default::default() };
        TestContext::setup(opts).await
    }

    /// Adds an inactive user and returns its activation task.
    async fn create_user(db: &dyn Db) -> AuthnTask {
        let mut ex = db.ex().await.unwrap();
        let user = db::create_user(
            &mut ex,
            Some(username!("some-user")),
            None,
            email_address!("some-user@example.com"),
            None,
        )
        .await
        .unwrap();
        let user_id = user.id;
        db::set_user_activation(
            &mut ex,
            user,
            Some(ActivationState::new(
                9876,
                datetime!(2023-12-01 05:50:00 UTC),
                Duration::from_secs(86400),
            )),
        )
        .await
        .unwrap();
        AuthnTask::SendActivationEmail { activation_code: 9876.into(), user_id }
    }

    #[tokio::test]
    async fn test_send_activation_email() {
        let context = setup().await;
        let task = create_user(context.db()).await;

        assert_eq!(None, context.task_runner.run(task).await.ok().unwrap());

        let message =
            context.mailer.expect_one_message(&email_address!("some-user@example.com")).await;
        let (_, body) = parse_message(&message);
        let user = db::get_user_by_username(&mut context.ex().await, username!("some-user"))
            .await
            .unwrap();
        assert_eq!(
            format!(
                "http://localhost:1234/api/users/{}/activate?code={}",
                user.id,
                EmailToken::from(9876)
            ),
            body
        );
    }

    #[tokio::test]
    async fn test_send_activation_email_obsolete() {
        let context = setup().await;
        let task = create_user(context.db()).await;
        let user = db::get_user_by_username(&mut context.ex().await, username!("some-user"))
            .await
            .unwrap();
        db::set_user_activation(&mut context.ex().await, user, None).await.unwrap();

        let result = context.task_runner.run(task).await.ok().unwrap().unwrap();
        assert!(result.contains("obsolete"));
        context.mailer.expect_no_messages().await;
    }

    #[tokio::test]
    async fn test_send_activation_email_retries_errors() {
        let context = setup().await;
        let task = create_user(context.db()).await;
        context.mailer.inject_error_for("some-user@example.com").await;

        match context.task_runner.run(task).await {
            Err(ExecError::RetryAfterDelay(delay, message)) => {
                assert_eq!(Duration::from_secs(1234), delay);
                assert!(message.contains("Failed to send activation email"));
            }
            _ => panic!("Unexpected task result"),
        }
        context.mailer.expect_no_messages().await;
    }
}
