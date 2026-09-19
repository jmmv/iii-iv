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
use crate::model::AuthnTask;
use iii_iv_core::db::{Db, DbError};
use iii_iv_core::rest::BaseUrls;
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

    /// Base URLs of the running service.
    base_urls: Arc<BaseUrls>,

    /// Database that stores authentication state.
    db: Arc<dyn Db + Send + Sync>,

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
    pub fn new(
        db: Arc<dyn Db + Send + Sync>,
        mailer: Arc<dyn SmtpMailer + Send + Sync>,
        activation_template: EmailTemplate,
        base_urls: Arc<BaseUrls>,
        opts: &AuthnOptions,
    ) -> Self {
        Self {
            activation_template: Arc::from(activation_template),
            base_urls,
            db,
            email_retry_delay: opts.email_retry_delay,
            mailer,
        }
    }

    /// Executes an authentication task.
    pub async fn run(&self, task: AuthnTask) -> ExecResult {
        match task {
            AuthnTask::SendActivationEmail { activation_code, user_id } => {
                self.send_activation_email(user_id, activation_code).await
            }
        }
    }

    /// Sends an account activation email if the activation request is still current.
    async fn send_activation_email(&self, user_id: Uuid, activation_code: u64) -> ExecResult {
        let mut tx = self.db.begin().await?;
        let user = match db::get_user_by_id(tx.ex(), user_id).await {
            Ok(user) => user,
            Err(DbError::NotFound) => {
                return Ok(Some("Skipped activation email for missing user".to_owned()));
            }
            Err(e) => return Err(e.into()),
        };

        if user.activation_code != Some(activation_code) {
            return Ok(Some("Skipped obsolete activation email".to_owned()));
        }

        let message = make_activation_code_message(
            &self.activation_template,
            &self.base_urls,
            &user,
            activation_code,
        )
        .map_err(|e| ExecError::Failed(format!("Failed to build activation email: {}", e)))?;

        tx.commit().await?;

        self.mailer.send(message).await.map_err(|e| {
            ExecError::RetryAfterDelay(
                self.email_retry_delay,
                format!("Failed to send activation email: {}", e),
            )
        })?;
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::testutils::TestContext;
    use crate::driver::{AuthnNoHooks, AuthnOptions};
    use iii_iv_core::db::Db;
    use iii_iv_core::model::{email_address, username};
    use iii_iv_queue::model::ExecError;
    use iii_iv_smtp::model::testutils::parse_message;
    use std::time::Duration;

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
        db::set_user_activation_code(&mut ex, user, Some(9876)).await.unwrap();
        AuthnTask::SendActivationEmail { activation_code: 9876, user_id }
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
        assert_eq!(format!("http://localhost:1234/api/users/{}/activate?code=9876", user.id), body);
    }

    #[tokio::test]
    async fn test_send_activation_email_obsolete() {
        let context = setup().await;
        let task = create_user(context.db()).await;
        let user = db::get_user_by_username(&mut context.ex().await, username!("some-user"))
            .await
            .unwrap();
        db::set_user_activation_code(&mut context.ex().await, user, None).await.unwrap();

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
