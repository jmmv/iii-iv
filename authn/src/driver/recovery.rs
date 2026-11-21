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

//! Password recovery business logic.

use crate::db;
use crate::driver::signup::password_validator;
use crate::driver::{AuthnDriver, AuthnHooks};
use crate::model::{
    AuthnTask, CredentialPurpose, EmailCredential, EmailToken, FailureOperation, Password,
};
use iii_iv_core::db::DbError;
use iii_iv_core::driver::{DriverError, DriverResult};
use iii_iv_core::model::EmailAddress;
use uuid::Uuid;

/// Common response for unusable recovery credentials.
fn invalid_recovery() -> DriverError {
    DriverError::InvalidInput("Invalid recovery link".to_owned())
}

impl<H: AuthnHooks> AuthnDriver<H> {
    /// Queues a recovery email without disclosing account eligibility.
    pub async fn request_password_recovery(self, email: EmailAddress) -> DriverResult<()> {
        let mut tx = self.db.begin().await?;
        let user = match db::get_user_by_email(tx.ex(), email).await {
            Ok(user) => user,
            Err(DbError::NotFound) => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        let user = match db::lock_user(tx.ex(), user.id).await {
            Ok(user) => user,
            Err(DbError::NotFound) => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        if user.password.is_none() {
            return Ok(());
        }
        let now = self.clock.now_utc();
        let purpose = CredentialPurpose::Recovery;
        if let Some(state) = db::get_email_credential(tx.ex(), user.id, purpose).await? {
            if now < state.issued_at + self.opts.recovery_resend_cooldown {
                return Ok(());
            }
        }
        let token = EmailToken::generate();
        db::put_email_credential(
            tx.ex(),
            user.id,
            purpose,
            &EmailCredential {
                digest: token.digest(purpose),
                issued_at: now,
                expires_at: now + self.opts.recovery_max_age,
            },
        )
        .await?;
        self.task_enqueuer
            .enqueue(tx.ex(), AuthnTask::SendPasswordRecoveryEmail { user_id: user.id, token })
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Consumes a recovery credential and revokes every existing session.
    pub async fn reset_password(
        self,
        user_id: Uuid,
        token: EmailToken,
        new_password: Password,
    ) -> DriverResult<()> {
        let mut tx = self.db.begin().await?;
        let user = match db::lock_user(tx.ex(), user_id).await {
            Ok(user) => user,
            Err(DbError::NotFound) => return Err(invalid_recovery()),
            Err(error) => return Err(error.into()),
        };
        let now = self.clock.now_utc();
        let purpose = CredentialPurpose::Recovery;
        let state = db::get_email_credential(tx.ex(), user_id, purpose)
            .await?
            .ok_or_else(invalid_recovery)?;
        if now >= state.expires_at || state.digest != token.digest(purpose) {
            return Err(invalid_recovery());
        }
        let old_hash = user.password.as_ref().ok_or_else(invalid_recovery)?;
        let permit = self.acquire_password_hash_capacity()?;
        let (hash, permit) = self.hash_password(new_password, password_validator, permit).await?;
        drop(permit);
        db::update_user_password(tx.ex(), user_id, old_hash, hash).await?;
        db::delete_email_credential(tx.ex(), user_id, purpose).await?;
        db::delete_email_credential(tx.ex(), user_id, CredentialPurpose::Activation).await?;
        db::set_user_active(tx.ex(), user_id, true).await?;
        db::clear_failures(tx.ex(), user_id, FailureOperation::Activation).await?;
        db::clear_failures(tx.ex(), user_id, FailureOperation::Login).await?;
        db::delete_sessions_for_user(tx.ex(), user_id, now).await?;
        tx.commit().await?;
        self.sessions_cache.lock().await.clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::testutils::TestContext;
    use crate::driver::{AuthnNoHooks, AuthnOptions};
    use crate::model::{ActivationState, password};
    use iii_iv_core::model::{email_address, username};
    use std::time::Duration;

    async fn account(context: &TestContext<AuthnNoHooks>) -> crate::model::User {
        context.create_active_user(&username!("recovery")).await;
        db::get_user_by_email(&mut context.ex().await, email_address!("recovery@example.com"))
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn test_recovery_reset_and_replay() {
        let context = TestContext::setup(AuthnOptions::default()).await;
        let session = context.do_test_login(username!("recovery")).await;
        let user =
            db::get_user_by_email(&mut context.ex().await, email_address!("recovery@example.com"))
                .await
                .unwrap();
        context.driver().request_password_recovery(user.email.clone()).await.unwrap();
        let token = context.get_latest_recovery_token(&user.email).await.unwrap();
        for _ in 0..3 {
            assert!(
                context
                    .driver()
                    .login("recovery".to_owned(), password!("wrong1password"), None)
                    .await
                    .is_err()
            );
        }
        assert!(
            context
                .driver()
                .reset_password(user.id, EmailToken::generate(), password!("new1password"))
                .await
                .is_err()
        );
        assert!(
            context
                .driver()
                .reset_password(user.id, token.clone(), password!("weak"))
                .await
                .is_err()
        );
        context
            .driver()
            .reset_password(user.id, token.clone(), password!("new1password"))
            .await
            .unwrap();
        assert!(
            context
                .driver()
                .reset_password(user.id, token, password!("other1password"))
                .await
                .is_err()
        );
        let mut tx = context.driver().db.begin().await.unwrap();
        assert!(
            context.driver().get_session(&mut tx, context.clock.now_utc(), session).await.is_err()
        );
        drop(tx);
        assert!(
            context
                .driver()
                .login(
                    "recovery".to_owned(),
                    password!("test0password"),
                    Some(Duration::from_secs(3600))
                )
                .await
                .is_err()
        );
        context
            .driver()
            .login(
                "recovery".to_owned(),
                password!("new1password"),
                Some(Duration::from_secs(3600)),
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_recovery_cooldown_replacement_and_expiry() {
        let context = TestContext::setup(AuthnOptions::default()).await;
        let user = account(&context).await;
        context.driver().request_password_recovery(user.email.clone()).await.unwrap();
        let first = context.get_latest_recovery_token(&user.email).await.unwrap();
        context.driver().request_password_recovery(user.email.clone()).await.unwrap();
        assert_eq!(first, context.get_latest_recovery_token(&user.email).await.unwrap());
        context.clock.sleep(Duration::from_secs(60)).await;
        context.driver().request_password_recovery(user.email.clone()).await.unwrap();
        let second = context.get_latest_recovery_token(&user.email).await.unwrap();
        assert_ne!(first, second);
        assert!(
            context
                .driver()
                .reset_password(user.id, first, password!("new1password"))
                .await
                .is_err()
        );
        context.clock.sleep(Duration::from_secs(3600)).await;
        assert!(
            context
                .driver()
                .reset_password(user.id, second, password!("new1password"))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_recovery_activates_and_invalidates_activation_link() {
        let context = TestContext::setup(AuthnOptions::default()).await;
        let user = account(&context).await;
        let id = user.id;
        let email = user.email.clone();
        db::set_user_activation(
            &mut context.ex().await,
            user,
            Some(ActivationState::new(42, context.clock.now_utc(), Duration::from_secs(86400))),
        )
        .await
        .unwrap();
        context.driver().request_password_recovery(email.clone()).await.unwrap();
        let token = context.get_latest_recovery_token(&email).await.unwrap();
        context.driver().reset_password(id, token, password!("new1password")).await.unwrap();
        assert!(db::get_user_by_id(&mut context.ex().await, id).await.unwrap().is_active);
        assert!(context.driver().activate(id, 42).await.is_err());
    }

    #[tokio::test]
    async fn test_recovery_unknown_and_disabled() {
        let context = TestContext::setup(AuthnOptions::default()).await;
        context
            .driver()
            .request_password_recovery(email_address!("unknown@example.com"))
            .await
            .unwrap();
        let email = email_address!("disabled@example.com");
        db::create_user(
            &mut context.ex().await,
            Some(username!("disabled")),
            None,
            email.clone(),
            None,
        )
        .await
        .unwrap();
        context.driver().request_password_recovery(email).await.unwrap();
        context.mailer.expect_no_messages().await;
        assert!(
            iii_iv_queue::db::get_tasks::<AuthnTask>(&mut context.ex().await)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn test_password_change_invalidates_recovery() {
        let context = TestContext::setup(AuthnOptions::default()).await;
        let session = context.do_test_login(username!("recovery")).await;
        let email = email_address!("recovery@example.com");
        let user = db::get_user_by_email(&mut context.ex().await, email.clone()).await.unwrap();
        context.driver().request_password_recovery(email.clone()).await.unwrap();
        let token = context.get_latest_recovery_token(&email).await.unwrap();
        context
            .driver()
            .change_password(session, password!("test0password"), password!("changed1password"))
            .await
            .unwrap();
        assert!(
            context
                .driver()
                .reset_password(user.id, token, password!("reset1password"))
                .await
                .is_err()
        );
    }
    #[tokio::test]
    async fn test_recovery_email_retry_and_obsolete_tasks() {
        use iii_iv_queue::model::ExecError;
        let context = TestContext::setup(AuthnOptions::default()).await;
        let user = account(&context).await;
        context.driver().request_password_recovery(user.email.clone()).await.unwrap();
        let mut tasks =
            iii_iv_queue::db::get_tasks::<AuthnTask>(&mut context.ex().await).await.unwrap();
        let (_, task) = tasks
            .drain(..)
            .find(|(_, task)| matches!(task, AuthnTask::SendPasswordRecoveryEmail { .. }))
            .unwrap();
        context.mailer.inject_error_for(user.email.as_str()).await;
        match context.task_runner.run(task).await {
            Err(ExecError::RetryAfterDelay(delay, _)) => {
                assert_eq!(Duration::from_secs(1800), delay)
            }
            _ => panic!("Expected a retry within the credential lifetime"),
        }
        context.clock.sleep(Duration::from_secs(3600)).await;
        let tasks =
            iii_iv_queue::db::get_tasks::<AuthnTask>(&mut context.ex().await).await.unwrap();
        for (_, task) in tasks {
            if matches!(task, AuthnTask::SendPasswordRecoveryEmail { .. }) {
                assert!(
                    context.task_runner.run(task).await.ok().unwrap().unwrap().contains("obsolete")
                );
            }
        }
    }
    #[tokio::test]
    async fn test_recovery_queue_failure_rolls_back() {
        use crate::driver::AuthnTaskEnqueuer;
        use async_trait::async_trait;
        use iii_iv_core::db::Executor;
        use std::sync::Arc;

        struct FailingQueue;
        #[async_trait]
        impl AuthnTaskEnqueuer for FailingQueue {
            async fn enqueue(&self, _ex: &mut Executor, _task: AuthnTask) -> DriverResult<()> {
                Err(DriverError::BackendError("queue unavailable".to_owned()))
            }
        }
        let context = TestContext::setup(AuthnOptions::default()).await;
        let user = account(&context).await;
        let mut driver = context.driver();
        driver.task_enqueuer = Arc::new(FailingQueue);
        assert!(driver.request_password_recovery(user.email).await.is_err());
        assert_eq!(
            None,
            db::get_email_credential(&mut context.ex().await, user.id, CredentialPurpose::Recovery)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_concurrent_resets_consume_only_once() {
        let context = TestContext::setup(AuthnOptions::default()).await;
        let user = account(&context).await;
        context.driver().request_password_recovery(user.email.clone()).await.unwrap();
        let token = context.get_latest_recovery_token(&user.email).await.unwrap();
        let (first, second) = tokio::join!(
            context.driver().reset_password(user.id, token.clone(), password!("first1password")),
            context.driver().reset_password(user.id, token, password!("second1password")),
        );
        assert_ne!(first.is_ok(), second.is_ok());
    }

    #[tokio::test]
    async fn test_recovery_task_skips_deleted_account() {
        let context = TestContext::setup(AuthnOptions::default()).await;
        let user = account(&context).await;
        context.driver().request_password_recovery(user.email).await.unwrap();
        let tasks =
            iii_iv_queue::db::get_tasks::<AuthnTask>(&mut context.ex().await).await.unwrap();
        db::delete_user(&mut context.ex().await, user.id).await.unwrap();
        assert_eq!(
            None,
            db::get_email_credential(&mut context.ex().await, user.id, CredentialPurpose::Recovery)
                .await
                .unwrap()
        );
        for (_, task) in tasks {
            if matches!(task, AuthnTask::SendPasswordRecoveryEmail { .. }) {
                assert!(
                    context
                        .task_runner
                        .run(task)
                        .await
                        .ok()
                        .unwrap()
                        .unwrap()
                        .contains("missing user")
                );
            }
        }
    }
}
