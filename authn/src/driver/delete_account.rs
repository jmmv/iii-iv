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

//! Permanently removes an authenticated account.

use crate::db;
use crate::driver::{AuthnDriver, AuthnHooks};
use crate::model::{AccessToken, Password};
use iii_iv_core::db::DbError;
use iii_iv_core::driver::{DriverError, DriverResult};

impl<H: AuthnHooks> AuthnDriver<H> {
    /// Verifies the current password and atomically deletes all account state via the hook.
    pub(crate) async fn delete_account(
        self,
        token: AccessToken,
        password: Password,
    ) -> DriverResult<()> {
        let permit = self.acquire_password_hash_capacity()?;
        let mut tx = self.db.begin().await?;
        let now = self.clock.now_utc();
        let session = self.get_session_uncached(&mut tx, now, token.clone()).await?;
        match db::lock_user(tx.ex(), session.user.id).await {
            Ok(_) => {}
            Err(DbError::NotFound) => return Err(DriverError::Unauthenticated),
            Err(error) => return Err(error.into()),
        }
        let now = self.clock.now_utc();
        let session = self.get_session_uncached(&mut tx, now, token).await?;
        let hash = session.user.password.as_ref().ok_or_else(|| {
            DriverError::InvalidInput("Password not set; cannot delete account".to_owned())
        })?;
        let (verified, permit) = self.verify_password(password, hash, permit).await?;
        drop(permit);
        if !verified {
            return Err(DriverError::InvalidInput("Invalid password".to_owned()));
        }
        self.hooks.delete_account_hook(&mut tx, now, &session.user).await?;
        db::purge_sessions_for_user(tx.ex(), session.user.id).await?;
        db::delete_user(tx.ex(), session.user.id).await?;
        tx.commit().await?;
        self.sessions_cache.lock().await.clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::testutils::TestContext;
    use crate::driver::{AuthnOptions, NO_EXTENSIONS, NoExtensions};
    use crate::model::{ActivationState, FailureOperation, Session, User, password};
    use async_trait::async_trait;
    use iii_iv_core::clocks::testutils::SettableClock;
    use iii_iv_core::db::{Db, Executor, TxExecutor};
    use iii_iv_core::model::username;
    use sqlx::Row;
    use std::sync::Arc;
    use std::time::Duration;
    use time::OffsetDateTime;
    use time::macros::datetime;

    #[tokio::test]
    async fn test_delete_account() {
        let db: Arc<dyn Db + Send + Sync> =
            Arc::from(iii_iv_core::db::sqlite::testutils::setup().await);
        let clock = Arc::new(SettableClock::new(datetime!(2026-01-01 0:00 UTC)));
        let opts =
            AuthnOptions { sessions_cache_ttl: Duration::from_secs(900), ..Default::default() };
        let first =
            TestContext::setup_with(opts.clone(), db.clone(), clock.clone(), "realm", true).await;
        let second = TestContext::setup_with(opts, db.clone(), clock.clone(), "realm", true).await;
        let token = first.do_test_login(username!("delete")).await;
        let other_token = first.do_test_login(username!("keep")).await;
        let session = db::get_session(&mut first.ex().await, &token).await.unwrap();
        let user = db::get_user_by_id(&mut first.ex().await, session.user_id).await.unwrap();
        let mut tx = db.begin().await.unwrap();
        second
            .driver()
            .get_session(&mut tx, first.driver().now_utc(), token.clone())
            .await
            .unwrap();
        tx.commit().await.unwrap();
        let expired = Session::new(
            AccessToken::generate(),
            user.id,
            datetime!(2025-01-01 0:00 UTC),
            datetime!(2025-01-02 0:00 UTC),
        );
        db::put_session(&mut first.ex().await, &expired).await.unwrap();
        let logged_out = Session::new(
            AccessToken::generate(),
            user.id,
            first.driver().now_utc(),
            first.now_delta(60),
        );
        db::put_session(&mut first.ex().await, &logged_out).await.unwrap();
        db::delete_session(&mut first.ex().await, logged_out, first.driver().now_utc())
            .await
            .unwrap();
        db::set_user_activation(
            &mut first.ex().await,
            user,
            Some(ActivationState::new(123, first.driver().now_utc(), Duration::from_secs(60))),
        )
        .await
        .unwrap();
        let mut tx = db.begin().await.unwrap();
        let now = first.driver().now_utc();
        let mut failures =
            db::lock_failures(tx.ex(), session.user_id, FailureOperation::Login, now)
                .await
                .unwrap();
        failures.count = 1;
        db::save_failures(tx.ex(), session.user_id, FailureOperation::Login, &failures)
            .await
            .unwrap();
        tx.commit().await.unwrap();

        first.driver().delete_account(token.clone(), password!("test0password")).await.unwrap();
        assert_eq!(
            DbError::NotFound,
            db::get_user_by_id(&mut first.ex().await, session.user_id).await.unwrap_err()
        );
        assert!(
            db::get_user_activation(&mut first.ex().await, session.user_id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            db::get_failures(&mut first.ex().await, session.user_id, FailureOperation::Login)
                .await
                .unwrap()
                .is_none()
        );
        let count: i64 = match &mut first.ex().await {
            Executor::Sqlite(ex) => {
                sqlx::query("SELECT COUNT(*) AS count FROM sessions WHERE user_id = ?")
                    .bind(session.user_id)
                    .fetch_one(ex)
                    .await
                    .unwrap()
                    .get("count")
            }
            #[allow(unused)]
            _ => unreachable!(),
        };
        assert_eq!(0, count);
        let mut tx = db.begin().await.unwrap();
        assert_eq!(
            DriverError::Unauthenticated,
            second
                .driver()
                .get_session(&mut tx, first.driver().now_utc(), token.clone())
                .await
                .unwrap_err()
        );
        second.driver().get_session(&mut tx, first.driver().now_utc(), other_token).await.unwrap();
        tx.commit().await.unwrap();
        assert_eq!(
            DriverError::Unauthenticated,
            first.driver().delete_account(token, password!("test0password")).await.unwrap_err()
        );
        db.close().await;
    }

    #[tokio::test]
    async fn test_delete_account_rejects_invalid_credentials() {
        let context = TestContext::setup(AuthnOptions::default()).await;
        let token = context.do_test_login(username!("delete")).await;
        assert_eq!(
            DriverError::InvalidInput("Invalid password".to_owned()),
            context.driver().delete_account(token.clone(), password!("wrong")).await.unwrap_err()
        );
        let mut tx = context.db().begin().await.unwrap();
        context
            .driver()
            .get_session(&mut tx, context.driver().now_utc(), token.clone())
            .await
            .unwrap();
        tx.commit().await.unwrap();
        assert_eq!(
            DriverError::Unauthenticated,
            context
                .driver()
                .delete_account(AccessToken::generate(), password!("test0password"))
                .await
                .unwrap_err()
        );
        assert_eq!(
            DriverError::Unauthenticated,
            context
                .driver()
                .get_session(
                    &mut context.db().begin().await.unwrap(),
                    context.now_delta(48 * 3600),
                    token
                )
                .await
                .unwrap_err()
        );
    }

    struct PausingHasher {
        entered: Arc<tokio::sync::Notify>,
        release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
    }

    impl crate::driver::passwords::PasswordHasher for PausingHasher {
        fn hash(
            &self,
            password: Password,
            validator: fn(&str) -> Option<&'static str>,
        ) -> iii_iv_core::model::ModelResult<crate::model::HashedPassword> {
            password.validate_and_hash(validator)
        }

        fn verify(
            &self,
            password: Password,
            hash: crate::model::HashedPassword,
        ) -> iii_iv_core::model::ModelResult<bool> {
            self.entered.notify_one();
            self.release.lock().unwrap().recv_timeout(Duration::from_secs(10)).unwrap();
            password.verify(&hash)
        }
    }

    #[tokio::test]
    async fn test_delete_account_races_login() {
        let db: Arc<dyn Db + Send + Sync> =
            Arc::from(iii_iv_core::db::sqlite::testutils::setup().await);
        let clock = Arc::new(SettableClock::new(datetime!(2026-01-01 0:00 UTC)));
        let context =
            TestContext::setup_with(AuthnOptions::default(), db.clone(), clock, "realm", true)
                .await;
        let token = context.do_test_login(username!("delete")).await;
        let user_id = db::get_session(&mut context.ex().await, &token).await.unwrap().user_id;
        let entered = Arc::new(tokio::sync::Notify::new());
        let (release, receiver) = std::sync::mpsc::channel();
        let paused = context.driver().with_password_hasher(Arc::new(PausingHasher {
            entered: entered.clone(),
            release: std::sync::Mutex::new(receiver),
        }));
        let pending = tokio::spawn(async move {
            paused.login("delete".to_owned(), password!("test0password"), None).await
        });
        entered.notified().await;
        context.driver().delete_account(token, password!("test0password")).await.unwrap();
        release.send(()).unwrap();
        assert_eq!(DriverError::Unauthenticated, pending.await.unwrap().unwrap_err());
        assert!(
            db::get_failures(&mut context.ex().await, user_id, FailureOperation::Login)
                .await
                .unwrap()
                .is_none()
        );
        db.close().await;
    }

    #[tokio::test]
    async fn test_delete_account_capacity_and_expired_session() {
        let opts = AuthnOptions { password_hash_concurrency: 1, ..Default::default() };
        let context = TestContext::setup(opts).await;
        let token = context.do_test_login(username!("delete")).await;
        let permit = context.driver().acquire_password_hash_capacity().unwrap();
        assert_eq!(
            DriverError::Unavailable,
            context
                .driver()
                .delete_account(token.clone(), password!("test0password"))
                .await
                .unwrap_err()
        );
        drop(permit);
        let session = db::get_session(&mut context.ex().await, &token).await.unwrap();
        let expired = Session::new(
            AccessToken::generate(),
            session.user_id,
            context.now_delta(-120),
            context.now_delta(-60),
        );
        db::put_session(&mut context.ex().await, &expired).await.unwrap();
        assert_eq!(
            DriverError::Unauthenticated,
            context
                .driver()
                .delete_account(expired.access_token, password!("test0password"))
                .await
                .unwrap_err()
        );
        context.driver().delete_account(token, password!("test0password")).await.unwrap();
    }

    #[derive(Clone)]
    struct DeletionHook {
        fail: bool,
    }

    #[async_trait]
    impl AuthnHooks for DeletionHook {
        type LoginOutput = NoExtensions;
        type SignupInput = NoExtensions;

        async fn delete_account_hook(
            &self,
            tx: &mut TxExecutor,
            now: OffsetDateTime,
            user: &User,
        ) -> DriverResult<()> {
            if self.fail {
                db::update_user(tx.ex(), user.id, now + Duration::from_secs(10)).await?;
                return Err(DriverError::BackendError("deletion-hook-failure".to_owned()));
            }
            Ok(())
        }

        async fn login_hook(
            &self,
            _tx: &mut TxExecutor,
            _now: OffsetDateTime,
            _user: &User,
        ) -> DriverResult<NoExtensions> {
            Ok(NO_EXTENSIONS)
        }

        async fn signup_hook(
            &self,
            _tx: &mut TxExecutor,
            _now: OffsetDateTime,
            _user: &User,
            _input: NoExtensions,
        ) -> DriverResult<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_delete_account_hook_failure_rolls_back() {
        let db: Arc<dyn Db + Send + Sync> =
            Arc::from(iii_iv_core::db::sqlite::testutils::setup().await);
        let clock = Arc::new(SettableClock::new(datetime!(2026-01-01 0:00 UTC)));
        let context = TestContext::setup_with_hooks(
            AuthnOptions::default(),
            db.clone(),
            clock,
            "realm",
            true,
            DeletionHook { fail: true },
        )
        .await;
        let token = context.do_test_login(username!("delete")).await;
        let session = db::get_session(&mut context.ex().await, &token).await.unwrap();
        let before = db::get_user_by_id(&mut context.ex().await, session.user_id).await.unwrap();
        assert_eq!(
            DriverError::BackendError("deletion-hook-failure".to_owned()),
            context
                .driver()
                .delete_account(token.clone(), password!("test0password"))
                .await
                .unwrap_err()
        );
        assert_eq!(
            before,
            db::get_user_by_id(&mut context.ex().await, session.user_id).await.unwrap()
        );
        db::get_session(&mut context.ex().await, &token).await.unwrap();
        db.close().await;
    }
}
