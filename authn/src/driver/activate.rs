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

//! Extends the driver with the `activate` method.

use crate::db;
use crate::driver::failures::FixedWindow;
use crate::driver::{AuthnDriver, AuthnHooks};
use crate::model::{FailureHistory, FailureOperation, User};
use iii_iv_core::db::DbError;
use iii_iv_core::driver::{DriverError, DriverResult};
use time::OffsetDateTime;
use uuid::Uuid;

/// Builds the common public error for unsuccessful activation.
fn invalid_activation() -> DriverError {
    DriverError::InvalidInput("Invalid activation code".to_owned())
}

impl<H: AuthnHooks> AuthnDriver<H> {
    /// Records a rejected code using the configured activation policy.
    fn record_activation_failure(&self, state: &mut FailureHistory, now: OffsetDateTime) {
        FixedWindow {
            limit: self.opts.activation_failure_limit,
            window: self.opts.activation_failure_window,
            block_duration: self.opts.activation_block_duration,
        }
        .record(state, now);
    }

    /// Marks a user as active based on a confirmation code.
    pub(crate) async fn activate(self, user_id: Uuid, code: u64) -> DriverResult<User> {
        let mut tx = self.db.begin().await?;

        let mut failures = match db::lock_failures(
            tx.ex(),
            user_id,
            FailureOperation::Activation,
            self.clock.now_utc(),
        )
        .await
        {
            Ok(failures) => failures,
            Err(DbError::NotFound) => return Err(invalid_activation()),
            Err(error) => return Err(error.into()),
        };
        let now = self.clock.now_utc();
        if failures.is_blocked(now) {
            return Err(invalid_activation());
        }

        let activation =
            db::get_user_activation(tx.ex(), user_id).await?.ok_or_else(invalid_activation)?;
        if now >= activation.expires_at {
            return Err(invalid_activation());
        }
        if code != activation.code {
            self.record_activation_failure(&mut failures, now);
            db::save_failures(tx.ex(), user_id, FailureOperation::Activation, &failures).await?;
            tx.commit().await?;
            return Err(invalid_activation());
        }

        if !db::consume_user_activation(tx.ex(), user_id, code, now).await? {
            return Err(invalid_activation());
        }
        db::clear_failures(tx.ex(), user_id, FailureOperation::Activation).await?;
        let user = db::get_user_by_id(tx.ex(), user_id).await?;
        tx.commit().await?;

        Ok(user)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::testutils::*;
    use crate::driver::{AuthnNoHooks, AuthnOptions};
    use crate::model::ActivationState;
    use futures::future::join_all;
    use iii_iv_core::clocks::testutils::SettableClock;
    use iii_iv_core::db::sqlite::connect;
    use iii_iv_core::db::{Db, Executor};
    use iii_iv_core::model::{email_address, username};
    use std::sync::Arc;
    use std::time::Duration;
    use time::macros::datetime;

    /// Creates a test user with an optional activation `code` and returns its ID.
    async fn create_test_user(ex: &mut Executor, code: Option<u64>) -> Uuid {
        let user = db::create_user(
            ex,
            Some(username!("some-username")),
            None,
            email_address!("a@example.com"),
            None,
        )
        .await
        .unwrap();
        let user_id = user.id;
        db::set_user_activation(
            ex,
            user,
            code.map(|code| {
                ActivationState::new(
                    code,
                    datetime!(2023-12-01 05:50:00 UTC),
                    Duration::from_secs(86400),
                )
            }),
        )
        .await
        .unwrap();

        user_id
    }

    /// Creates independent driver contexts sharing the default test database and clock.
    async fn protection_context(
        opts: AuthnOptions,
    ) -> (TestContext<AuthnNoHooks>, TestContext<AuthnNoHooks>, Uuid) {
        let first = TestContext::setup(opts.clone()).await;
        let second = TestContext::setup_with(
            opts,
            first.driver().db.clone(),
            first.clock.clone(),
            "the-realm",
            true,
        )
        .await;
        let id = create_test_user(&mut first.ex().await, Some(42)).await;
        (first, second, id)
    }

    /// Reads persistent activation failure history.
    async fn history(context: &TestContext<AuthnNoHooks>, id: Uuid) -> Option<FailureHistory> {
        db::get_failures(&mut context.ex().await, id, FailureOperation::Activation).await.unwrap()
    }

    #[tokio::test]
    async fn test_activation_custom_policy() {
        let opts = AuthnOptions {
            activation_failure_limit: 3,
            activation_failure_window: Duration::from_secs(10),
            activation_block_duration: Duration::from_secs(3),
            ..Default::default()
        };
        let (first, second, id) = protection_context(opts).await;
        assert_eq!(Err(invalid_activation()), first.driver().activate(id, 0).await);

        first.clock.sleep(Duration::from_secs(9)).await;
        assert_eq!(Err(invalid_activation()), second.driver().activate(id, 0).await);
        let state = history(&first, id).await.unwrap();
        assert_eq!(2, state.count);
        assert_eq!(None, state.blocked_until);

        first.clock.sleep(Duration::from_secs(1)).await;
        assert_eq!(Err(invalid_activation()), second.driver().activate(id, 0).await);
        let state = history(&first, id).await.unwrap();
        assert_eq!(1, state.count);
        assert_eq!(first.driver().now_utc(), state.window_start);
        assert_eq!(None, state.blocked_until);

        assert_eq!(Err(invalid_activation()), first.driver().activate(id, 0).await);
        assert_eq!(Err(invalid_activation()), second.driver().activate(id, 0).await);
        let before = history(&second, id).await;
        assert_eq!(3, before.as_ref().unwrap().count);
        assert_eq!(
            Some(first.driver().now_utc() + Duration::from_secs(3)),
            before.as_ref().unwrap().blocked_until
        );

        first.clock.sleep(Duration::from_secs(2)).await;
        assert_eq!(Err(invalid_activation()), second.driver().activate(id, 42).await);
        assert_eq!(before, history(&first, id).await);
        first.clock.sleep(Duration::from_secs(1)).await;
        assert!(second.driver().activate(id, 42).await.unwrap().is_active);
        assert_eq!(None, history(&first, id).await);
    }

    #[tokio::test]
    async fn test_activation_zero_options() {
        for (limit, window, block_duration) in [(0, 10, 3), (2, 0, 3), (2, 10, 0)] {
            let opts = AuthnOptions {
                activation_failure_limit: limit,
                activation_failure_window: Duration::from_secs(window),
                activation_block_duration: Duration::from_secs(block_duration),
                ..Default::default()
            };
            let (first, second, id) = protection_context(opts).await;
            assert_eq!(Err(invalid_activation()), first.driver().activate(id, 0).await);
            if limit == 0 {
                assert_eq!(1, history(&first, id).await.unwrap().count);
                assert_eq!(Err(invalid_activation()), second.driver().activate(id, 42).await);
            } else {
                for _ in 0..3 {
                    assert_eq!(Err(invalid_activation()), second.driver().activate(id, 0).await);
                }
                let state = history(&first, id).await.unwrap();
                if window == 0 {
                    assert_eq!(1, state.count);
                    assert_eq!(None, state.blocked_until);
                } else {
                    assert_eq!(4, state.count);
                    assert_eq!(Some(first.driver().now_utc()), state.blocked_until);
                }
                assert!(first.driver().activate(id, 42).await.unwrap().is_active);
            }
        }
    }

    #[tokio::test]
    async fn test_activation_limits() {
        let (first, second, id) = protection_context(AuthnOptions::default()).await;
        for attempt in 1..=10 {
            assert_eq!(Err(invalid_activation()), first.driver().activate(id, 0).await);
            assert_eq!(attempt, history(&second, id).await.unwrap().count);
        }
        let before = history(&second, id).await;
        first.clock.sleep(Duration::from_secs(3599)).await;
        assert_eq!(Err(invalid_activation()), second.driver().activate(id, 42).await);
        assert_eq!(Err(invalid_activation()), second.driver().activate(id, 0).await);
        assert_eq!(before, history(&first, id).await);

        first.clock.sleep(Duration::from_secs(1)).await;
        assert!(second.driver().activate(id, 42).await.unwrap().is_active);
        assert_eq!(None, history(&first, id).await);
        assert_eq!(Err(invalid_activation()), first.driver().activate(id, 42).await);
        let missing = Uuid::new_v4();
        assert_eq!(Err(invalid_activation()), first.driver().activate(missing, 42).await);
        assert_eq!(None, history(&first, id).await);
        assert_eq!(None, history(&first, missing).await);
    }

    #[tokio::test]
    async fn test_activation_windows() {
        let (first, second, id) = protection_context(AuthnOptions::default()).await;
        for _ in 0..9 {
            assert_eq!(Err(invalid_activation()), first.driver().activate(id, 0).await);
        }
        first.clock.sleep(Duration::from_secs(3600)).await;
        assert_eq!(Err(invalid_activation()), second.driver().activate(id, 0).await);
        let state = history(&first, id).await.unwrap();
        assert_eq!(1, state.count);
        assert_eq!(first.driver().now_utc(), state.window_start);
        assert_eq!(None, state.blocked_until);

        first.clock.sleep(Duration::from_secs(3599)).await;
        for _ in 0..9 {
            assert_eq!(Err(invalid_activation()), first.driver().activate(id, 0).await);
        }
        let before = history(&first, id).await;
        first.clock.sleep(Duration::from_secs(1)).await;
        assert_eq!(Err(invalid_activation()), second.driver().activate(id, 42).await);
        assert_eq!(before, history(&second, id).await);

        first.clock.sleep(Duration::from_secs(86400)).await;
        assert_eq!(Err(invalid_activation()), second.driver().activate(id, 42).await);
        assert_eq!(before, history(&second, id).await);
        assert!(!db::get_user_by_id(&mut first.ex().await, id).await.unwrap().is_active);
    }

    #[tokio::test]
    async fn test_activation_concurrency() {
        let (first, second, id) = protection_context(AuthnOptions::default()).await;
        let attempts = (0..20).map(|index| {
            let driver = if index % 2 == 0 { first.driver() } else { second.driver() };
            async move { driver.activate(id, 0).await }
        });
        for result in join_all(attempts).await {
            assert_eq!(Err(invalid_activation()), result);
        }
        let failures = history(&first, id).await.unwrap();
        assert_eq!(10, failures.count);
        assert_eq!(Err(invalid_activation()), second.driver().activate(id, 42).await);

        first.clock.sleep(Duration::from_secs(3600)).await;
        let (left, right) =
            tokio::join!(first.driver().activate(id, 42), second.driver().activate(id, 42));
        assert_ne!(left.is_ok(), right.is_ok());
        assert_eq!(None, history(&first, id).await);
    }

    #[tokio::test]
    async fn test_activation_survives_database_reopen() {
        let path =
            std::env::temp_dir().join(format!("iii-iv-activation-{}.sqlite", Uuid::new_v4()));
        let connection = format!("sqlite://{}?mode=rwc", path.display());
        let id;
        let before;
        {
            let db = Arc::new(connect(&connection).await.unwrap());
            let clock = Arc::new(SettableClock::new(datetime!(2023-12-01 05:50:00 UTC)));
            let context = TestContext::setup_with(
                AuthnOptions::default(),
                db.clone(),
                clock,
                "the-realm",
                true,
            )
            .await;
            id = create_test_user(&mut context.ex().await, Some(42)).await;
            for _ in 0..10 {
                assert_eq!(Err(invalid_activation()), context.driver().activate(id, 0).await);
            }
            before = history(&context, id).await;
            drop(context);
            db.close().await;
        }
        {
            let db = Arc::new(connect(&connection).await.unwrap());
            let clock = Arc::new(SettableClock::new(datetime!(2023-12-01 05:50:00 UTC)));
            let context = TestContext::setup_with(
                AuthnOptions::default(),
                db.clone(),
                clock.clone(),
                "realm",
                true,
            )
            .await;
            assert_eq!(Err(invalid_activation()), context.driver().activate(id, 42).await);
            assert_eq!(before, history(&context, id).await);
            clock.advance(Duration::from_secs(3600));
            context.driver().activate(id, 42).await.unwrap();
            drop(context);
            db.close().await;
        }
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn test_activate_ok() {
        let context = TestContext::setup(AuthnOptions::default()).await;

        let user_id = create_test_user(&mut context.ex().await, Some(42)).await;

        context.driver().activate(user_id, 42).await.unwrap();

        let user = db::get_user_by_id(&mut context.ex().await, user_id).await.unwrap();
        assert!(user.is_active);
    }

    #[tokio::test]
    async fn test_activate_when_signups_closed() {
        let opts = AuthnOptions { open_signups: false, ..Default::default() };
        let context = TestContext::setup(opts).await;

        let user_id = create_test_user(&mut context.ex().await, Some(42)).await;
        context.driver().activate(user_id, 42).await.unwrap();

        let user = db::get_user_by_id(&mut context.ex().await, user_id).await.unwrap();
        assert!(user.is_active);
    }

    #[tokio::test]
    async fn test_activate_expired() {
        let context = TestContext::setup(AuthnOptions::default()).await;
        let id = create_test_user(&mut context.ex().await, Some(42)).await;
        let activation =
            db::get_user_activation(&mut context.ex().await, id).await.unwrap().unwrap();
        assert_eq!(context.driver().now_utc() + Duration::from_secs(86400), activation.expires_at);
        let clock = Arc::new(SettableClock::new(activation.expires_at));
        let later = TestContext::setup_with(
            AuthnOptions::default(),
            context.driver().db.clone(),
            clock,
            "the-realm",
            true,
        )
        .await;
        assert_eq!(
            Err(DriverError::InvalidInput("Invalid activation code".to_owned())),
            later.driver().activate(id, 42).await
        );
        assert!(!db::get_user_by_id(&mut later.ex().await, id).await.unwrap().is_active);
    }

    #[tokio::test]
    async fn test_activate_bad_code() {
        let context = TestContext::setup(AuthnOptions::default()).await;

        let user_id = create_test_user(&mut context.ex().await, Some(42)).await;

        match context.driver().activate(user_id, 41).await {
            Err(DriverError::InvalidInput(e)) => assert!(e.contains("Invalid activation code")),
            e => panic!("{:?}", e),
        }

        let user = db::get_user_by_id(&mut context.ex().await, user_id).await.unwrap();
        assert!(!user.is_active);
    }

    #[tokio::test]
    async fn test_activate_already_active() {
        let context = TestContext::setup(AuthnOptions::default()).await;

        let user_id = create_test_user(&mut context.ex().await, None).await;

        match context.driver().activate(user_id, 1234).await {
            Err(DriverError::InvalidInput(e)) => assert!(e == "Invalid activation code"),
            e => panic!("{:?}", e),
        }

        let user = db::get_user_by_id(&mut context.ex().await, user_id).await.unwrap();
        assert!(user.is_active);
    }

    #[tokio::test]
    async fn test_user_not_found() {
        let context = TestContext::setup(AuthnOptions::default()).await;

        let user_id = Uuid::new_v4();

        match context.driver().activate(user_id, 1234).await {
            Err(DriverError::InvalidInput(e)) => assert_eq!("Invalid activation code", e),
            e => panic!("{:?}", e),
        }

        db::get_user_by_id(&mut context.ex().await, user_id).await.unwrap_err();
    }
}
