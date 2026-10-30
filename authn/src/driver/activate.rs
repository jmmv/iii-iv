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
use crate::driver::{AuthnDriver, AuthnHooks};
use crate::model::User;
use iii_iv_core::driver::{DriverError, DriverResult};
use uuid::Uuid;

impl<H: AuthnHooks> AuthnDriver<H> {
    /// Marks a user as active based on a confirmation code.
    pub(crate) async fn activate(self, user_id: Uuid, code: u64) -> DriverResult<User> {
        let mut tx = self.db.begin().await?;

        if !db::consume_user_activation(tx.ex(), user_id, code, self.clock.now_utc()).await? {
            return Err(DriverError::InvalidInput("Invalid activation code".to_owned()));
        }
        let user = db::get_user_by_id(tx.ex(), user_id).await?;
        tx.commit().await?;

        Ok(user)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::AuthnOptions;
    use crate::driver::testutils::*;
    use crate::model::ActivationState;
    use iii_iv_core::clocks::testutils::SettableClock;
    use iii_iv_core::db::Executor;
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
