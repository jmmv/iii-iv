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
    /// Marks a used as active based on a confirmation code.
    pub(crate) async fn activate(self, user_id: Uuid, code: u64) -> DriverResult<User> {
        let mut tx = self.db.begin().await?;

        let user = db::get_user_by_id(tx.ex(), user_id).await?;
        match user.activation_code {
            Some(exp_code) => {
                if exp_code != code {
                    return Err(DriverError::InvalidInput("Invalid activation code".to_owned()));
                }
            }
            None => return Err(DriverError::InvalidInput("User is already active".to_owned())),
        }

        let user = db::set_user_activation_code(tx.ex(), user, None).await?;
        tx.commit().await?;

        Ok(user)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::AuthnOptions;
    use crate::driver::testutils::*;
    use iii_iv_core::db::Executor;
    use iii_iv_core::model::{email_address, username};

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
        db::set_user_activation_code(ex, user, code).await.unwrap();

        user_id
    }

    #[tokio::test]
    async fn test_activate_ok() {
        let context = TestContext::setup(AuthnOptions::default()).await;

        let user_id = create_test_user(&mut context.ex().await, Some(42)).await;

        context.driver().activate(user_id, 42).await.unwrap();

        let user = db::get_user_by_id(&mut context.ex().await, user_id).await.unwrap();
        assert!(user.activation_code.is_none());
    }

    #[tokio::test]
    async fn test_activate_when_signups_closed() {
        let opts = AuthnOptions { open_signups: false, ..Default::default() };
        let context = TestContext::setup(opts).await;

        let user_id = create_test_user(&mut context.ex().await, Some(42)).await;
        context.driver().activate(user_id, 42).await.unwrap();

        let user = db::get_user_by_id(&mut context.ex().await, user_id).await.unwrap();
        assert!(user.activation_code.is_none());
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
        assert!(user.activation_code.is_some());
    }

    #[tokio::test]
    async fn test_activate_already_active() {
        let context = TestContext::setup(AuthnOptions::default()).await;

        let user_id = create_test_user(&mut context.ex().await, None).await;

        match context.driver().activate(user_id, 1234).await {
            Err(DriverError::InvalidInput(e)) => assert!(e.contains("already active")),
            e => panic!("{:?}", e),
        }

        let user = db::get_user_by_id(&mut context.ex().await, user_id).await.unwrap();
        assert!(user.activation_code.is_none());
    }

    #[tokio::test]
    async fn test_user_not_found() {
        let context = TestContext::setup(AuthnOptions::default()).await;

        let user_id = Uuid::new_v4();

        match context.driver().activate(user_id, 1234).await {
            Err(DriverError::NotFound(_)) => (),
            e => panic!("{:?}", e),
        }

        db::get_user_by_id(&mut context.ex().await, user_id).await.unwrap_err();
    }
}
