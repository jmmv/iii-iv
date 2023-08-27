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
use crate::driver::AuthnDriver;
use iii_iv_core::driver::{DriverError, DriverResult};
use iii_iv_core::model::Username;

impl AuthnDriver {
    /// Marks a used as active based on a confirmation code.
    pub(crate) async fn activate(self, username: Username, code: u64) -> DriverResult<()> {
        let mut tx = self.db.begin().await?;

        let user = db::get_user_by_username(tx.ex(), username).await?;
        match user.activation_code() {
            Some(exp_code) => {
                if exp_code != code {
                    return Err(DriverError::InvalidInput("Invalid activation code".to_owned()));
                }
            }
            None => return Err(DriverError::InvalidInput("User is already active".to_owned())),
        }

        db::set_user_activation_code(tx.ex(), user, None).await?;
        tx.commit().await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::testutils::*;
    use iii_iv_core::db::Executor;
    use iii_iv_core::model::EmailAddress;

    /// Creates a test user with an optional activation `code` and returns its username.
    async fn create_test_user(ex: &mut Executor, code: Option<u64>) -> Username {
        let username = Username::from("some-username");

        let user = db::create_user(ex, username.clone(), None, EmailAddress::from("a@example.com"))
            .await
            .unwrap();
        db::set_user_activation_code(ex, user, code).await.unwrap();

        username
    }

    #[tokio::test]
    async fn test_activate_ok() {
        let context = TestContext::setup().await;
        let mut ex = context.db().ex();

        let username = create_test_user(&mut ex, Some(42)).await;

        context.driver().activate(username.clone(), 42).await.unwrap();

        let user = db::get_user_by_username(&mut ex, username).await.unwrap();
        assert!(user.activation_code().is_none());
    }

    #[tokio::test]
    async fn test_activate_bad_code() {
        let context = TestContext::setup().await;
        let mut ex = context.db().ex();

        let username = create_test_user(&mut ex, Some(42)).await;

        match context.driver().activate(username.clone(), 41).await {
            Err(DriverError::InvalidInput(e)) => assert!(e.contains("Invalid activation code")),
            e => panic!("{:?}", e),
        }

        let user = db::get_user_by_username(&mut ex, username).await.unwrap();
        assert!(user.activation_code().is_some());
    }

    #[tokio::test]
    async fn test_activate_already_active() {
        let context = TestContext::setup().await;
        let mut ex = context.db().ex();

        let username = create_test_user(&mut ex, None).await;

        match context.driver().activate(username.clone(), 1234).await {
            Err(DriverError::InvalidInput(e)) => assert!(e.contains("already active")),
            e => panic!("{:?}", e),
        }

        let user = db::get_user_by_username(&mut ex, username).await.unwrap();
        assert!(user.activation_code().is_none());
    }

    #[tokio::test]
    async fn test_user_not_found() {
        let context = TestContext::setup().await;
        let mut ex = context.db().ex();

        let username = Username::from("unknown");

        match context.driver().activate(username.clone(), 1234).await {
            Err(DriverError::NotFound(_)) => (),
            e => panic!("{:?}", e),
        }

        db::get_user_by_username(&mut ex, username).await.unwrap_err();
    }
}
