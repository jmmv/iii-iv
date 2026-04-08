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

//! Extends the driver with the `change_password` method.

use crate::db;
use crate::driver::AuthnDriver;
use crate::driver::signup::password_validator;
use crate::model::{AccessToken, Password};
use iii_iv_core::db::DbError;
use iii_iv_core::driver::{DriverError, DriverResult};
use iii_iv_core::model::Username;

impl AuthnDriver {
    /// Changes the password for a user after verifying the old password.
    ///
    /// Invalidates all sessions for the user after successful password change.
    pub(crate) async fn change_password(
        self,
        token: AccessToken,
        username: Username,
        old_password: Password,
        new_password: Password,
    ) -> DriverResult<()> {
        let mut tx = self.db.begin().await?;
        let now = self.clock.now_utc();

        let session = match db::get_session(tx.ex(), &token).await {
            Ok(session) => session,
            Err(DbError::NotFound) => {
                return Err(DriverError::NotFound("Entity not found".to_owned()));
            }
            Err(e) => return Err(e.into()),
        };

        if session.username() != &username {
            return Err(DriverError::NotFound("Entity not found".to_owned()));
        }

        let user = match db::get_user_by_username(tx.ex(), username.clone()).await {
            Ok(user) => user,
            Err(DbError::NotFound) => {
                return Err(DriverError::NotFound("User not found".to_owned()));
            }
            Err(e) => return Err(e.into()),
        };

        let old_hash = match user.password() {
            Some(hash) => hash,
            None => {
                return Err(DriverError::Unauthorized(
                    "Password not set; cannot change".to_owned(),
                ));
            }
        };

        if !old_password.verify(old_hash)? {
            return Err(DriverError::InvalidInput("Invalid password".to_owned()));
        }

        if user.activation_code().is_some() {
            return Err(DriverError::NotActivated);
        }

        let new_password = new_password.validate_and_hash(password_validator)?;
        match db::update_user_password(tx.ex(), username.clone(), old_hash, new_password).await {
            Ok(()) => {}
            Err(DbError::NotFound) => {
                return Err(DriverError::InvalidInput(
                    "Password changed during update; please try again".to_owned(),
                ));
            }
            Err(e) => return Err(e.into()),
        }

        db::delete_sessions_for_user(tx.ex(), &username, now).await?;

        tx.commit().await?;

        let mut cache = self.sessions_cache.lock().await;
        cache.clear();

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::AuthnOptions;
    use crate::driver::testutils::*;
    use crate::model::{Session, password};
    use iii_iv_core::model::EmailAddress;

    #[tokio::test]
    async fn test_change_password_ok() {
        let context = TestContext::setup(AuthnOptions::default()).await;
        let username = Username::from("test");

        let token = context.do_test_login(username.clone()).await;

        let old_password = password!("test0password");
        let new_password = password!("new1password");

        context
            .driver()
            .change_password(token, username.clone(), old_password.clone(), new_password.clone())
            .await
            .unwrap();

        context.driver().login(username.clone(), new_password).await.unwrap();
    }

    #[tokio::test]
    async fn test_change_password_user_not_found() {
        let context = TestContext::setup(AuthnOptions::default()).await;
        let username = Username::from("test");

        let token = context.do_test_login(username.clone()).await;

        match context
            .driver()
            .change_password(
                token,
                Username::from("nonexistent"),
                password!("old0password"),
                password!("new1password"),
            )
            .await
        {
            Err(DriverError::NotFound(msg)) => assert!(msg.contains("Entity not found")),
            e => panic!("{:?}", e),
        }
    }

    #[tokio::test]
    async fn test_change_password_wrong_old_password() {
        let context = TestContext::setup(AuthnOptions::default()).await;
        let username = Username::from("test");

        let token = context.do_test_login(username.clone()).await;

        match context
            .driver()
            .change_password(
                token,
                username.clone(),
                password!("wrong0password"),
                password!("new1password"),
            )
            .await
        {
            Err(DriverError::InvalidInput(msg)) => assert!(msg.contains("Invalid password")),
            e => panic!("{:?}", e),
        }
    }

    #[tokio::test]
    async fn test_change_password_not_activated() {
        let context = TestContext::setup(AuthnOptions::default()).await;
        let username = Username::from("test");

        let password = password!("old0password");
        let email = EmailAddress::new("test@example.com").unwrap();
        context.driver().signup(username.clone(), password.clone(), email.clone()).await.unwrap();

        let token = {
            let mut tx = context.db().begin().await.unwrap();
            let _user = db::get_user_by_username(tx.ex(), username.clone()).await.unwrap();
            let access_token = AccessToken::generate();
            let session =
                Session::new(access_token.clone(), username.clone(), context.driver().now_utc());
            db::put_session(tx.ex(), &session).await.unwrap();
            db::update_user(tx.ex(), username.clone(), context.driver().now_utc()).await.unwrap();
            tx.commit().await.unwrap();
            access_token
        };

        match context
            .driver()
            .change_password(token, username.clone(), password.clone(), password!("new1password"))
            .await
        {
            Err(DriverError::NotActivated) => (),
            e => panic!("{:?}", e),
        }
    }

    #[tokio::test]
    async fn test_change_password_weak_new_password() {
        let context = TestContext::setup(AuthnOptions::default()).await;
        let username = Username::from("test");

        let token = context.do_test_login(username.clone()).await;

        let old_password = password!("test0password");
        for (new_password_str, error) in [
            ("a", "Too short"),
            ("abcdefg", "Too short"),
            ("long enough", "letters and numbers"),
            ("1234567890", "letters and numbers"),
        ] {
            match context
                .driver()
                .change_password(
                    token.clone(),
                    username.clone(),
                    old_password.clone(),
                    Password::new(new_password_str).unwrap(),
                )
                .await
            {
                Err(DriverError::InvalidInput(msg)) => {
                    assert!(msg.contains("Weak password"));
                    assert!(msg.contains(error));
                }
                e => panic!("{:?}", e),
            }
        }
    }

    #[tokio::test]
    async fn test_change_password_invalidates_sessions() {
        let context = TestContext::setup(AuthnOptions::default()).await;
        let username = Username::from("test");

        let token = context.do_test_login(username.clone()).await;

        let old_password = password!("test0password");
        let new_password = password!("new1password");

        context
            .driver()
            .change_password(
                token.clone(),
                username.clone(),
                old_password.clone(),
                new_password.clone(),
            )
            .await
            .unwrap();

        match db::get_session(&mut context.ex().await, &token).await {
            Err(DbError::NotFound) => (),
            e => panic!("{:?}", e),
        }
    }

    #[tokio::test]
    async fn test_change_password_wrong_old_password_after_change() {
        let context = TestContext::setup(AuthnOptions::default()).await;
        let username = Username::from("test");

        let token = context.do_test_login(username.clone()).await;

        context
            .driver()
            .change_password(
                token.clone(),
                username.clone(),
                password!("test0password"),
                password!("new1password"),
            )
            .await
            .unwrap();

        match context
            .driver()
            .change_password(
                token,
                username.clone(),
                password!("test0password"),
                password!("another1password"),
            )
            .await
        {
            Err(DriverError::NotFound(msg)) => {
                assert!(msg.contains("Entity not found"))
            }
            e => panic!("{:?}", e),
        }
    }
}
