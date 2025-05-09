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

//! Extends the driver with the `login` method.

use crate::db;
use crate::driver::AuthnDriver;
use crate::model::{AccessToken, Password, Session};
use iii_iv_core::db::DbError;
use iii_iv_core::driver::{DriverError, DriverResult};
use iii_iv_core::model::Username;
use std::sync::Arc;

impl AuthnDriver {
    /// Logs a user with `username` and `password`.
    pub(crate) async fn login(
        self,
        username: Username,
        password: Password,
    ) -> DriverResult<Session> {
        let mut tx = self.db.begin().await?;
        let now = self.clock.now_utc();

        let user = match db::get_user_by_username(tx.ex(), username.clone()).await {
            Ok(user) => user,
            Err(DbError::NotFound) => {
                return Err(DriverError::Unauthorized("Unknown user".to_owned()));
            }
            Err(e) => return Err(e.into()),
        };

        match user.password() {
            Some(hash) => {
                if !password.verify(hash)? {
                    return Err(DriverError::Unauthorized("Invalid password".to_owned()));
                }
            }
            None => return Err(DriverError::Unauthorized("Login not allowed".to_owned())),
        };

        if user.activation_code().is_some() {
            return Err(DriverError::NotActivated);
        }

        let access_token = AccessToken::generate();
        let session = Session::new(access_token.clone(), username.clone(), now);
        db::put_session(tx.ex(), &session).await?;

        db::update_user(tx.ex(), username.clone(), now).await?;

        tx.commit().await.unwrap();

        let mut cache = self.sessions_cache.lock().await;
        let previous = cache.insert(access_token, Ok(Arc::from(user)));
        assert!(previous.is_none(), "The session has not yet been returned to the client");

        Ok(session)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::AuthnOptions;
    use crate::driver::testutils::*;
    use iii_iv_core::model::EmailAddress;
    use time::OffsetDateTime;

    #[tokio::test]
    async fn test_login_ok_first_time() {
        let context = TestContext::setup(AuthnOptions::default()).await;

        let username = Username::from("hello");
        let password = Password::from("password");

        db::create_user(
            &mut context.ex().await,
            username.clone(),
            Some(password.clone().validate_and_hash(|_| None).unwrap()),
            EmailAddress::from("some@example.com"),
        )
        .await
        .unwrap();

        let before = context.driver().now_utc();
        let response = context.driver().login(username.clone(), password).await.unwrap();
        let after = context.driver().now_utc();

        let session =
            db::get_session(&mut context.ex().await, response.access_token()).await.unwrap();
        assert_eq!(&username, session.username());
        assert!(session.login_time() >= before && session.login_time() <= after);
        let user = db::get_user_by_username(&mut context.ex().await, username).await.unwrap();
        assert!(user.last_login().unwrap() >= before && user.last_login().unwrap() <= after);
        assert_eq!(&EmailAddress::from("some@example.com"), user.email());
    }

    #[tokio::test]
    async fn test_login_ok_returning() {
        let context = TestContext::setup(AuthnOptions::default()).await;

        let username = Username::from("hello");
        let password = Password::from("password");

        db::create_user(
            &mut context.ex().await,
            username.clone(),
            Some(password.clone().validate_and_hash(|_| None).unwrap()),
            EmailAddress::from("some@example.com"),
        )
        .await
        .unwrap();
        db::update_user(
            &mut context.ex().await,
            username.clone(),
            OffsetDateTime::from_unix_timestamp(1).unwrap(),
        )
        .await
        .unwrap();

        let before = context.driver().now_utc();
        let response = context.driver().login(username.clone(), password).await.unwrap();
        let after = context.driver().now_utc();

        let session =
            db::get_session(&mut context.ex().await, response.access_token()).await.unwrap();
        assert_eq!(&username, session.username());
        assert!(session.login_time() >= before && session.login_time() <= after);
        let user = db::get_user_by_username(&mut context.ex().await, username).await.unwrap();
        assert!(user.last_login().unwrap() >= before && user.last_login().unwrap() <= after);
        assert_eq!(&EmailAddress::from("some@example.com"), user.email());
    }

    #[tokio::test]
    async fn test_login_unknown_user() {
        let context = TestContext::setup(AuthnOptions::default()).await;

        match context.driver().login(Username::from("foo"), Password::from("bar")).await {
            Err(DriverError::Unauthorized(msg)) => assert!(msg.contains("Unknown user")),
            e => panic!("{:?}", e),
        }
    }

    #[tokio::test]
    async fn test_login_invalid_password() {
        let context = TestContext::setup(AuthnOptions::default()).await;

        let username = Username::from("hello");

        db::create_user(
            &mut context.ex().await,
            username.clone(),
            Some(Password::new("ABC").unwrap().validate_and_hash(|_| None).unwrap()),
            EmailAddress::from("some@example.com"),
        )
        .await
        .unwrap();

        match context.driver().login(username, Password::from("abc")).await {
            Err(DriverError::Unauthorized(msg)) => assert!(msg.contains("Invalid password")),
            e => panic!("{:?}", e),
        }
    }

    #[tokio::test]
    async fn test_login_not_allowed() {
        let context = TestContext::setup(AuthnOptions::default()).await;

        let username = Username::from("hello");

        db::create_user(
            &mut context.ex().await,
            username.clone(),
            None,
            EmailAddress::from("some@example.com"),
        )
        .await
        .unwrap();

        match context.driver().login(username, Password::from("irrelevant")).await {
            Err(DriverError::Unauthorized(msg)) => assert!(msg.contains("Login not allowed")),
            e => panic!("{:?}", e),
        }
    }

    #[tokio::test]
    async fn test_login_not_activated() {
        let context = TestContext::setup(AuthnOptions::default()).await;

        let username = Username::from("hello");
        let password = Password::from("password");

        let user = db::create_user(
            &mut context.ex().await,
            username.clone(),
            Some(password.clone().validate_and_hash(|_| None).unwrap()),
            EmailAddress::from("some@example.com"),
        )
        .await
        .unwrap();
        db::set_user_activation_code(&mut context.ex().await, user, Some(50)).await.unwrap();

        match context.driver().login(username, password).await {
            Err(DriverError::NotActivated) => (),
            e => panic!("{:?}", e),
        }
    }

    #[tokio::test]
    async fn test_login_inserts_session_into_cache() {
        let context = TestContext::setup(AuthnOptions::default()).await;

        let username = Username::from("hello");
        let password = Password::from("password");

        db::create_user(
            &mut context.ex().await,
            username.clone(),
            Some(password.clone().validate_and_hash(|_| None).unwrap()),
            EmailAddress::from("some@example.com"),
        )
        .await
        .unwrap();

        assert_eq!(0, context.driver().sessions_cache.lock().await.len());
        let response = context.driver().login(username.clone(), password).await.unwrap();
        let driver = context.driver();
        let cache = driver.sessions_cache.lock().await;
        assert_eq!(1, cache.len());
        assert!(cache.contains_key(response.access_token()));
    }
}
