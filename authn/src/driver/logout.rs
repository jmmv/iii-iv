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

//! Extends the driver with the `logout` method.

use crate::db;
use crate::driver::AuthnDriver;
use crate::model::AccessToken;
use iii_iv_core::driver::{DriverError, DriverResult};
use iii_iv_core::model::Username;

impl AuthnDriver {
    /// Marks a session as deleted.
    pub(crate) async fn logout(self, token: AccessToken, username: Username) -> DriverResult<()> {
        let mut tx = self.db.begin().await?;
        let now = self.clock.now_utc();

        let session = db::get_session(tx.ex(), &token).await?;
        if session.username() != &username {
            return Err(DriverError::NotFound("Entity not found".to_owned()));
        }
        db::delete_session(tx.ex(), session, now).await?;

        tx.commit().await?;

        // Removing the session from the cache is only a best-effort operation.  If we end up with
        // multiple instances of a frontend running at once, there is no easy way to perform cache
        // invalidation across all of them.  But we don't know how this code is consumed (maybe it
        // is part of a single-instance server instead of a lambda-style deployment), so let's try
        // to do the right thing.
        let mut cache = self.sessions_cache.lock().await;
        let _previous = cache.remove(&token);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::AuthnOptions;
    use crate::driver::testutils::*;
    use iii_iv_core::db::DbError;
    use std::time::Duration;

    #[tokio::test]
    async fn test_ok() {
        let context = TestContext::setup(AuthnOptions::default()).await;

        let username = Username::from("test");

        let token = context.do_test_login(username.clone()).await;
        context.driver().logout(token.clone(), username).await.unwrap();

        match db::get_session(&mut context.ex().await, &token).await {
            Err(DbError::NotFound) => (),
            e => panic!("{:?}", e),
        }
    }

    #[tokio::test]
    async fn test_not_found() {
        let context = TestContext::setup(AuthnOptions::default()).await;

        let username1 = Username::from("test1");

        let token1 = context.do_test_login(username1.clone()).await;
        let token2 = context.do_test_login(Username::from("test2")).await;
        context.driver().logout(token1.clone(), username1).await.unwrap();

        db::get_session(&mut context.ex().await, &token1).await.unwrap_err();
        db::get_session(&mut context.ex().await, &token2).await.unwrap();
    }

    #[tokio::test]
    async fn test_invalid_user_error() {
        let context = TestContext::setup(AuthnOptions::default()).await;

        let username1 = Username::from("test1");
        let username2 = Username::from("test2");

        let token1 = context.do_test_login(username1.clone()).await;
        let err1 = context.driver().logout(token1.clone(), username2).await.unwrap_err();
        context.driver().logout(token1.clone(), username1.clone()).await.unwrap();
        let err2 = context.driver().logout(token1.clone(), username1).await.unwrap_err();

        assert_eq!(err1, err2);
    }

    #[tokio::test]
    async fn test_remove_from_sessions_cache() {
        // Configure a cache with just one entry and "infinite" duration so that we can precisely
        // control when entries get evicted.
        let opts = AuthnOptions {
            sessions_cache_capacity: 1,
            sessions_cache_ttl: Duration::from_secs(900),
            ..Default::default()
        };
        let context = TestContext::setup(opts).await;

        let username = Username::from("test");

        assert_eq!(0, context.driver().sessions_cache.lock().await.len());
        let token = context.do_test_login(username.clone()).await;

        let mut tx = context.db().begin().await.unwrap();
        let _user = context
            .driver()
            .get_session(&mut tx, context.driver().now_utc(), token.clone())
            .await
            .unwrap();
        tx.commit().await.unwrap();
        assert_eq!(1, context.driver().sessions_cache.lock().await.len());

        context.driver().logout(token.clone(), username).await.unwrap();
        assert_eq!(0, context.driver().sessions_cache.lock().await.len());
    }
}
