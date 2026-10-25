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
use crate::driver::{AuthnDriver, AuthnHooks};
use crate::model::AccessToken;
use iii_iv_core::driver::DriverResult;

impl<H: AuthnHooks> AuthnDriver<H> {
    /// Marks a session as deleted.
    pub(crate) async fn logout(self, token: AccessToken) -> DriverResult<()> {
        let mut tx = self.db.begin().await?;
        let now = self.clock.now_utc();

        let session = db::get_session(tx.ex(), &token).await?;
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
    use iii_iv_core::clocks::Clock;
    use iii_iv_core::clocks::testutils::SettableClock;
    use iii_iv_core::db::Db;
    use iii_iv_core::db::DbError;
    use iii_iv_core::driver::DriverError;
    use iii_iv_core::model::username;
    use std::sync::Arc;
    use std::time::Duration;
    use time::macros::datetime;

    #[tokio::test]
    async fn test_ok() {
        let context = TestContext::setup(AuthnOptions::default()).await;

        let username = username!("test");

        let token = context.do_test_login(username.clone()).await;
        context.driver().logout(token.clone()).await.unwrap();

        match db::get_session(&mut context.ex().await, &token).await {
            Err(DbError::NotFound) => (),
            e => panic!("{:?}", e),
        }
    }

    #[tokio::test]
    async fn test_not_found() {
        let context = TestContext::setup(AuthnOptions::default()).await;

        let username1 = username!("test1");

        let token1 = context.do_test_login(username1.clone()).await;
        let token2 = context.do_test_login(username!("test2")).await;
        context.driver().logout(token1.clone()).await.unwrap();

        db::get_session(&mut context.ex().await, &token1).await.unwrap_err();
        db::get_session(&mut context.ex().await, &token2).await.unwrap();
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

        let username = username!("test");

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

        context.driver().logout(token.clone()).await.unwrap();
        assert_eq!(0, context.driver().sessions_cache.lock().await.len());
    }

    #[tokio::test]
    async fn test_logout_visible_across_drivers_by_default() {
        let db: Arc<dyn Db + Send + Sync> =
            Arc::from(iii_iv_core::db::sqlite::testutils::setup().await);
        let clock: Arc<dyn Clock + Send + Sync> =
            Arc::from(SettableClock::new(datetime!(2023-12-01 05:50:00 UTC)));
        let first = TestContext::setup_with(
            AuthnOptions::default(),
            db.clone(),
            clock.clone(),
            "the-realm",
            true,
        )
        .await;
        let second =
            TestContext::setup_with(AuthnOptions::default(), db, clock, "the-realm", true).await;
        let token = first.do_test_login(username!("test")).await;

        let mut tx = second.db().begin().await.unwrap();
        second
            .driver()
            .get_session(&mut tx, second.driver().now_utc(), token.clone())
            .await
            .unwrap();
        tx.commit().await.unwrap();

        first.driver().logout(token.clone()).await.unwrap();

        let mut tx = second.db().begin().await.unwrap();
        match second.driver().get_session(&mut tx, second.driver().now_utc(), token).await {
            Err(DriverError::Unauthenticated) => {}
            e => panic!("{:?}", e),
        }
    }

    #[tokio::test]
    async fn test_logout_cache_delay_is_not_extended_by_access() {
        let cache_ttl = Duration::from_secs(2);
        let lookup_interval = Duration::from_millis(1200);
        let opts = AuthnOptions { sessions_cache_ttl: cache_ttl, ..Default::default() };
        let db: Arc<dyn Db + Send + Sync> =
            Arc::from(iii_iv_core::db::sqlite::testutils::setup().await);
        let clock: Arc<dyn Clock + Send + Sync> =
            Arc::from(SettableClock::new(datetime!(2023-12-01 05:50:00 UTC)));
        let first =
            TestContext::setup_with(opts.clone(), db.clone(), clock.clone(), "the-realm", true)
                .await;
        let second = TestContext::setup_with(opts, db, clock, "the-realm", true).await;
        let token = first.do_test_login(username!("test")).await;

        let mut tx = second.db().begin().await.unwrap();
        second
            .driver()
            .get_session(&mut tx, second.driver().now_utc(), token.clone())
            .await
            .unwrap();
        tx.commit().await.unwrap();

        first.driver().logout(token.clone()).await.unwrap();

        let mut tx = second.db().begin().await.unwrap();
        second
            .driver()
            .get_session(&mut tx, second.driver().now_utc(), token.clone())
            .await
            .unwrap();
        tx.commit().await.unwrap();

        // The first delayed lookup occurs within the original TTL.  The second occurs after it and
        // must miss the cache even though the first lookup accessed the entry.
        std::thread::sleep(lookup_interval);
        let mut tx = second.db().begin().await.unwrap();
        second
            .driver()
            .get_session(&mut tx, second.driver().now_utc(), token.clone())
            .await
            .unwrap();
        tx.commit().await.unwrap();

        std::thread::sleep(lookup_interval);
        let mut tx = second.db().begin().await.unwrap();
        match second.driver().get_session(&mut tx, second.driver().now_utc(), token).await {
            Err(DriverError::Unauthenticated) => {}
            e => panic!("{:?}", e),
        }
    }
}
