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

use crate::db::AuthnTx;
use crate::driver::AuthnDriver;
use crate::model::AccessToken;
use iii_iv_core::clocks::Clock;
use iii_iv_core::db::{BareTx, Db};
use iii_iv_core::driver::{DriverError, DriverResult};
use iii_iv_core::model::Username;
use iii_iv_lettre::SmtpMailer;

impl<C, D, M> AuthnDriver<C, D, M>
where
    C: Clock + Clone + Send + Sync + 'static,
    D: Db + Clone + Send + Sync + 'static,
    D::Tx: AuthnTx + From<D::SqlxTx> + Send + Sync + 'static,
    M: SmtpMailer + Clone + Send + Sync + 'static,
{
    /// Marks a session as deleted.
    pub(crate) async fn logout(self, token: AccessToken, username: Username) -> DriverResult<()> {
        let mut tx = self.db.begin().await?;
        let now = self.clock.now_utc();

        let session = tx.get_session(&token).await?;
        if session.username() != &username {
            return Err(DriverError::NotFound("Entity not found".to_owned()));
        }
        tx.delete_session(session, now).await?;

        tx.commit().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::testutils::*;
    use iii_iv_core::db::DbError;

    #[tokio::test]
    async fn test_ok() {
        let context = TestContext::setup().await;

        let username = Username::from("test");

        let token = context.do_test_login(username.clone()).await;
        context.driver().logout(token.clone(), username).await.unwrap();

        let mut tx = context.tx().await;
        match tx.get_session(&token).await {
            Err(DbError::NotFound) => (),
            e => panic!("{:?}", e),
        }
    }

    #[tokio::test]
    async fn test_not_found() {
        let context = TestContext::setup().await;

        let username1 = Username::from("test1");

        let token1 = context.do_test_login(username1.clone()).await;
        let token2 = context.do_test_login(Username::from("test2")).await;
        context.driver().logout(token1.clone(), username1).await.unwrap();

        let mut tx = context.tx().await;
        tx.get_session(&token1).await.unwrap_err();
        tx.get_session(&token2).await.unwrap();
    }

    #[tokio::test]
    async fn test_invalid_user_error() {
        let context = TestContext::setup().await;

        let username1 = Username::from("test1");
        let username2 = Username::from("test2");

        let token1 = context.do_test_login(username1.clone()).await;
        let err1 = context.driver().logout(token1.clone(), username2).await.unwrap_err();
        context.driver().logout(token1.clone(), username1.clone()).await.unwrap();
        let err2 = context.driver().logout(token1.clone(), username1).await.unwrap_err();

        assert_eq!(err1, err2);
    }
}
