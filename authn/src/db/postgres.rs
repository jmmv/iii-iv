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

//! Implementation of the database abstraction using PostgreSQL.

use crate::db::AuthnTx;
use crate::model::{AccessToken, HashedPassword, Session, User};
use iii_iv_core::db::{BareTx, DbError, DbResult};
use iii_iv_core::model::{EmailAddress, Username};
use iii_iv_postgres::{map_sqlx_error, run_schema};
use sqlx::postgres::{PgRow, Postgres};
use sqlx::{Row, Transaction};
use std::convert::TryFrom;
use time::OffsetDateTime;

/// Schema to use to initialize the database.
const SCHEMA: &str = include_str!("postgres_schema.sql");

impl TryFrom<PgRow> for Session {
    type Error = DbError;

    fn try_from(row: PgRow) -> DbResult<Self> {
        let access_token: String = row.try_get("access_token").map_err(map_sqlx_error)?;
        let username: String = row.try_get("username").map_err(map_sqlx_error)?;
        let login_time: OffsetDateTime = row.try_get("login_time").map_err(map_sqlx_error)?;

        let access_token = AccessToken::new(access_token)?;
        let username = Username::new(username)?;

        Ok(Session::new(access_token, username, login_time))
    }
}

impl TryFrom<PgRow> for User {
    type Error = DbError;

    fn try_from(row: PgRow) -> DbResult<Self> {
        let username: String = row.try_get("username").map_err(map_sqlx_error)?;
        let password: Option<String> = row.try_get("password").map_err(map_sqlx_error)?;
        let email: String = row.try_get("email").map_err(map_sqlx_error)?;
        let activation_code: Option<i64> =
            row.try_get("activation_code").map_err(map_sqlx_error)?;
        let last_login: Option<OffsetDateTime> =
            row.try_get("last_login").map_err(map_sqlx_error)?;

        let mut user = User::new(Username::new(username)?, EmailAddress::new(email)?)
            .with_activation_code(activation_code.map(|i| i as u64));
        if let Some(password) = password {
            user = user.with_password(HashedPassword::new(password));
        }
        if let Some(last_login) = last_login {
            user = user.with_last_login(last_login);
        }
        Ok(user)
    }
}

/// A transaction backed by a PostgreSQL database.
pub struct PostgresAuthnTx {
    /// The PostgreSQL transaction itself.
    tx: Transaction<'static, Postgres>,
}

impl From<Transaction<'static, Postgres>> for PostgresAuthnTx {
    fn from(tx: Transaction<'static, Postgres>) -> Self {
        Self { tx }
    }
}

#[async_trait::async_trait]
impl BareTx for PostgresAuthnTx {
    async fn commit(mut self) -> DbResult<()> {
        self.tx.commit().await.map_err(map_sqlx_error)
    }

    async fn migrate(&mut self) -> DbResult<()> {
        run_schema(&mut self.tx, SCHEMA).await
    }
}

#[async_trait::async_trait]
impl AuthnTx for PostgresAuthnTx {
    async fn create_user(
        &mut self,
        username: Username,
        password: Option<HashedPassword>,
        email: EmailAddress,
    ) -> DbResult<User> {
        let query_str = "INSERT INTO users (username, password, email) VALUES ($1, $2, $3)";
        let done = sqlx::query(query_str)
            .bind(username.as_str())
            .bind(password.as_ref().map(|x| Some(x.as_str())))
            .bind(email.as_str())
            .execute(&mut self.tx)
            .await
            .map_err(map_sqlx_error)?;
        if done.rows_affected() != 1 {
            return Err(DbError::BackendError("Insertion affected more than one row".to_owned()));
        }
        let mut user = User::new(username, email);
        if let Some(password) = password {
            user = user.with_password(password);
        }
        Ok(user)
    }

    async fn get_user_by_username(&mut self, username: Username) -> DbResult<User> {
        let query_str = "SELECT * FROM users WHERE username = $1";
        let raw_user = sqlx::query(query_str)
            .bind(username.as_str())
            .fetch_one(&mut self.tx)
            .await
            .map_err(map_sqlx_error)?;
        User::try_from(raw_user)
    }

    async fn update_user(
        &mut self,
        username: Username,
        last_login: OffsetDateTime,
    ) -> DbResult<()> {
        let query_str = "UPDATE users SET last_login = $1 WHERE username = $2";
        let done = sqlx::query(query_str)
            .bind(last_login)
            .bind(username.as_str())
            .execute(&mut self.tx)
            .await
            .map_err(map_sqlx_error)?;
        match done.rows_affected() {
            0 => Err(DbError::NotFound),
            1 => Ok(()),
            _ => Err(DbError::BackendError("Update affected more than one row".to_owned())),
        }
    }

    async fn set_user_activation_code(&mut self, user: User, code: Option<u64>) -> DbResult<User> {
        let query_str = "UPDATE users SET activation_code = $1 WHERE username = $2";
        let done = sqlx::query(query_str)
            .bind(code.map(|i| i as i64)) // Sign is irrelevant for storage purposes.
            .bind(user.username().as_str())
            .execute(&mut self.tx)
            .await
            .map_err(map_sqlx_error)?;
        match done.rows_affected() {
            0 => Err(DbError::NotFound),
            1 => Ok(user.with_activation_code(code)),
            _ => Err(DbError::BackendError("Update affected more than one row".to_owned())),
        }
    }

    async fn get_session(&mut self, access_token: &AccessToken) -> DbResult<Session> {
        let query_str = "
            SELECT access_token, username, login_time
            FROM sessions
            WHERE access_token = $1 AND logout_time IS NULL";
        let raw_session = sqlx::query(query_str)
            .bind(access_token.as_str())
            .fetch_one(&mut self.tx)
            .await
            .map_err(map_sqlx_error)?;
        Session::try_from(raw_session)
    }

    async fn put_session(&mut self, session: &Session) -> DbResult<()> {
        let query_str =
            "INSERT INTO sessions (access_token, username, login_time) VALUES ($1, $2, $3)";

        let done = sqlx::query(query_str)
            .bind(session.access_token().as_str())
            .bind(session.username().as_str())
            .bind(session.login_time())
            .execute(&mut self.tx)
            .await
            .map_err(map_sqlx_error)?;
        if done.rows_affected() != 1 {
            return Err(DbError::BackendError("Insertion affected more than one row".to_owned()));
        }
        Ok(())
    }

    async fn delete_session(&mut self, session: Session, now: OffsetDateTime) -> DbResult<()> {
        let query_str = "UPDATE sessions SET logout_time = $1 WHERE access_token = $2";
        let done = sqlx::query(query_str)
            .bind(now)
            .bind(session.access_token().as_str())
            .execute(&mut self.tx)
            .await
            .map_err(map_sqlx_error)?;
        if done.rows_affected() != 1 {
            return Err(DbError::BackendError("UPDATE affected more than one row".to_owned()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::tests::generate_db_tests;

    generate_db_tests!(
        iii_iv_postgres::testutils::setup::<PostgresAuthnTx>().await,
        #[ignore = "Requires environment configuration and is expensive"]
    );
}
