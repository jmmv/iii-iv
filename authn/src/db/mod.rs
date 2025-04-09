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

//! Database abstraction to manipulate users and authentication.

use crate::model::{AccessToken, HashedPassword, Session, User};
#[cfg(feature = "postgres")]
use iii_iv_core::db::postgres;
#[cfg(any(feature = "sqlite", test))]
use iii_iv_core::db::sqlite::{self, build_timestamp, unpack_timestamp};
use iii_iv_core::db::{DbError, DbResult, Executor};
use iii_iv_core::model::{EmailAddress, Username};
use sqlx::Row;
#[cfg(feature = "postgres")]
use sqlx::postgres::PgRow;
#[cfg(any(feature = "sqlite", test))]
use sqlx::sqlite::SqliteRow;
use time::OffsetDateTime;

#[cfg(test)]
mod tests;

/// Initializes the database schema.
pub async fn init_schema(ex: &mut Executor) -> DbResult<()> {
    match ex {
        #[cfg(feature = "postgres")]
        Executor::Postgres(ex) => postgres::run_schema(ex, include_str!("postgres.sql")).await,

        #[cfg(any(feature = "sqlite", test))]
        Executor::Sqlite(ex) => sqlite::run_schema(ex, include_str!("sqlite.sql")).await,

        #[allow(unused)]
        _ => unreachable!(),
    }
}

#[cfg(feature = "postgres")]
impl TryFrom<PgRow> for Session {
    type Error = DbError;

    fn try_from(row: PgRow) -> DbResult<Self> {
        let access_token: String = row.try_get("access_token").map_err(postgres::map_sqlx_error)?;
        let username: String = row.try_get("username").map_err(postgres::map_sqlx_error)?;
        let login_time: OffsetDateTime =
            row.try_get("login_time").map_err(postgres::map_sqlx_error)?;

        let access_token = AccessToken::new(access_token)?;
        let username = Username::new(username)?;

        Ok(Session::new(access_token, username, login_time))
    }
}

#[cfg(feature = "postgres")]
impl TryFrom<PgRow> for User {
    type Error = DbError;

    fn try_from(row: PgRow) -> DbResult<Self> {
        let username: String = row.try_get("username").map_err(postgres::map_sqlx_error)?;
        let password: Option<String> = row.try_get("password").map_err(postgres::map_sqlx_error)?;
        let email: String = row.try_get("email").map_err(postgres::map_sqlx_error)?;
        let activation_code: Option<i64> =
            row.try_get("activation_code").map_err(postgres::map_sqlx_error)?;
        let last_login: Option<OffsetDateTime> =
            row.try_get("last_login").map_err(postgres::map_sqlx_error)?;

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

#[cfg(any(feature = "sqlite", test))]
impl TryFrom<SqliteRow> for Session {
    type Error = DbError;

    fn try_from(row: SqliteRow) -> DbResult<Self> {
        let access_token: String = row.try_get("access_token").map_err(sqlite::map_sqlx_error)?;
        let username: String = row.try_get("username").map_err(sqlite::map_sqlx_error)?;
        let login_time_secs: i64 =
            row.try_get("login_time_secs").map_err(sqlite::map_sqlx_error)?;
        let login_time_nsecs: i64 =
            row.try_get("login_time_nsecs").map_err(sqlite::map_sqlx_error)?;

        let access_token = AccessToken::new(access_token)?;
        let username = Username::new(username)?;
        let login_time = build_timestamp(login_time_secs, login_time_nsecs)?;

        Ok(Session::new(access_token, username, login_time))
    }
}

#[cfg(any(feature = "sqlite", test))]
impl TryFrom<SqliteRow> for User {
    type Error = DbError;

    fn try_from(row: SqliteRow) -> DbResult<Self> {
        let username: String = row.try_get("username").map_err(sqlite::map_sqlx_error)?;
        let password: Option<String> = row.try_get("password").map_err(sqlite::map_sqlx_error)?;
        let email: String = row.try_get("email").map_err(sqlite::map_sqlx_error)?;
        let activation_code: Option<i64> =
            row.try_get("activation_code").map_err(sqlite::map_sqlx_error)?;
        let last_login_secs: Option<i64> =
            row.try_get("last_login_secs").map_err(sqlite::map_sqlx_error)?;
        let last_login_nsecs: Option<i64> =
            row.try_get("last_login_nsecs").map_err(sqlite::map_sqlx_error)?;

        let mut user = User::new(Username::new(username)?, EmailAddress::new(email)?)
            .with_activation_code(activation_code.map(|i| i as u64));
        if let Some(password) = password {
            user = user.with_password(HashedPassword::new(password));
        }
        match (last_login_secs, last_login_nsecs) {
            (Some(secs), Some(nsecs)) => user = user.with_last_login(build_timestamp(secs, nsecs)?),
            (None, None) => (),
            (_, _) => {
                return Err(DbError::DataIntegrityError(
                    "Inconsistent values for last_login".to_owned(),
                ));
            }
        }
        Ok(user)
    }
}

/// Creates a new user named `username`, with a `password` in hashed form and an `email` address.
/// The user is created as activated (no activation code) and as not having logged in.
pub async fn create_user(
    ex: &mut Executor,
    username: Username,
    password: Option<HashedPassword>,
    email: EmailAddress,
) -> DbResult<User> {
    let rows_affected = match ex {
        #[cfg(feature = "postgres")]
        Executor::Postgres(ex) => {
            let query_str = "INSERT INTO users (username, password, email) VALUES ($1, $2, $3)";
            let done = sqlx::query(query_str)
                .bind(username.as_str())
                .bind(password.as_ref().map(|x| Some(x.as_str())))
                .bind(email.as_str())
                .execute(ex)
                .await
                .map_err(postgres::map_sqlx_error)?;
            done.rows_affected()
        }

        #[cfg(any(feature = "sqlite", test))]
        Executor::Sqlite(ex) => {
            let query_str = "INSERT INTO users (username, password, email) VALUES (?, ?, ?)";
            let done = sqlx::query(query_str)
                .bind(username.as_str())
                .bind(password.as_ref().map(|x| Some(x.as_str())))
                .bind(email.as_str())
                .execute(ex)
                .await
                .map_err(sqlite::map_sqlx_error)?;
            done.rows_affected()
        }

        #[allow(unused)]
        _ => unreachable!(),
    };

    if rows_affected != 1 {
        return Err(DbError::BackendError("Insertion affected more than one row".to_owned()));
    }
    let mut user = User::new(username, email);
    if let Some(password) = password {
        user = user.with_password(password);
    }
    Ok(user)
}

/// Gets information about an existing user named `username`.
pub async fn get_user_by_username(ex: &mut Executor, username: Username) -> DbResult<User> {
    match ex {
        #[cfg(feature = "postgres")]
        Executor::Postgres(ex) => {
            let query_str = "SELECT * FROM users WHERE username = $1";
            let raw_user = sqlx::query(query_str)
                .bind(username.as_str())
                .fetch_one(ex)
                .await
                .map_err(postgres::map_sqlx_error)?;
            User::try_from(raw_user)
        }

        #[cfg(any(feature = "sqlite", test))]
        Executor::Sqlite(ex) => {
            let query_str = "SELECT * FROM users WHERE username = ?";
            let raw_user = sqlx::query(query_str)
                .bind(username.as_str())
                .fetch_one(ex)
                .await
                .map_err(sqlite::map_sqlx_error)?;
            User::try_from(raw_user)
        }

        #[allow(unused)]
        _ => unreachable!(),
    }
}

/// Updates an existing user `username` to have new `last_login` details.
pub(crate) async fn update_user(
    ex: &mut Executor,
    username: Username,
    last_login: OffsetDateTime,
) -> DbResult<()> {
    let rows_affected = match ex {
        #[cfg(feature = "postgres")]
        Executor::Postgres(ex) => {
            let query_str = "UPDATE users SET last_login = $1 WHERE username = $2";
            let done = sqlx::query(query_str)
                .bind(last_login)
                .bind(username.as_str())
                .execute(ex)
                .await
                .map_err(postgres::map_sqlx_error)?;
            done.rows_affected()
        }

        #[cfg(any(feature = "sqlite", test))]
        Executor::Sqlite(ex) => {
            let (last_login_secs, last_login_nsecs) = unpack_timestamp(last_login);

            let query_str = "
                UPDATE users SET last_login_secs = ?, last_login_nsecs = ?
                WHERE username = ?";
            let done = sqlx::query(query_str)
                .bind(last_login_secs)
                .bind(last_login_nsecs)
                .bind(username.as_str())
                .execute(ex)
                .await
                .map_err(sqlite::map_sqlx_error)?;
            done.rows_affected()
        }

        #[allow(unused)]
        _ => unreachable!(),
    };

    match rows_affected {
        0 => Err(DbError::NotFound),
        1 => Ok(()),
        _ => Err(DbError::BackendError("Update affected more than one row".to_owned())),
    }
}

/// Updates the activation code of an existing user, either to a new code or to nothing to
/// indicate that the user is active.
pub(crate) async fn set_user_activation_code(
    ex: &mut Executor,
    user: User,
    code: Option<u64>,
) -> DbResult<User> {
    let i64_code = code.map(|i| i as i64); // Sign is irrelevant for storage purposes.

    let rows_affected = match ex {
        #[cfg(feature = "postgres")]
        Executor::Postgres(ex) => {
            let query_str = "UPDATE users SET activation_code = $1 WHERE username = $2";
            let done = sqlx::query(query_str)
                .bind(i64_code)
                .bind(user.username().as_str())
                .execute(ex)
                .await
                .map_err(postgres::map_sqlx_error)?;
            done.rows_affected()
        }

        #[cfg(any(feature = "sqlite", test))]
        Executor::Sqlite(ex) => {
            let query_str = "UPDATE users SET activation_code = ? WHERE username = ?";
            let done = sqlx::query(query_str)
                .bind(i64_code)
                .bind(user.username().as_str())
                .execute(ex)
                .await
                .map_err(sqlite::map_sqlx_error)?;
            done.rows_affected()
        }

        #[allow(unused)]
        _ => unreachable!(),
    };

    match rows_affected {
        0 => Err(DbError::NotFound),
        1 => Ok(user.with_activation_code(code)),
        _ => Err(DbError::BackendError("Update affected more than one row".to_owned())),
    }
}

/// Gets a session from its access token.  Sessions marked as deleted (logged out) are
/// ignored.
pub(crate) async fn get_session(
    ex: &mut Executor,
    access_token: &AccessToken,
) -> DbResult<Session> {
    match ex {
        #[cfg(feature = "postgres")]
        Executor::Postgres(ex) => {
            let query_str = "
                SELECT access_token, username, login_time
                FROM sessions
                WHERE access_token = $1 AND logout_time IS NULL";
            let raw_session = sqlx::query(query_str)
                .bind(access_token.as_str())
                .fetch_one(ex)
                .await
                .map_err(postgres::map_sqlx_error)?;
            Session::try_from(raw_session)
        }

        #[cfg(any(feature = "sqlite", test))]
        Executor::Sqlite(ex) => {
            let query_str = "
                SELECT access_token, username, login_time_secs, login_time_nsecs
                FROM sessions
                WHERE
                    access_token = ? AND
                    logout_time_secs IS NULL AND
                    logout_time_nsecs IS NULL";
            let raw_session = sqlx::query(query_str)
                .bind(access_token.as_str())
                .fetch_one(ex)
                .await
                .map_err(sqlite::map_sqlx_error)?;
            Session::try_from(raw_session)
        }

        #[allow(unused)]
        _ => unreachable!(),
    }
}

/// Saves a session.
pub(crate) async fn put_session(ex: &mut Executor, session: &Session) -> DbResult<()> {
    let rows_affected = match ex {
        #[cfg(feature = "postgres")]
        Executor::Postgres(ex) => {
            let query_str =
                "INSERT INTO sessions (access_token, username, login_time) VALUES ($1, $2, $3)";

            let done = sqlx::query(query_str)
                .bind(session.access_token().as_str())
                .bind(session.username().as_str())
                .bind(session.login_time())
                .execute(ex)
                .await
                .map_err(postgres::map_sqlx_error)?;
            done.rows_affected()
        }

        #[cfg(any(feature = "sqlite", test))]
        Executor::Sqlite(ex) => {
            let (login_time_secs, login_time_nsecs) = unpack_timestamp(session.login_time());

            let query_str = "
                INSERT INTO sessions (access_token, username, login_time_secs, login_time_nsecs)
                VALUES (?, ?, ?, ?)";
            let done = sqlx::query(query_str)
                .bind(session.access_token().as_str())
                .bind(session.username().as_str())
                .bind(login_time_secs)
                .bind(login_time_nsecs)
                .execute(ex)
                .await
                .map_err(sqlite::map_sqlx_error)?;
            done.rows_affected()
        }

        #[allow(unused)]
        _ => unreachable!(),
    };

    if rows_affected != 1 {
        return Err(DbError::BackendError("Insertion affected more than one row".to_owned()));
    }
    Ok(())
}

/// Marks a session as deleted.
pub(crate) async fn delete_session(
    ex: &mut Executor,
    session: Session,
    now: OffsetDateTime,
) -> DbResult<()> {
    let rows_affected = match ex {
        #[cfg(feature = "postgres")]
        Executor::Postgres(ex) => {
            let query_str = "UPDATE sessions SET logout_time = $1 WHERE access_token = $2";
            let done = sqlx::query(query_str)
                .bind(now)
                .bind(session.access_token().as_str())
                .execute(ex)
                .await
                .map_err(postgres::map_sqlx_error)?;
            done.rows_affected()
        }

        #[cfg(any(feature = "sqlite", test))]
        Executor::Sqlite(ex) => {
            let (now_secs, now_nsecs) = unpack_timestamp(now);

            let query_str = "
                UPDATE sessions
                SET logout_time_secs = ?, logout_time_nsecs = ?
                WHERE access_token = ?";
            let done = sqlx::query(query_str)
                .bind(now_secs)
                .bind(now_nsecs)
                .bind(session.access_token().as_str())
                .execute(ex)
                .await
                .map_err(sqlite::map_sqlx_error)?;
            done.rows_affected()
        }

        #[allow(unused)]
        _ => unreachable!(),
    };

    if rows_affected != 1 {
        return Err(DbError::BackendError("UPDATE affected more than one row".to_owned()));
    }
    Ok(())
}
