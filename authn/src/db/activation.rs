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

//! Persistence of pending account activation.

use crate::db::{clear_failures, get_user_by_id, lock_failures};
use crate::model::{ActivationState, FailureOperation, User};
#[cfg(feature = "postgres")]
use iii_iv_core::db::postgres;
#[cfg(any(feature = "sqlite", test))]
use iii_iv_core::db::sqlite::{self, build_timestamp, unpack_timestamp};
use iii_iv_core::db::{DbError, DbResult, Executor};
use sqlx::Row;
#[cfg(feature = "postgres")]
use sqlx::postgres::PgRow;
#[cfg(any(feature = "sqlite", test))]
use sqlx::sqlite::SqliteRow;
use time::OffsetDateTime;
use uuid::Uuid;

#[cfg(feature = "postgres")]
impl TryFrom<PgRow> for ActivationState {
    type Error = DbError;

    fn try_from(row: PgRow) -> DbResult<Self> {
        let code: i64 = row.try_get("code").map_err(postgres::map_sqlx_error)?;
        Ok(Self {
            code: code as u64,
            issued_at: row.try_get("issued_at").map_err(postgres::map_sqlx_error)?,
            expires_at: row.try_get("expires_at").map_err(postgres::map_sqlx_error)?,
        })
    }
}

#[cfg(any(feature = "sqlite", test))]
impl TryFrom<SqliteRow> for ActivationState {
    type Error = DbError;

    fn try_from(row: SqliteRow) -> DbResult<Self> {
        let code: i64 = row.try_get("code").map_err(sqlite::map_sqlx_error)?;
        Ok(Self {
            code: code as u64,
            issued_at: build_timestamp(
                row.try_get("issued_at_secs").map_err(sqlite::map_sqlx_error)?,
                row.try_get("issued_at_nsecs").map_err(sqlite::map_sqlx_error)?,
            )?,
            expires_at: build_timestamp(
                row.try_get("expires_at_secs").map_err(sqlite::map_sqlx_error)?,
                row.try_get("expires_at_nsecs").map_err(sqlite::map_sqlx_error)?,
            )?,
        })
    }
}

/// Reads pending activation state.
pub async fn get_user_activation(
    ex: &mut Executor,
    user_id: Uuid,
) -> DbResult<Option<ActivationState>> {
    match ex {
        #[cfg(feature = "postgres")]
        Executor::Postgres(ex) => {
            let row = sqlx::query("SELECT * FROM activation_state WHERE user_id = $1")
                .bind(user_id)
                .fetch_optional(ex)
                .await
                .map_err(postgres::map_sqlx_error)?;
            row.map(ActivationState::try_from).transpose()
        }

        #[cfg(any(feature = "sqlite", test))]
        Executor::Sqlite(ex) => {
            let row = sqlx::query("SELECT * FROM activation_state WHERE user_id = ?")
                .bind(user_id)
                .fetch_optional(ex)
                .await
                .map_err(sqlite::map_sqlx_error)?;
            row.map(ActivationState::try_from).transpose()
        }

        #[allow(unused)]
        _ => unreachable!(),
    }
}

/// Inserts or clears activation state and resets activation failures atomically.
///
/// Returns `DbError::AlreadyExists` if the user already has pending activation.
///
/// Call within a transaction, before reads unless a write lock is already held.
pub async fn set_user_activation(
    ex: &mut Executor,
    user: User,
    activation: Option<ActivationState>,
) -> DbResult<User> {
    let now = activation.as_ref().map_or(OffsetDateTime::UNIX_EPOCH, |state| state.issued_at);
    lock_failures(ex, user.id, FailureOperation::Activation, now).await?;
    match ex {
        #[cfg(feature = "postgres")]
        Executor::Postgres(ex) => match activation {
            None => {
                sqlx::query("DELETE FROM activation_state WHERE user_id = $1")
                    .bind(user.id)
                    .execute(ex)
                    .await
                    .map_err(postgres::map_sqlx_error)?;
            }

            Some(activation) => {
                sqlx::query(
                    "INSERT INTO activation_state (user_id, code, issued_at, expires_at)
                        VALUES ($1, $2, $3, $4)",
                )
                .bind(user.id)
                .bind(activation.code as i64)
                .bind(activation.issued_at)
                .bind(activation.expires_at)
                .execute(ex)
                .await
                .map_err(postgres::map_sqlx_error)?;
            }
        },

        #[cfg(any(feature = "sqlite", test))]
        Executor::Sqlite(ex) => match activation {
            None => {
                sqlx::query("DELETE FROM activation_state WHERE user_id = ?")
                    .bind(user.id)
                    .execute(ex)
                    .await
                    .map_err(sqlite::map_sqlx_error)?;
            }

            Some(activation) => {
                let (issued_secs, issued_nsecs) = unpack_timestamp(activation.issued_at);
                let (expires_secs, expires_nsecs) = unpack_timestamp(activation.expires_at);
                sqlx::query(
                    "INSERT INTO activation_state (user_id, code, issued_at_secs, issued_at_nsecs,
                        expires_at_secs, expires_at_nsecs) VALUES (?, ?, ?, ?, ?, ?)",
                )
                .bind(user.id)
                .bind(activation.code as i64)
                .bind(issued_secs)
                .bind(issued_nsecs)
                .bind(expires_secs)
                .bind(expires_nsecs)
                .execute(ex)
                .await
                .map_err(sqlite::map_sqlx_error)?;
            }
        },

        #[allow(unused)]
        _ => unreachable!(),
    }
    clear_failures(ex, user.id, FailureOperation::Activation).await?;
    get_user_by_id(ex, user.id).await
}

/// Atomically consumes a matching, unexpired code.  Returns whether activation succeeded.
pub async fn consume_user_activation(
    ex: &mut Executor,
    user_id: Uuid,
    code: u64,
    now: OffsetDateTime,
) -> DbResult<bool> {
    let affected = match ex {
        #[cfg(feature = "postgres")]
        Executor::Postgres(ex) => sqlx::query(
            "DELETE FROM activation_state WHERE user_id = $1 AND code = $2 AND expires_at > $3",
        )
        .bind(user_id)
        .bind(code as i64)
        .bind(now)
        .execute(ex)
        .await
        .map_err(postgres::map_sqlx_error)?
        .rows_affected(),

        #[cfg(any(feature = "sqlite", test))]
        Executor::Sqlite(ex) => {
            let (secs, nsecs) = unpack_timestamp(now);
            sqlx::query(
                "DELETE FROM activation_state WHERE user_id = ? AND code = ?
                AND (expires_at_secs > ? OR (expires_at_secs = ? AND expires_at_nsecs > ?))",
            )
            .bind(user_id)
            .bind(code as i64)
            .bind(secs)
            .bind(secs)
            .bind(nsecs)
            .execute(ex)
            .await
            .map_err(sqlite::map_sqlx_error)?
            .rows_affected()
        }

        #[allow(unused)]
        _ => unreachable!(),
    };
    Ok(affected == 1)
}
