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

//! Abuse protection.

use crate::model::{FailureHistory, FailureOperation};
#[cfg(feature = "postgres")]
use iii_iv_core::db::postgres;
#[cfg(any(feature = "sqlite", test))]
use iii_iv_core::db::sqlite::{self, build_timestamp, unpack_timestamp};
use iii_iv_core::db::{DbError, DbResult, Executor, ensure_one_upsert};
use sqlx::Row;
#[cfg(feature = "postgres")]
use sqlx::postgres::PgRow;
#[cfg(any(feature = "sqlite", test))]
use sqlx::sqlite::SqliteRow;
use time::OffsetDateTime;
use uuid::Uuid;

#[cfg(feature = "postgres")]
impl TryFrom<PgRow> for FailureHistory {
    type Error = DbError;

    fn try_from(row: PgRow) -> DbResult<Self> {
        let count: i64 = row.try_get("failure_count").map_err(postgres::map_sqlx_error)?;
        Ok(Self {
            count: u32::try_from(count).map_err(|e| DbError::DataIntegrityError(e.to_string()))?,
            last_failure: row.try_get("last_failure").map_err(postgres::map_sqlx_error)?,
            blocked_until: row.try_get("blocked_until").map_err(postgres::map_sqlx_error)?,
        })
    }
}

#[cfg(any(feature = "sqlite", test))]
impl TryFrom<SqliteRow> for FailureHistory {
    type Error = DbError;

    fn try_from(row: SqliteRow) -> DbResult<Self> {
        let count: i64 = row.try_get("failure_count").map_err(sqlite::map_sqlx_error)?;
        let secs = row.try_get("last_failure_secs").map_err(sqlite::map_sqlx_error)?;
        let nsecs = row.try_get("last_failure_nsecs").map_err(sqlite::map_sqlx_error)?;
        let blocked_secs: Option<i64> =
            row.try_get("blocked_until_secs").map_err(sqlite::map_sqlx_error)?;
        let blocked_nsecs: Option<i64> =
            row.try_get("blocked_until_nsecs").map_err(sqlite::map_sqlx_error)?;
        let blocked_until = match (blocked_secs, blocked_nsecs) {
            (None, None) => None,
            (Some(secs), Some(nsecs)) => Some(build_timestamp(secs, nsecs)?),
            _ => return Err(DbError::DataIntegrityError("Inconsistent blocked_until".to_owned())),
        };
        Ok(Self {
            count: u32::try_from(count).map_err(|e| DbError::DataIntegrityError(e.to_string()))?,
            last_failure: build_timestamp(secs, nsecs)?,
            blocked_until,
        })
    }
}

/// Reads backoff without acquiring a write lock.
pub(crate) async fn get_failures(
    ex: &mut Executor,
    user_id: Uuid,
    operation: FailureOperation,
) -> DbResult<Option<FailureHistory>> {
    match ex {
        #[cfg(feature = "postgres")]
        Executor::Postgres(ex) => {
            let row =
                sqlx::query("SELECT * FROM authn_failures WHERE user_id = $1 AND operation = $2")
                    .bind(user_id)
                    .bind(operation.as_str())
                    .fetch_optional(ex)
                    .await
                    .map_err(postgres::map_sqlx_error)?;
            row.map(FailureHistory::try_from).transpose()
        }

        #[cfg(any(feature = "sqlite", test))]
        Executor::Sqlite(ex) => {
            let row =
                sqlx::query("SELECT * FROM authn_failures WHERE user_id = ? AND operation = ?")
                    .bind(user_id)
                    .bind(operation.as_str())
                    .fetch_optional(ex)
                    .await
                    .map_err(sqlite::map_sqlx_error)?;
            row.map(FailureHistory::try_from).transpose()
        }

        #[allow(unused)]
        _ => unreachable!(),
    }
}

/// Serializes outcomes for an account, including when its history does not exist yet.
///
/// This must be the first statement in the transaction, before any reads.  The upsert locks
/// the row on PostgreSQL and acquires SQLite's writer lock without upgrading a read snapshot.
/// A new zero-count row must be updated, deleted, or rolled back before leaving the transaction.
pub(crate) async fn lock_failures(
    ex: &mut Executor,
    user_id: Uuid,
    operation: FailureOperation,
    now: OffsetDateTime,
) -> DbResult<FailureHistory> {
    let affected = match ex {
        #[cfg(feature = "postgres")]
        Executor::Postgres(ex) => sqlx::query(
            "INSERT INTO authn_failures (user_id, operation, failure_count, last_failure)
                SELECT id, $2, 0, $3 FROM users WHERE id = $1
                ON CONFLICT (user_id, operation) DO UPDATE SET user_id = EXCLUDED.user_id",
        )
        .bind(user_id)
        .bind(operation.as_str())
        .bind(now)
        .execute(ex)
        .await
        .map_err(postgres::map_sqlx_error)?
        .rows_affected(),

        #[cfg(any(feature = "sqlite", test))]
        Executor::Sqlite(ex) => {
            let (secs, nsecs) = unpack_timestamp(now);
            sqlx::query(
                "INSERT INTO authn_failures
                (user_id, operation, failure_count, last_failure_secs, last_failure_nsecs)
                SELECT id, ?, 0, ?, ? FROM users WHERE id = ?
                ON CONFLICT (user_id, operation) DO UPDATE SET user_id = EXCLUDED.user_id",
            )
            .bind(operation.as_str())
            .bind(secs)
            .bind(nsecs)
            .bind(user_id)
            .execute(ex)
            .await
            .map_err(sqlite::map_sqlx_error)?
            .rows_affected()
        }

        #[allow(unused)]
        _ => unreachable!(),
    };
    if affected == 0 {
        return Err(DbError::NotFound);
    }
    ensure_one_upsert(affected)?;
    get_failures(ex, user_id, operation).await?.ok_or(DbError::NotFound)
}

/// Stores a history while the transaction holds its account lock.
pub(crate) async fn save_failures(
    ex: &mut Executor,
    user_id: Uuid,
    operation: FailureOperation,
    state: &FailureHistory,
) -> DbResult<()> {
    let affected = match ex {
        #[cfg(feature = "postgres")]
        Executor::Postgres(ex) => sqlx::query(
            "UPDATE authn_failures SET failure_count = $1,
                last_failure = $2, blocked_until = $3 WHERE user_id = $4 AND operation = $5",
        )
        .bind(i64::from(state.count))
        .bind(state.last_failure)
        .bind(state.blocked_until)
        .bind(user_id)
        .bind(operation.as_str())
        .execute(ex)
        .await
        .map_err(postgres::map_sqlx_error)?
        .rows_affected(),

        #[cfg(any(feature = "sqlite", test))]
        Executor::Sqlite(ex) => {
            let (secs, nsecs) = unpack_timestamp(state.last_failure);
            let (blocked_secs, blocked_nsecs) = state.blocked_until.map(unpack_timestamp).unzip();
            sqlx::query(
                "UPDATE authn_failures SET failure_count = ?,
                last_failure_secs = ?, last_failure_nsecs = ?, blocked_until_secs = ?,
                blocked_until_nsecs = ? WHERE user_id = ? AND operation = ?",
            )
            .bind(i64::from(state.count))
            .bind(secs)
            .bind(nsecs)
            .bind(blocked_secs)
            .bind(blocked_nsecs)
            .bind(user_id)
            .bind(operation.as_str())
            .execute(ex)
            .await
            .map_err(sqlite::map_sqlx_error)?
            .rows_affected()
        }

        #[allow(unused)]
        _ => unreachable!(),
    };
    ensure_one_upsert(affected)
}

/// Removes history for one operation while holding its transaction lock.
pub(crate) async fn clear_failures(
    ex: &mut Executor,
    user_id: Uuid,
    operation: FailureOperation,
) -> DbResult<()> {
    match ex {
        #[cfg(feature = "postgres")]
        Executor::Postgres(ex) => {
            sqlx::query("DELETE FROM authn_failures WHERE user_id = $1 AND operation = $2")
                .bind(user_id)
                .bind(operation.as_str())
                .execute(ex)
                .await
                .map_err(postgres::map_sqlx_error)?;
        }

        #[cfg(any(feature = "sqlite", test))]
        Executor::Sqlite(ex) => {
            sqlx::query("DELETE FROM authn_failures WHERE user_id = ? AND operation = ?")
                .bind(user_id)
                .bind(operation.as_str())
                .execute(ex)
                .await
                .map_err(sqlite::map_sqlx_error)?;
        }

        #[allow(unused)]
        _ => unreachable!(),
    }
    Ok(())
}
