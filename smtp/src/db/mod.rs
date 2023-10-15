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

//! Database abstraction to track email submissions.

#[cfg(test)]
use futures::TryStreamExt;
#[cfg(feature = "postgres")]
use iii_iv_core::db::postgres;
#[cfg(test)]
use iii_iv_core::db::sqlite::build_timestamp;
#[cfg(any(feature = "sqlite", test))]
use iii_iv_core::db::sqlite::{self, unpack_timestamp};
use iii_iv_core::db::{count_as_usize, ensure_one_upsert, DbResult, Executor};
use lettre::Message;
use sqlx::Row;
use time::{Date, OffsetDateTime};

#[cfg(test)]
mod tests;

/// Initializes the database schema.
pub async fn init_schema(ex: &mut Executor) -> DbResult<()> {
    match ex {
        #[cfg(feature = "postgres")]
        Executor::Postgres(ref mut ex) => {
            postgres::run_schema(ex, include_str!("postgres.sql")).await
        }

        #[cfg(any(feature = "sqlite", test))]
        Executor::Sqlite(ref mut ex) => sqlite::run_schema(ex, include_str!("sqlite.sql")).await,

        #[allow(unused)]
        _ => unreachable!(),
    }
}

/// Counts how many emails were sent on `day`.
pub(crate) async fn count_email_log(ex: &mut Executor, day: Date) -> DbResult<usize> {
    let total: i64 = match ex {
        Executor::Postgres(ref mut ex) => {
            let from = day.midnight().assume_utc();
            let to = from + time::Duration::DAY;

            let query_str =
                "SELECT COUNT(*) AS total FROM email_log WHERE sent >= $1 AND sent < $2";
            let row = sqlx::query(query_str)
                .bind(from)
                .bind(to)
                .fetch_one(ex)
                .await
                .map_err(postgres::map_sqlx_error)?;
            row.try_get("total").map_err(postgres::map_sqlx_error)?
        }

        #[cfg(any(test, feature = "sqlite"))]
        Executor::Sqlite(ref mut ex) => {
            let from = day.midnight().assume_utc();
            let to = from + time::Duration::DAY;

            let (from_sec, from_nsec) = unpack_timestamp(from);
            let (to_sec, to_nsec) = unpack_timestamp(to);

            let query_str = "
                SELECT COUNT(*) AS total
                FROM email_log
                WHERE
                    (sent_sec >= ? OR (sent_sec = ? AND sent_nsec >= ?))
                    AND (sent_sec < ? OR (sent_sec = ? AND sent_nsec < ?))
            ";
            let row = sqlx::query(query_str)
                .bind(from_sec)
                .bind(from_sec)
                .bind(from_nsec)
                .bind(to_sec)
                .bind(to_sec)
                .bind(to_nsec)
                .fetch_one(ex)
                .await
                .map_err(sqlite::map_sqlx_error)?;
            row.try_get("total").map_err(sqlite::map_sqlx_error)?
        }

        #[allow(unused)]
        _ => unreachable!(),
    };
    count_as_usize(total)
}

/// En entry in the email log.
#[cfg(test)]
type EmailLogEntry = (OffsetDateTime, Vec<u8>, Option<String>);

/// Gets all entries in the email log.
#[cfg(test)]
pub(crate) async fn get_email_log(ex: &mut Executor) -> DbResult<Vec<EmailLogEntry>> {
    let mut entries = vec![];
    match ex {
        Executor::Postgres(ref mut ex) => {
            let query_str = "SELECT sent, message, result FROM email_log";
            let mut rows = sqlx::query(query_str).fetch(ex);
            while let Some(row) = rows.try_next().await.map_err(postgres::map_sqlx_error)? {
                let sent: OffsetDateTime = row.try_get("sent").map_err(postgres::map_sqlx_error)?;
                let message: Vec<u8> = row.try_get("message").map_err(postgres::map_sqlx_error)?;
                let result: Option<String> =
                    row.try_get("result").map_err(postgres::map_sqlx_error)?;

                entries.push((sent, message, result));
            }
        }

        #[cfg(any(test, feature = "sqlite"))]
        Executor::Sqlite(ref mut ex) => {
            let query_str = "SELECT sent_sec, sent_nsec, message, result FROM email_log";
            let mut rows = sqlx::query(query_str).fetch(ex);
            while let Some(row) = rows.try_next().await.map_err(sqlite::map_sqlx_error)? {
                let sent_sec: i64 = row.try_get("sent_sec").map_err(sqlite::map_sqlx_error)?;
                let sent_nsec: i64 = row.try_get("sent_nsec").map_err(sqlite::map_sqlx_error)?;
                let message: Vec<u8> = row.try_get("message").map_err(sqlite::map_sqlx_error)?;
                let result: Option<String> =
                    row.try_get("result").map_err(sqlite::map_sqlx_error)?;

                let sent = build_timestamp(sent_sec, sent_nsec)?;

                entries.push((sent, message, result))
            }
        }

        #[allow(unused)]
        _ => unreachable!(),
    }
    Ok(entries)
}

/// Records that an email was sent to `email` at time `now`.
pub(crate) async fn put_email_log(
    ex: &mut Executor,
    message: &Message,
    now: OffsetDateTime,
) -> DbResult<i64> {
    match ex {
        Executor::Postgres(ref mut ex) => {
            let query_str = "INSERT INTO email_log (sent, message) VALUES ($1, $2) RETURNING id";
            let row = sqlx::query(query_str)
                .bind(now)
                .bind(message.formatted())
                .fetch_one(ex)
                .await
                .map_err(postgres::map_sqlx_error)?;
            let last_insert_id: i32 = row.try_get("id").map_err(postgres::map_sqlx_error)?;
            Ok(i64::from(last_insert_id))
        }

        #[cfg(any(test, feature = "sqlite"))]
        Executor::Sqlite(ref mut ex) => {
            let (now_sec, now_nsec) = unpack_timestamp(now);

            let query_str = "INSERT INTO email_log (sent_sec, sent_nsec, message) VALUES (?, ?, ?)";
            let done = sqlx::query(query_str)
                .bind(now_sec)
                .bind(now_nsec)
                .bind(message.formatted())
                .execute(ex)
                .await
                .map_err(sqlite::map_sqlx_error)?;
            Ok(done.last_insert_rowid())
        }

        #[allow(unused)]
        _ => unreachable!(),
    }
}

/// Records the result of sending an email.
pub(crate) async fn update_email_log(ex: &mut Executor, id: i64, result: &str) -> DbResult<()> {
    match ex {
        Executor::Postgres(ref mut ex) => {
            let query_str = "UPDATE email_log SET result = $1 WHERE id = $2";
            let done = sqlx::query(query_str)
                .bind(result)
                .bind(id)
                .execute(ex)
                .await
                .map_err(postgres::map_sqlx_error)?;
            ensure_one_upsert(done.rows_affected())?;
            Ok(())
        }

        #[cfg(any(test, feature = "sqlite"))]
        Executor::Sqlite(ref mut ex) => {
            let query_str = "UPDATE email_log SET result = ? WHERE id = ?";
            let done = sqlx::query(query_str)
                .bind(result)
                .bind(id)
                .execute(ex)
                .await
                .map_err(sqlite::map_sqlx_error)?;
            ensure_one_upsert(done.rows_affected())?;
            Ok(())
        }

        #[allow(unused)]
        _ => unreachable!(),
    }
}
