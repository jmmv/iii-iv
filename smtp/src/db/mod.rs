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
use iii_iv_core::db::{DbError, DbResult, Executor, count_as_usize, ensure_one_upsert};
use iii_iv_core::model::EmailAddress;
use lettre::Message;
use mailparse::{MailAddr, addrparse_header, parse_headers};
use sqlx::{AssertSqlSafe, Row};
use time::{Date, OffsetDateTime};

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

/// Determines ownership from header-visible recipients in historical messages.
fn has_recipient(message: &[u8], recipient: &EmailAddress) -> DbResult<bool> {
    let invalid =
        |error| DbError::DataIntegrityError(format!("Invalid email log message: {}", error));
    let (headers, _) = parse_headers(message).map_err(invalid)?;
    let mut found = false;
    let mut recipient_headers = false;
    for header in headers {
        if !["to", "cc", "bcc"].iter().any(|name| header.get_key_ref().eq_ignore_ascii_case(name)) {
            continue;
        }
        recipient_headers = true;
        for address in addrparse_header(&header).map_err(invalid)?.iter() {
            found |= match address {
                MailAddr::Group(group) => {
                    group.addrs.iter().any(|address| address.addr == recipient.as_str())
                }
                MailAddr::Single(address) => address.addr == recipient.as_str(),
            };
        }
    }
    if !recipient_headers {
        return Err(DbError::DataIntegrityError(
            "Email log message has no recipient headers".to_owned(),
        ));
    }
    Ok(found)
}

/// Deletes complete email log entries addressed to `recipient`, returning the number removed.
///
/// Matches exact mailboxes in To, Cc, and retained Bcc headers, including historical messages.
/// Envelope-only recipients cannot be recovered from stored messages.  The caller must use a
/// transaction and coordinate concurrent mail submission.  All messages are parsed before any
/// deletion, so malformed stored messages fail without silently leaving account data behind.
pub async fn delete_email_logs_by_recipient(
    ex: &mut Executor,
    recipient: &EmailAddress,
) -> DbResult<usize> {
    let messages: Vec<(i32, Vec<u8>)> = match ex {
        #[cfg(feature = "postgres")]
        Executor::Postgres(ex) => sqlx::query_as("SELECT id, message FROM email_log")
            .fetch_all(ex)
            .await
            .map_err(postgres::map_sqlx_error)?,

        #[cfg(any(feature = "sqlite", test))]
        Executor::Sqlite(ex) => sqlx::query_as("SELECT id, message FROM email_log")
            .fetch_all(ex)
            .await
            .map_err(sqlite::map_sqlx_error)?,

        #[allow(unused)]
        _ => unreachable!(),
    };
    let mut ids = Vec::new();
    for (id, message) in messages {
        if has_recipient(&message, recipient)? {
            ids.push(id);
        }
    }
    let mut deleted = 0;
    for id in ids {
        deleted += delete_email_log(ex, id).await?;
    }
    usize::try_from(deleted).map_err(|error| DbError::DataIntegrityError(error.to_string()))
}

/// Removes a log record, returning zero if it was already removed.
pub(crate) async fn delete_email_log(ex: &mut Executor, id: i32) -> DbResult<u64> {
    match ex {
        #[cfg(feature = "postgres")]
        Executor::Postgres(ex) => sqlx::query("DELETE FROM email_log WHERE id = $1")
            .bind(id)
            .execute(ex)
            .await
            .map_err(postgres::map_sqlx_error)
            .map(|done| done.rows_affected()),

        #[cfg(any(feature = "sqlite", test))]
        Executor::Sqlite(ex) => sqlx::query("DELETE FROM email_log WHERE id = ?")
            .bind(id)
            .execute(ex)
            .await
            .map_err(sqlite::map_sqlx_error)
            .map(|done| done.rows_affected()),

        #[allow(unused)]
        _ => unreachable!(),
    }
}

/// Counts how many emails were sent on `day`.
pub(crate) async fn count_email_log(ex: &mut Executor, day: Date) -> DbResult<usize> {
    let total: i64 = match ex {
        Executor::Postgres(ex) => {
            let from = day.midnight().assume_utc();
            let to = from + time::Duration::DAY;

            let query_str =
                "SELECT COUNT(*) AS total FROM email_log WHERE sent >= $1 AND sent < $2";
            let row = sqlx::query(AssertSqlSafe(query_str))
                .bind(from)
                .bind(to)
                .fetch_one(ex)
                .await
                .map_err(postgres::map_sqlx_error)?;
            row.try_get("total").map_err(postgres::map_sqlx_error)?
        }

        #[cfg(any(test, feature = "sqlite"))]
        Executor::Sqlite(ex) => {
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
            let row = sqlx::query(AssertSqlSafe(query_str))
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
        Executor::Postgres(ex) => {
            let query_str = "SELECT sent, message, result FROM email_log";
            let mut rows = sqlx::query(AssertSqlSafe(query_str)).fetch(ex);
            while let Some(row) = rows.try_next().await.map_err(postgres::map_sqlx_error)? {
                let sent: OffsetDateTime = row.try_get("sent").map_err(postgres::map_sqlx_error)?;
                let message: Vec<u8> = row.try_get("message").map_err(postgres::map_sqlx_error)?;
                let result: Option<String> =
                    row.try_get("result").map_err(postgres::map_sqlx_error)?;

                entries.push((sent, message, result));
            }
        }

        #[cfg(any(test, feature = "sqlite"))]
        Executor::Sqlite(ex) => {
            let query_str = "SELECT sent_sec, sent_nsec, message, result FROM email_log";
            let mut rows = sqlx::query(AssertSqlSafe(query_str)).fetch(ex);
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
) -> DbResult<i32> {
    match ex {
        Executor::Postgres(ex) => {
            let query_str = "INSERT INTO email_log (sent, message) VALUES ($1, $2) RETURNING id";
            let row = sqlx::query(AssertSqlSafe(query_str))
                .bind(now)
                .bind(message.formatted())
                .fetch_one(ex)
                .await
                .map_err(postgres::map_sqlx_error)?;
            row.try_get("id").map_err(postgres::map_sqlx_error)
        }

        #[cfg(any(test, feature = "sqlite"))]
        Executor::Sqlite(ex) => {
            let (now_sec, now_nsec) = unpack_timestamp(now);

            let query_str = "INSERT INTO email_log (sent_sec, sent_nsec, message) VALUES (?, ?, ?)";
            let done = sqlx::query(AssertSqlSafe(query_str))
                .bind(now_sec)
                .bind(now_nsec)
                .bind(message.formatted())
                .execute(ex)
                .await
                .map_err(sqlite::map_sqlx_error)?;
            Ok(i32::try_from(done.last_insert_rowid()).expect("email id is constrained to INT4"))
        }

        #[allow(unused)]
        _ => unreachable!(),
    }
}

/// Records the result of sending an email.
pub(crate) async fn update_email_log(ex: &mut Executor, id: i32, result: &str) -> DbResult<()> {
    match ex {
        Executor::Postgres(ex) => {
            let query_str = "UPDATE email_log SET result = $1 WHERE id = $2";
            let done = sqlx::query(AssertSqlSafe(query_str))
                .bind(result)
                .bind(id)
                .execute(ex)
                .await
                .map_err(postgres::map_sqlx_error)?;
            ensure_one_upsert(done.rows_affected())?;
            Ok(())
        }

        #[cfg(any(test, feature = "sqlite"))]
        Executor::Sqlite(ex) => {
            let query_str = "UPDATE email_log SET result = ? WHERE id = ?";
            let done = sqlx::query(AssertSqlSafe(query_str))
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
