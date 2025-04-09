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

//! Database abstraction in terms of the operations needed by the server.

use crate::model::*;
use futures::TryStreamExt;
use iii_iv_core::db::postgres::{self};
#[cfg(test)]
use iii_iv_core::db::sqlite;
use iii_iv_core::db::{DbError, DbResult, Executor};
use sqlx::Row;
use std::collections::BTreeSet;
#[cfg(test)]
pub(crate) mod tests;

/// Initializes the database schema.
pub async fn init_schema(ex: &mut Executor) -> DbResult<()> {
    match ex {
        Executor::Postgres(ex) => postgres::run_schema(ex, include_str!("postgres.sql")).await,

        #[cfg(test)]
        Executor::Sqlite(ex) => sqlite::run_schema(ex, include_str!("sqlite.sql")).await,

        #[allow(unused)]
        _ => unreachable!(),
    }
}

/// Gets a list of all existing keys.
pub(crate) async fn get_keys(e: &mut Executor) -> DbResult<BTreeSet<Key>> {
    match e {
        Executor::Postgres(e) => {
            let query_str = "SELECT key FROM store ORDER BY key";
            let mut rows = sqlx::query(query_str).fetch(e);

            let mut keys = BTreeSet::default();
            while let Some(row) = rows.try_next().await.map_err(postgres::map_sqlx_error)? {
                let key: String = row.try_get("key").map_err(postgres::map_sqlx_error)?;
                keys.insert(Key::new(key));
            }
            Ok(keys)
        }

        #[cfg(test)]
        Executor::Sqlite(e) => {
            let query_str = "SELECT key FROM store ORDER BY key";
            let mut rows = sqlx::query(query_str).fetch(e);

            let mut keys = BTreeSet::default();
            while let Some(row) = rows.try_next().await.map_err(sqlite::map_sqlx_error)? {
                let key: String = row.try_get("key").map_err(sqlite::map_sqlx_error)?;
                keys.insert(Key::new(key));
            }
            Ok(keys)
        }

        #[allow(unused)]
        _ => unreachable!(),
    }
}

/// Gets the current value of the given `key`.
pub(crate) async fn get_key(e: &mut Executor, key: &Key) -> DbResult<Entry> {
    let value: String;
    let version: i32;
    match e {
        Executor::Postgres(e) => {
            let query_str = "SELECT value, version FROM store WHERE key = $1";
            let row = sqlx::query(query_str)
                .bind(key.as_ref())
                .fetch_one(e)
                .await
                .map_err(postgres::map_sqlx_error)?;
            value = row.try_get("value").map_err(postgres::map_sqlx_error)?;
            version = row.try_get("version").map_err(postgres::map_sqlx_error)?;
        }

        #[cfg(test)]
        Executor::Sqlite(e) => {
            let query_str = "SELECT value, version FROM store WHERE key = ?";
            let row = sqlx::query(query_str)
                .bind(key.as_ref())
                .fetch_one(e)
                .await
                .map_err(sqlite::map_sqlx_error)?;
            value = row.try_get("value").map_err(sqlite::map_sqlx_error)?;
            version = row.try_get("version").map_err(sqlite::map_sqlx_error)?;
        }

        #[allow(unused)]
        _ => unreachable!(),
    }
    Ok(Entry::new(value, Version::from_i32(version)?))
}

/// Gets the current version of the given `key`, or `None` if it does not exist.
pub(crate) async fn get_key_version(e: &mut Executor, key: &Key) -> DbResult<Option<Version>> {
    match e {
        Executor::Postgres(e) => {
            let query_str = "SELECT version FROM store WHERE key = $1";
            let maybe_row = sqlx::query(query_str)
                .bind(key.as_ref())
                .fetch_optional(e)
                .await
                .map_err(postgres::map_sqlx_error)?;
            match maybe_row {
                None => Ok(None),
                Some(row) => {
                    let version: i32 = row.try_get("version").map_err(postgres::map_sqlx_error)?;
                    Ok(Some(Version::from_i32(version)?))
                }
            }
        }

        #[cfg(test)]
        Executor::Sqlite(e) => {
            let query_str = "SELECT version FROM store WHERE key = ?";
            let maybe_row = sqlx::query(query_str)
                .bind(key.as_ref())
                .fetch_optional(e)
                .await
                .map_err(sqlite::map_sqlx_error)?;
            match maybe_row {
                None => Ok(None),
                Some(row) => {
                    let version: u32 = row.try_get("version").map_err(sqlite::map_sqlx_error)?;
                    Ok(Some(Version::from_u32(version)?))
                }
            }
        }

        #[allow(unused)]
        _ => unreachable!(),
    }
}

/// Sets `key` to `entry`, which includes its value and version.
pub(crate) async fn set_key(e: &mut Executor, key: &Key, entry: &Entry) -> DbResult<()> {
    let affected = match e {
        Executor::Postgres(e) => {
            let query_str = "
            INSERT INTO store
            VALUES ($1, $2, $3)
            ON CONFLICT(key) DO UPDATE SET value = $2, version = $3
        ";
            let done = sqlx::query(query_str)
                .bind(key.as_ref())
                .bind(entry.value())
                .bind(entry.version().as_i32())
                .execute(e)
                .await
                .map_err(postgres::map_sqlx_error)?;
            done.rows_affected()
        }

        #[cfg(test)]
        Executor::Sqlite(e) => {
            let query_str = "
            INSERT INTO store
            VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value = ?, version = ? WHERE key = ?
        ";
            let done = sqlx::query(query_str)
                .bind(key.as_ref())
                .bind(entry.value())
                .bind(entry.version().as_u32())
                .bind(entry.value())
                .bind(entry.version().as_u32())
                .bind(key.as_ref())
                .execute(e)
                .await
                .map_err(sqlite::map_sqlx_error)?;
            done.rows_affected()
        }

        #[allow(unused)]
        _ => unreachable!(),
    };
    if affected != 1 {
        return Err(DbError::BackendError("Upsert affected more than one row".to_owned()));
    }
    Ok(())
}

/// Deletes `key`.
pub(crate) async fn delete_key(e: &mut Executor, key: &Key) -> DbResult<()> {
    let affected = match e {
        Executor::Postgres(e) => {
            let query_str = "DELETE FROM store WHERE key = $1";
            let done = sqlx::query(query_str)
                .bind(key.as_ref())
                .execute(e)
                .await
                .map_err(postgres::map_sqlx_error)?;
            done.rows_affected()
        }

        #[cfg(test)]
        Executor::Sqlite(e) => {
            let query_str = "DELETE FROM store WHERE key = ?";
            let done = sqlx::query(query_str)
                .bind(key.as_ref())
                .execute(e)
                .await
                .map_err(sqlite::map_sqlx_error)?;
            done.rows_affected()
        }

        #[allow(unused)]
        _ => unreachable!(),
    };
    if affected == 0 {
        return Err(DbError::NotFound);
    } else if affected != 1 {
        return Err(DbError::BackendError("Deletion affected more than one row".to_owned()));
    }
    Ok(())
}
