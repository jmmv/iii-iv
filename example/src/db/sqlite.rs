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

//! Implementation of the database abstraction using SQLite.

use crate::db::Tx;
use crate::model::*;
use futures::lock::Mutex;
use futures::TryStreamExt;
use iii_iv_core::db::{BareTx, DbError, DbResult};
use iii_iv_sqlite::{map_sqlx_error, run_schema};
use sqlx::{Row, Sqlite, Transaction};
use std::collections::BTreeSet;

/// Schema to use to initialize the test database.
const SCHEMA: &str = include_str!("sqlite.sql");

/// A transaction backed by a SQLite database.
pub(crate) struct SqliteTx {
    /// Inner transaction type to obtain access to the raw sqlx transaction.
    tx: Mutex<Transaction<'static, Sqlite>>,
}

impl From<Mutex<Transaction<'static, Sqlite>>> for SqliteTx {
    fn from(tx: Mutex<Transaction<'static, Sqlite>>) -> Self {
        Self { tx }
    }
}

#[async_trait::async_trait]
impl BareTx for SqliteTx {
    async fn commit(mut self) -> DbResult<()> {
        let tx = self.tx.into_inner();
        tx.commit().await.map_err(map_sqlx_error)
    }

    async fn migrate(&mut self) -> DbResult<()> {
        run_schema(&mut self.tx, SCHEMA).await
    }
}

#[async_trait::async_trait]
impl Tx for SqliteTx {
    async fn delete_key(&mut self, key: &Key) -> DbResult<()> {
        let mut tx = self.tx.lock().await;

        let query_str = "DELETE FROM store WHERE key = ?";
        let done = sqlx::query(query_str)
            .bind(key.as_ref())
            .execute(&mut **tx)
            .await
            .map_err(map_sqlx_error)?;
        if done.rows_affected() == 0 {
            return Err(DbError::NotFound);
        } else if done.rows_affected() != 1 {
            return Err(DbError::BackendError("Deletion affected more than one row".to_owned()));
        }
        Ok(())
    }

    async fn get_key(&mut self, key: &Key) -> DbResult<Entry> {
        let mut tx = self.tx.lock().await;

        let query_str = "SELECT value, version FROM store WHERE key = ?";
        let row = sqlx::query(query_str)
            .bind(key.as_ref())
            .fetch_one(&mut **tx)
            .await
            .map_err(map_sqlx_error)?;
        let value: String = row.try_get("value").map_err(map_sqlx_error)?;
        let version: u32 = row.try_get("version").map_err(map_sqlx_error)?;

        Ok(Entry::new(value, Version::from_u32(version)?))
    }

    async fn get_key_version(&mut self, key: &Key) -> DbResult<Option<Version>> {
        let mut tx = self.tx.lock().await;

        let query_str = "SELECT version FROM store WHERE key = ?";
        let maybe_row = sqlx::query(query_str)
            .bind(key.as_ref())
            .fetch_optional(&mut **tx)
            .await
            .map_err(map_sqlx_error)?;
        match maybe_row {
            None => Ok(None),
            Some(row) => {
                let version: u32 = row.try_get("version").map_err(map_sqlx_error)?;
                Ok(Some(Version::from_u32(version)?))
            }
        }
    }

    async fn get_keys(&mut self) -> DbResult<BTreeSet<Key>> {
        let mut tx = self.tx.lock().await;

        let query_str = "SELECT key FROM store ORDER BY key";
        let mut rows = sqlx::query(query_str).fetch(&mut **tx);

        let mut keys = BTreeSet::default();
        while let Some(row) = rows.try_next().await.map_err(map_sqlx_error)? {
            let key: String = row.try_get("key").map_err(map_sqlx_error)?;
            keys.insert(Key::new(key));
        }
        Ok(keys)
    }

    async fn set_key(&mut self, key: &Key, entry: &Entry) -> DbResult<()> {
        let mut tx = self.tx.lock().await;

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
            .execute(&mut **tx)
            .await
            .map_err(map_sqlx_error)?;
        if done.rows_affected() != 1 {
            return Err(DbError::BackendError("Upsert affected more than one row".to_owned()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::tests::generate_db_tests;

    generate_db_tests!(iii_iv_sqlite::testutils::setup::<SqliteTx>().await);
}
