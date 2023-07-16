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

use crate::db::Tx;
use crate::model::*;
use futures::TryStreamExt;
use iii_iv_core::db::{BareTx, DbError, DbResult};
use iii_iv_postgres::{map_sqlx_error, run_schema};
use sqlx::{Postgres, Row, Transaction};
use std::collections::BTreeSet;

/// Schema to use to initialize the production database.
const SCHEMA: &str = include_str!("postgres.sql");

/// A transaction backed by a PostgreSQL database.
pub(crate) struct PostgresTx {
    /// Inner transaction type to obtain access to the raw sqlx transaction.
    tx: Transaction<'static, Postgres>,
}

impl From<Transaction<'static, Postgres>> for PostgresTx {
    fn from(tx: Transaction<'static, Postgres>) -> Self {
        Self { tx }
    }
}

#[async_trait::async_trait]
impl BareTx for PostgresTx {
    async fn commit(mut self) -> DbResult<()> {
        self.tx.commit().await.map_err(map_sqlx_error)
    }

    async fn migrate(&mut self) -> DbResult<()> {
        run_schema(&mut self.tx, SCHEMA).await
    }
}

#[async_trait::async_trait]
impl Tx for PostgresTx {
    async fn delete_key(&mut self, key: &Key) -> DbResult<()> {
        let query_str = "DELETE FROM store WHERE key = $1";
        let done = sqlx::query(query_str)
            .bind(key.as_ref())
            .execute(&mut *self.tx)
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
        let query_str = "SELECT value, version FROM store WHERE key = $1";
        let row = sqlx::query(query_str)
            .bind(key.as_ref())
            .fetch_one(&mut *self.tx)
            .await
            .map_err(map_sqlx_error)?;
        let value: String = row.try_get("value").map_err(map_sqlx_error)?;
        let version: i32 = row.try_get("version").map_err(map_sqlx_error)?;

        Ok(Entry::new(value, Version::from_i32(version)?))
    }

    async fn get_key_version(&mut self, key: &Key) -> DbResult<Option<Version>> {
        let query_str = "SELECT version FROM store WHERE key = $1";
        let maybe_row = sqlx::query(query_str)
            .bind(key.as_ref())
            .fetch_optional(&mut *self.tx)
            .await
            .map_err(map_sqlx_error)?;
        match maybe_row {
            None => Ok(None),
            Some(row) => {
                let version: i32 = row.try_get("version").map_err(map_sqlx_error)?;
                Ok(Some(Version::from_i32(version)?))
            }
        }
    }

    async fn get_keys(&mut self) -> DbResult<BTreeSet<Key>> {
        let query_str = "SELECT key FROM store ORDER BY key";
        let mut rows = sqlx::query(query_str).fetch(&mut *self.tx);

        let mut keys = BTreeSet::default();
        while let Some(row) = rows.try_next().await.map_err(map_sqlx_error)? {
            let key: String = row.try_get("key").map_err(map_sqlx_error)?;
            keys.insert(Key::new(key));
        }
        Ok(keys)
    }

    async fn set_key(&mut self, key: &Key, entry: &Entry) -> DbResult<()> {
        let query_str = "
            INSERT INTO store
            VALUES ($1, $2, $3)
            ON CONFLICT(key) DO UPDATE SET value = $2, version = $3
        ";
        let done = sqlx::query(query_str)
            .bind(key.as_ref())
            .bind(entry.value())
            .bind(entry.version().as_i32())
            .execute(&mut *self.tx)
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

    generate_db_tests!(
        iii_iv_postgres::testutils::setup::<PostgresTx>().await,
        #[ignore = "Requires environment configuration and is expensive"]);
}
