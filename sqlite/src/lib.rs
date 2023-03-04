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

//! Common utilities to interact with an SQLite database.

// Keep these in sync with other top-level files.
#![warn(anonymous_parameters, bad_style, clippy::missing_docs_in_private_items, missing_docs)]
#![warn(unused, unused_extern_crates, unused_import_braces, unused_qualifications)]
#![warn(unsafe_code)]

use derivative::Derivative;
use futures::lock::Mutex;
use futures::TryStreamExt;
use iii_iv_core::db::{BareTx, Db, DbError, DbResult};
use sqlx::sqlite::{Sqlite, SqlitePool};
use sqlx::Transaction;
use std::marker::PhantomData;

/// Takes a raw SQLx error `e` and converts it to our generic error type.
pub fn map_sqlx_error(e: sqlx::Error) -> DbError {
    match e {
        sqlx::Error::ColumnDecode { source, .. } => DbError::DataIntegrityError(source.to_string()),
        sqlx::Error::RowNotFound => DbError::NotFound,
        e if e.to_string().contains("FOREIGN KEY constraint failed") => DbError::NotFound,
        e if e.to_string().contains("UNIQUE constraint failed") => DbError::AlreadyExists,
        e => DbError::BackendError(e.to_string()),
    }
}

/// A database instance backed by an in-memory SQLite database.
#[derive(Derivative)]
#[derivative(Clone(bound = ""))]
pub struct SqliteDb<T>
where
    T: BareTx + From<Mutex<Transaction<'static, Sqlite>>> + Send + Sync + 'static,
{
    /// Shared SQLite connection pool.  This is a cloneable type that all concurrent
    /// transactions can use it concurrently.
    pool: SqlitePool,

    /// Marker for the unused type `T`.
    _phantom_tx: PhantomData<T>,
}

impl<T> SqliteDb<T>
where
    T: BareTx + From<Mutex<Transaction<'static, Sqlite>>> + Send + Sync + 'static,
{
    /// Creates a new connection.
    async fn connect_internal(conn_str: &str) -> DbResult<Self> {
        let pool = SqlitePool::connect(conn_str).await.map_err(map_sqlx_error)?;
        Ok(Self { pool, _phantom_tx: PhantomData::default() })
    }
    /// Creates a new connection and sets the database schema.
    pub async fn connect(conn_str: &str) -> DbResult<Self> {
        let db = SqliteDb::<T>::connect_internal(conn_str).await?;

        let mut tx: T = db.begin().await?;
        tx.migrate().await?;
        tx.commit().await?;

        Ok(db)
    }
}

#[async_trait::async_trait]
impl<T> Db for SqliteDb<T>
where
    T: BareTx + From<Mutex<Transaction<'static, Sqlite>>> + Send + Sync + 'static,
{
    type SqlxTx = Mutex<Transaction<'static, Sqlite>>;
    type Tx = T;

    async fn begin(&self) -> DbResult<Self::Tx> {
        let tx = self.pool.begin().await.map_err(map_sqlx_error)?;
        Ok(Self::Tx::from(Mutex::from(tx)))
    }
}

/// Helper function to initialize the database with a schema.  Use in implementations of
/// `BareTx::migrate`.
pub async fn run_schema(
    tx: &mut Mutex<Transaction<'static, Sqlite>>,
    schema: &str,
) -> DbResult<()> {
    let mut tx = tx.lock().await;
    let mut results = sqlx::query(schema).execute_many(&mut *tx).await;
    while results.try_next().await.map_err(map_sqlx_error)?.is_some() {
        // Nothing to do.
    }
    Ok(())
}

/// Test utilities for the SQLite connection.
#[cfg(any(feature = "testutils", test))]
pub mod testutils {
    use super::*;

    /// A transaction backed by a SQLite database.
    pub(crate) struct SqliteTestTx {
        /// Inner transaction type to obtain access to the raw sqlx transaction.
        tx: Mutex<Transaction<'static, Sqlite>>,
    }

    impl From<Mutex<Transaction<'static, Sqlite>>> for SqliteTestTx {
        fn from(tx: Mutex<Transaction<'static, Sqlite>>) -> Self {
            Self { tx }
        }
    }

    #[async_trait::async_trait]
    impl BareTx for SqliteTestTx {
        async fn commit(mut self) -> DbResult<()> {
            let tx = self.tx.into_inner();
            tx.commit().await.map_err(map_sqlx_error)
        }
    }

    /// Initializes the test database.
    pub async fn setup<T>() -> SqliteDb<T>
    where
        T: BareTx + From<Mutex<Transaction<'static, Sqlite>>> + Send + Sync + 'static,
    {
        let _can_fail = env_logger::builder().is_test(true).try_init();
        let db = SqliteDb::connect_internal(":memory:").await.unwrap();

        let mut tx: T = db.begin().await.unwrap();
        tx.migrate_test().await.unwrap();
        tx.commit().await.unwrap();

        db
    }
}

#[cfg(test)]
mod tests {
    use super::testutils::*;
    use iii_iv_core::db::testutils::generate_core_db_tests;

    generate_core_db_tests!(setup::<SqliteTestTx>().await);
}
