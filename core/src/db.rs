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

//! Generic abstraction to access different database systems.
//!
//! The facilities in this module provide an abstraction over different database systems such as
//! PostgreSQL and SQLite.  The PostgreSQL backend is for production use and the SQLite backend is
//! primarily intended to support unit tests.

use crate::model::ModelError;
use async_trait::async_trait;

#[cfg(feature = "postgres")]
pub mod postgres;
#[cfg(feature = "sqlite")]
pub mod sqlite;

/// Database errors.  Any unexpected errors that come from the database are classified as
/// `BackendError`, but errors we know about have more specific types.
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum DbError {
    /// Indicates that a request to create an entry failed because it already exists.
    #[error("Already exists")]
    AlreadyExists,

    /// Catch-all error type for unexpected database errors.
    #[error("Database error: {0}")]
    BackendError(String),

    /// Indicates a failure processing the data that already exists in the database.
    #[error("Data integrity error: {0}")]
    DataIntegrityError(String),

    /// Indicates that a requested entry does not exist.
    #[error("Entity not found")]
    NotFound,

    /// Indicates that the database is not available (maybe because of too many active concurrent
    /// connections).
    #[error("Unavailable")]
    Unavailable,
}

impl From<ModelError> for DbError {
    fn from(e: ModelError) -> Self {
        DbError::DataIntegrityError(e.to_string())
    }
}

/// Result type for this module.
pub type DbResult<T> = Result<T, DbError>;

/// A database executor that can talk to multiple database implementations.
///
/// This type provides a generic mechanism to access a typed instance of a database, which is needed
/// by sqlx to offer type safety guarantees during query compilation.  Users of this type are forced
/// to destructure it and issue different calls for each database.
///
/// Note that this can wrap an executor that talks directly to a pool or to an open transaction.
pub enum Executor {
    /// A PostgreSQL executor that can be used in `sqlx` operations.
    #[cfg(feature = "postgres")]
    Postgres(postgres::PostgresExecutor),

    /// A SQLite executor that can be used in `sqlx` operations.
    #[cfg(feature = "sqlite")]
    Sqlite(sqlite::SqliteExecutor),
}

/// A wrapper for a database executor backed by an open transaction.
pub struct TxExecutor(Executor);

impl TxExecutor {
    /// Returns the executor wrapped by this transaction.
    ///
    /// This would be better called `executor` but this method is used so frequently that it makes
    /// call sites too verbose.
    pub fn ex(&mut self) -> &mut Executor {
        &mut self.0
    }

    /// Commits the transaction.
    pub async fn commit(self) -> DbResult<()> {
        match self.0 {
            #[cfg(feature = "postgres")]
            Executor::Postgres(e) => e.commit().await,

            #[cfg(feature = "sqlite")]
            Executor::Sqlite(e) => e.commit().await,
        }
    }
}

/// Abstraction over the database connection.
#[async_trait]
pub trait Db {
    /// Obtains an executor for direct access to the pool.
    ///
    /// This would be better called `executor` but this method is used so frequently that it makes
    /// call sites too verbose.
    fn ex(&self) -> Executor;

    /// Begins a transaction.
    ///
    /// It is the responsibility of the caller to call `commit` on the returned executor.  Otherwise
    /// the transaction is rolled back on drop.
    async fn begin(&self) -> DbResult<TxExecutor>;
}

/// Macros to help instantiate tests for multiple database systems.
#[cfg(any(test, feature = "testutils"))]
pub mod testutils {
    pub use paste::paste;

    /// Instantiates the `module::name` test for the database configured by `setup`.
    ///
    /// The `extra` metadata parameter can be used to tag the generated tests.
    #[macro_export]
    macro_rules! generate_one_test [
        ( $name:ident, $setup:expr, $module:path $(, #[$extra:meta] )? ) => {
            #[tokio::test]
            $(#[$extra])?
            async fn $name() {
                $crate::db::testutils::paste! {
                    $module :: [< $name >]($setup).await;
                }
            }
        }
    ];

    pub use generate_one_test;

    /// Instantiates a collection of tests for a specific database system.
    ///
    /// The database implementation to run the tests against is determined by the `setup`
    /// expression, which needs to return a database object parameterized with the desired
    /// transaction type.  The returned database should also have been initialized with the
    /// desired schema.
    ///
    /// The `extra` metadata parameter can be used to tag the generated tests.
    #[macro_export]
    macro_rules! generate_tests [
        ( #[$extra:meta], $setup:expr, $module:path $(, $name:ident)+ ) => {
            $(
                $crate::db::testutils::generate_one_test!($name, $setup, $module, #[$extra]);
            )+
        };

        ( $setup:expr, $module:path $(, $name:ident)+ ) => {
            $(
                $crate::db::testutils::generate_one_test!($name, $setup, $module);
            )+
        };
    ];

    pub use generate_tests;
}

#[cfg(all(test, any(feature = "postgres", feature = "sqlite")))]
mod tests {
    use super::*;
    use sqlx::Row;
    use std::sync::Arc;

    /// Runs a `query` on `ex` and does not care about its results.  The `query` must be valid for
    /// all possible database implementations.
    pub async fn exec(ex: &mut Executor, query: &str) -> DbResult<()> {
        match ex {
            #[cfg(feature = "postgres")]
            Executor::Postgres(ref mut ex) => {
                let _result = sqlx::query(query).execute(ex).await.unwrap();
            }

            #[cfg(feature = "sqlite")]
            Executor::Sqlite(ref mut ex) => {
                let _result = sqlx::query(query).execute(ex).await.unwrap();
            }
        }
        Ok(())
    }

    /// Runs a `query` on `ex` that fetches a single row with an `i64` value on `column` and returns
    /// that value.  The `query` must be valid for all possible database implementations.
    async fn query_i64(ex: &mut Executor, column: &str, query: &str) -> i64 {
        match ex {
            #[cfg(feature = "postgres")]
            Executor::Postgres(ref mut ex) => {
                let row = sqlx::query(query).fetch_one(ex).await.unwrap();
                row.try_get(column).unwrap()
            }

            #[cfg(feature = "sqlite")]
            Executor::Sqlite(ref mut ex) => {
                let row = sqlx::query(query).fetch_one(ex).await.unwrap();
                row.try_get(column).unwrap()
            }
        }
    }

    pub(super) async fn test_direct_execution(db: Box<dyn Db>) {
        exec(&mut db.ex(), "CREATE TABLE test (i INTEGER)").await.unwrap();
        exec(&mut db.ex(), "INSERT INTO test (i) VALUES (3)").await.unwrap();
        assert_eq!(1, query_i64(&mut db.ex(), "count", "SELECT COUNT(*) AS count FROM test").await);
    }

    pub(super) async fn test_tx_commit(db: Box<dyn Db>) {
        exec(&mut db.ex(), "CREATE TABLE test (i INTEGER)").await.unwrap();

        let mut tx = db.begin().await.unwrap();
        exec(tx.ex(), "INSERT INTO test (i) VALUES (3)").await.unwrap();
        tx.commit().await.unwrap();

        assert_eq!(1, query_i64(&mut db.ex(), "count", "SELECT COUNT(*) AS count FROM test").await);
    }

    pub(super) async fn test_tx_rollback_on_drop(db: Box<dyn Db>) {
        exec(&mut db.ex(), "CREATE TABLE test (i INTEGER)").await.unwrap();

        {
            let mut tx = db.begin().await.unwrap();
            exec(tx.ex(), "INSERT INTO test (i) VALUES (3)").await.unwrap();
        }

        assert_eq!(0, query_i64(&mut db.ex(), "count", "SELECT COUNT(*) AS count FROM test").await);
    }

    pub(super) async fn test_multiple_txs(db: Box<dyn Db>) {
        let tx1 = db.begin().await.unwrap();
        let tx2 = db.begin().await.unwrap();
        tx1.commit().await.unwrap();
        tx2.commit().await.unwrap();
    }

    pub(super) async fn test_begin_tx_after_drop(db: Box<dyn Db>) {
        let db: Arc<dyn Db> = Arc::from(db);

        let tx1 = db.clone().begin().await.unwrap();
        tx1.commit().await.unwrap();

        let tx2 = db.begin().await.unwrap();
        tx2.commit().await.unwrap();
    }

    /// Instantiates tests that need concurrent access to the database.  These tests cannot write
    /// to the database.
    #[macro_export]
    macro_rules! generate_db_ro_concurrent_tests [
        ( $setup:expr $(, #[$extra:meta])? ) => {
            $crate::db::testutils::generate_tests!(
                $( #[$extra], )?
                $setup,
                $crate::db::tests,
                test_multiple_txs,
                test_begin_tx_after_drop
            );
        }
    ];

    pub(super) use generate_db_ro_concurrent_tests;

    /// Instantiates tests that need write access to the test database.
    #[macro_export]
    macro_rules! generate_db_rw_tests [
        ( $setup:expr $(, #[$extra:meta])? ) => {
            $crate::db::testutils::generate_tests!(
                $( #[$extra], )?
                $setup,
                $crate::db::tests,
                test_direct_execution,
                test_tx_commit,
                test_tx_rollback_on_drop
            );
        }
    ];

    pub(super) use generate_db_rw_tests;
}
