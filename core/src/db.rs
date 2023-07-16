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

//! Generic features and types to access a database.
//!
//! Every service using these primitives must define its own `Tx` trait that extends `BareTx` and
//! that provides the database operations that make sense in the context of the service's business
//! logic.  These operations should be primitive: the driver layer is responsible for coordinating
//! multiple operations within a single transaction.  Then, each service should provide concrete
//! implementations of its `Tx` for the database implementations it wants to use.  It's expected
//! that services will use `SqliteDb<Tx>` during tests and probably `PostgresDb<Tx>` for production.
//!
//! The design behind this transaction-based approach is to keep the services' code unaware of the
//! database implementation.  The primary reason is to support implementing unit tests using the
//! SQLite backend while using PostgreSQL in production.  There is some fidelity loss in doing so
//! because the behavior of the two implementations may not be identical (the SQL statements will
//! be different), but it's a good-enough approximation.  The fact that the tests developed in this
//! manner can run with zero  configuration and be extremely fast outweighs this issue.

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

/// Abstraction over the database connection.
#[async_trait]
pub trait Db {
    /// Type of the transaction wrapper type to generate.
    type Tx: BareTx + Send + Sync + 'static;

    /// Begins a transaction.
    async fn begin(&self) -> DbResult<Self::Tx>;
}

/// Common operations for all transactions.
#[async_trait]
pub trait BareTx {
    /// Commits the transaction.
    async fn commit(mut self) -> DbResult<()>;

    /// Initializes or upgrades the database schema when establishing the database connection.
    async fn migrate(&mut self) -> DbResult<()> {
        Ok(())
    }

    /// Initializes or upgrades the database schema when establishing the database connection to the
    /// test database.
    async fn migrate_test(&mut self) -> DbResult<()> {
        self.migrate().await
    }
}

/// Common tests for the database implementations in the framework and helper macros.
#[cfg(any(test, feature = "testutils"))]
pub mod testutils {
    use super::{BareTx, Db};
    pub use paste::paste;

    #[allow(missing_docs, clippy::missing_docs_in_private_items)]
    pub async fn test_uncommitted_tx<D>(db: D)
    where
        D: Db,
        D::Tx: BareTx,
    {
        let _unused = db.begin().await.unwrap();
    }

    #[allow(missing_docs, clippy::missing_docs_in_private_items)]
    pub async fn test_multiple_txs<D>(db: D)
    where
        D: Db,
        D::Tx: BareTx,
    {
        let tx1 = db.begin().await.unwrap();
        let tx2 = db.begin().await.unwrap();
        tx1.commit().await.unwrap();
        tx2.commit().await.unwrap();
    }

    #[allow(missing_docs, clippy::missing_docs_in_private_items)]
    pub async fn test_begin_tx_after_drop<D>(db: D)
    where
        D: Db + Clone + Send + Sync + 'static,
        D::Tx: BareTx,
    {
        let tx1 = db.clone().begin().await.unwrap();
        tx1.commit().await.unwrap();

        let tx2 = db.begin().await.unwrap();
        tx2.commit().await.unwrap();
    }

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

    /// Instantiates a collection of tests for the current database implementation.
    ///
    /// The "current" database implementation is determined by the `setup` expression, which needs
    /// to return a database object parameterized with the desired transaction type.
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

    /// Instantiates the collection of tests that validate the database crates of iii-iv.
    /// This should never be called in client code, but client code needs to define a similar macro
    /// to instantiate its own tets.
    #[macro_export]
    macro_rules! generate_core_db_tests [
        ( $setup:expr $(, #[$extra:meta])? ) => {
            $crate::db::testutils::generate_tests!(
                $( #[$extra], )?
                $setup,
                $crate::db::testutils,
                test_uncommitted_tx,
                test_multiple_txs,
                test_begin_tx_after_drop
            );
        }
    ];

    pub use generate_core_db_tests;
}
