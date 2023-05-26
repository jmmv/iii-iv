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
use std::time::Duration;
use time::OffsetDateTime;

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

/// Creates a new connection.
async fn connect_internal(conn_str: &str) -> DbResult<SqlitePool> {
    SqlitePool::connect(conn_str).await.map_err(map_sqlx_error)
}

/// Creates a new connection and sets the database schema.
pub async fn connect(conn_str: &str) -> DbResult<SqlitePool> {
    connect_internal(conn_str).await
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
    /// Attaches a new database of type `T` to an existing pool.
    ///
    /// This takes care of running the migration process for the type `T`, which in turn results
    /// in the database connection being established.
    pub async fn attach(pool: SqlitePool) -> DbResult<Self> {
        let db = Self { pool, _phantom_tx: PhantomData::default() };

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

/// Converts a duration as extracted from the database into a `Duration`.
///
/// We expect `u64` values here but the sqlx interfaces require `i64`.  This is intentional,
/// and the code that loads these numbers from the database should cast them as `u64` understanding
/// that the stored representation may become negative.
pub fn build_duration(duration_sec: u64, duration_nsec: u64) -> DbResult<Duration> {
    Ok(Duration::from_secs(duration_sec) + Duration::from_nanos(duration_nsec))
}

/// Converts a timestamp as extracted from the database into an `OffsetDateTime`.
///
/// We expect `u64` values here but the sqlx interfaces require `i64`.  This is intentional,
/// and the code that loads these numbers from the database should cast them as `u64` understanding
/// that the stored representation may become negative.
pub fn build_timestamp(timestamp_sec: u64, timestamp_nsec: u64) -> DbResult<OffsetDateTime> {
    match OffsetDateTime::from_unix_timestamp_nanos(
        (i128::from(timestamp_sec) * 1_000_000_000) + (i128::from(timestamp_nsec)),
    ) {
        Ok(timestamp) => Ok(timestamp),
        Err(e) => Err(DbError::DataIntegrityError(format!("Invalid timestamp: {}", e))),
    }
}

/// Converts a duration into the seconds and nanoseconds pair needed by the database.
///
/// We expect `u64` values here but the sqlx interfaces require `i64`.  This is intentional,
/// and the code that stores these numbers into the database should cast them as `u64` understanding
/// that the stored representation may become negative.
pub fn unpack_duration(d: Duration) -> (u64, u64) {
    let nanos = d.as_nanos();
    let sec = u64::try_from(nanos / 1_000_000_000).expect("Must have fit");
    let nsec = u64::try_from(nanos % 1_000_000_000).expect("Must have fit");
    (sec, nsec)
}

/// Converts a timestamp into the seconds and nanoseconds pair needed by the database.
///
/// We expect `u64` values here but the sqlx interfaces require `i64`.  This is intentional,
/// and the code that stores these numbers into the database should cast them as `u64` understanding
/// that the stored representation may become negative.
pub fn unpack_timestamp(ts: OffsetDateTime) -> (u64, u64) {
    let nanos = ts.unix_timestamp_nanos();
    let sec = u64::try_from(nanos / 1_000_000_000).expect("Must have fit");
    let nsec = u64::try_from(nanos % 1_000_000_000).expect("Must have fit");
    (sec, nsec)
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
        let pool = connect_internal(":memory:").await.unwrap();
        // We don't use attach because we don't want to run the DB migration code.
        let db = SqliteDb { pool, _phantom_tx: PhantomData::default() };

        let mut tx: T = db.begin().await.unwrap();
        tx.migrate_test().await.unwrap();
        tx.commit().await.unwrap();

        db
    }
}

#[cfg(test)]
mod tests {
    use super::testutils::*;
    use super::*;
    use iii_iv_core::db::testutils::generate_core_db_tests;

    generate_core_db_tests!(setup::<SqliteTestTx>().await);

    #[test]
    fn test_build_unpack_duration_secs_precision() {
        let d = Duration::from_secs(123456789123456789u64);
        let (secs, nsecs) = unpack_duration(d);
        assert_eq!(123456789123456789u64, secs);
        assert_eq!(0, nsecs);
        assert_eq!(Ok(d), build_duration(secs, nsecs));
    }

    #[test]
    fn test_build_unpack_duration_nsecs_precision() {
        let d = Duration::from_nanos(1234567899876543215u64);
        let (secs, nsecs) = unpack_duration(d);
        assert_eq!(1234567899u64, secs);
        assert_eq!(876543215u64, nsecs);
        assert_eq!(Ok(d), build_duration(secs, nsecs));
    }

    #[test]
    fn test_build_unpack_timestamp_secs_precision() {
        let d = OffsetDateTime::from_unix_timestamp(123456789i64).unwrap();
        let (secs, nsecs) = unpack_timestamp(d);
        assert_eq!(123456789u64, secs);
        assert_eq!(0, nsecs);
        assert_eq!(Ok(d), build_timestamp(secs, nsecs));
    }

    #[test]
    fn test_build_unpack_timestamp_nsecs_precision() {
        let d = OffsetDateTime::from_unix_timestamp_nanos(1234567899876543215i128).unwrap();
        let (secs, nsecs) = unpack_timestamp(d);
        assert_eq!(1234567899u64, secs);
        assert_eq!(876543215u64, nsecs);
        assert_eq!(Ok(d), build_timestamp(secs, nsecs));
    }

    #[test]
    fn test_build_timestamp_too_big() {
        match build_timestamp(123456789123456789u64, 0) {
            Err(_) => (),
            Ok(_) => panic!("Must have failed"),
        }
    }
}
