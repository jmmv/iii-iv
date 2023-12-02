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

use crate::db::{Db, DbError, DbResult, Executor, TxExecutor};
use async_trait::async_trait;
use futures::future::BoxFuture;
use futures::TryStreamExt;
use log::warn;
use sqlx::pool::PoolConnection;
use sqlx::sqlite::{Sqlite, SqlitePool};
use sqlx::Transaction;
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

/// Creates a new connection and sets the database schema.
pub async fn connect(conn_str: &str) -> DbResult<SqliteDb> {
    let pool = SqlitePool::connect(conn_str).await.map_err(map_sqlx_error)?;
    Ok(SqliteDb { pool })
}

/// A generic database executor implementation for SQLite.
#[derive(Debug)]
pub enum SqliteExecutor {
    /// An executor backed by a pool.  Operations issued via this executor aren't guaranteed to
    /// happen on the same connection.
    PoolExec(PoolConnection<Sqlite>),

    /// An executor backed by a transaction.
    TxExec(Transaction<'static, Sqlite>),
}

impl SqliteExecutor {
    /// Commits the transaction if this executor is backed by one.
    ///
    /// Calling this on a non-transaction-based executor results in a panic.
    pub(super) async fn commit(self) -> DbResult<()> {
        match self {
            SqliteExecutor::PoolExec(_) => unreachable!("Do not call commit on direct executors"),
            SqliteExecutor::TxExec(tx) => tx.commit().await.map_err(map_sqlx_error),
        }
    }
}

impl<'c> sqlx::Executor<'c> for &'c mut SqliteExecutor {
    type Database = Sqlite;

    fn describe<'e, 'q: 'e>(
        self,
        sql: &'q str,
    ) -> BoxFuture<'e, Result<sqlx::Describe<Self::Database>, sqlx::Error>>
    where
        'c: 'e,
    {
        match self {
            SqliteExecutor::PoolExec(conn) => conn.describe(sql),
            SqliteExecutor::TxExec(ref mut tx) => tx.describe(sql),
        }
    }

    fn execute<'e, 'q: 'e, E: 'q>(
        self,
        query: E,
    ) -> BoxFuture<'e, Result<<Self::Database as sqlx::Database>::QueryResult, sqlx::Error>>
    where
        'c: 'e,
        E: sqlx::Execute<'q, Self::Database>,
    {
        match self {
            SqliteExecutor::PoolExec(conn) => conn.execute(query),
            SqliteExecutor::TxExec(ref mut tx) => tx.execute(query),
        }
    }

    fn execute_many<'e, 'q: 'e, E: 'q>(
        self,
        query: E,
    ) -> futures::stream::BoxStream<
        'e,
        Result<<Self::Database as sqlx::Database>::QueryResult, sqlx::Error>,
    >
    where
        'c: 'e,
        E: sqlx::Execute<'q, Self::Database>,
    {
        match self {
            SqliteExecutor::PoolExec(conn) => conn.execute_many(query),
            SqliteExecutor::TxExec(ref mut tx) => tx.execute_many(query),
        }
    }

    fn fetch<'e, 'q: 'e, E: 'q>(
        self,
        query: E,
    ) -> futures::stream::BoxStream<'e, Result<<Self::Database as sqlx::Database>::Row, sqlx::Error>>
    where
        'c: 'e,
        E: sqlx::Execute<'q, Self::Database>,
    {
        match self {
            SqliteExecutor::PoolExec(conn) => conn.fetch(query),
            SqliteExecutor::TxExec(ref mut tx) => tx.fetch(query),
        }
    }

    fn fetch_all<'e, 'q: 'e, E: 'q>(
        self,
        query: E,
    ) -> BoxFuture<'e, Result<Vec<<Self::Database as sqlx::Database>::Row>, sqlx::Error>>
    where
        'c: 'e,
        E: sqlx::Execute<'q, Self::Database>,
    {
        match self {
            SqliteExecutor::PoolExec(conn) => conn.fetch_all(query),
            SqliteExecutor::TxExec(ref mut tx) => tx.fetch_all(query),
        }
    }

    fn fetch_many<'e, 'q: 'e, E: 'q>(
        self,
        query: E,
    ) -> futures::stream::BoxStream<
        'e,
        Result<
            sqlx::Either<
                <Self::Database as sqlx::Database>::QueryResult,
                <Self::Database as sqlx::Database>::Row,
            >,
            sqlx::Error,
        >,
    >
    where
        'c: 'e,
        E: sqlx::Execute<'q, Self::Database>,
    {
        match self {
            SqliteExecutor::PoolExec(conn) => conn.fetch_many(query),
            SqliteExecutor::TxExec(ref mut tx) => tx.fetch_many(query),
        }
    }

    fn fetch_one<'e, 'q: 'e, E: 'q>(
        self,
        query: E,
    ) -> BoxFuture<'e, Result<<Self::Database as sqlx::Database>::Row, sqlx::Error>>
    where
        'c: 'e,
        E: sqlx::Execute<'q, Self::Database>,
    {
        match self {
            SqliteExecutor::PoolExec(conn) => conn.fetch_one(query),
            SqliteExecutor::TxExec(ref mut tx) => tx.fetch_one(query),
        }
    }

    fn fetch_optional<'e, 'q: 'e, E: 'q>(
        self,
        query: E,
    ) -> BoxFuture<'e, Result<Option<<Self::Database as sqlx::Database>::Row>, sqlx::Error>>
    where
        'c: 'e,
        E: sqlx::Execute<'q, Self::Database>,
    {
        match self {
            SqliteExecutor::PoolExec(conn) => conn.fetch_optional(query),
            SqliteExecutor::TxExec(ref mut tx) => tx.fetch_optional(query),
        }
    }

    fn prepare<'e, 'q: 'e>(
        self,
        query: &'q str,
    ) -> BoxFuture<
        'e,
        Result<<Self::Database as sqlx::database::HasStatement<'q>>::Statement, sqlx::Error>,
    >
    where
        'c: 'e,
    {
        match self {
            SqliteExecutor::PoolExec(conn) => conn.prepare(query),
            SqliteExecutor::TxExec(ref mut tx) => tx.prepare(query),
        }
    }

    fn prepare_with<'e, 'q: 'e>(
        self,
        sql: &'q str,
        parameters: &'e [<Self::Database as sqlx::Database>::TypeInfo],
    ) -> BoxFuture<
        'e,
        Result<<Self::Database as sqlx::database::HasStatement<'q>>::Statement, sqlx::Error>,
    >
    where
        'c: 'e,
    {
        match self {
            SqliteExecutor::PoolExec(conn) => conn.prepare_with(sql, parameters),
            SqliteExecutor::TxExec(ref mut tx) => tx.prepare_with(sql, parameters),
        }
    }
}

/// A database instance backed by an in-memory SQLite database.
pub struct SqliteDb {
    /// Shared SQLite connection pool.  This is a cloneable type that all concurrent
    /// transactions can use concurrently.
    pool: SqlitePool,
}

impl SqliteDb {
    /// Returns an executor of the specific type used by this database.
    pub async fn typed_ex(&self) -> DbResult<SqliteExecutor> {
        let conn = self.pool.acquire().await.map_err(map_sqlx_error)?;
        Ok(SqliteExecutor::PoolExec(conn))
    }
}

impl Drop for SqliteDb {
    fn drop(&mut self) {
        if !self.pool.is_closed() {
            warn!("Dropping connection without having called close() first");
        }
    }
}

#[async_trait]
impl Db for SqliteDb {
    async fn ex(&self) -> DbResult<Executor> {
        let conn = self.pool.acquire().await.map_err(map_sqlx_error)?;
        Ok(Executor::Sqlite(SqliteExecutor::PoolExec(conn)))
    }

    async fn begin(&self) -> DbResult<TxExecutor> {
        let tx = self.pool.begin().await.map_err(map_sqlx_error)?;
        Ok(TxExecutor(Executor::Sqlite(SqliteExecutor::TxExec(tx))))
    }

    async fn close(&self) {
        self.pool.close().await;
    }
}

/// Helper function to initialize the database with a schema.
pub async fn run_schema(e: &mut SqliteExecutor, schema: &str) -> DbResult<()> {
    let mut results = sqlx::query(schema).execute_many(e).await;
    while results.try_next().await.map_err(map_sqlx_error)?.is_some() {
        // Nothing to do.
    }
    Ok(())
}

/// Converts a duration as extracted from the database into a `Duration`.
///
/// The input parameters must both be positive.  The reason why their types are `i64`s instead of
/// the `u64` you would expect is because the numeric types exposed by sqlx and SQLite are all
/// signed.  We could simply cast the types and accept negative representations in the database,
/// but that would pose difficulties when attempting to compare timestamps via relation operators
/// in SQL queries.
pub fn build_duration(duration_sec: i64, duration_nsec: i64) -> DbResult<Duration> {
    match (u64::try_from(duration_sec), u64::try_from(duration_nsec)) {
        (Ok(sec), Ok(nsec)) => Ok(Duration::from_secs(sec) + Duration::from_nanos(nsec)),
        _ => Err(DbError::DataIntegrityError(format!(
            "Duration cannot have negative quantities: sec={}, nsec={}",
            duration_sec, duration_nsec
        ))),
    }
}

/// Converts a timestamp as extracted from the database into an `OffsetDateTime`.
///
/// The input parameters must both be positive.  The reason why their types are `i64`s instead of
/// the `u64` you would expect is because the numeric types exposed by sqlx and SQLite are all
/// signed.  We could simply cast the types and accept negative representations in the database,
/// but that would pose difficulties when attempting to compare timestamps via relation operators
/// in SQL queries.
pub fn build_timestamp(timestamp_sec: i64, timestamp_nsec: i64) -> DbResult<OffsetDateTime> {
    if timestamp_sec < 0 || timestamp_nsec < 0 {
        return Err(DbError::DataIntegrityError(format!(
            "Timestamp cannot have negative quantities: sec={}, nsec={}",
            timestamp_sec, timestamp_nsec
        )));
    }

    match OffsetDateTime::from_unix_timestamp_nanos(
        (i128::from(timestamp_sec) * 1_000_000_000) + (i128::from(timestamp_nsec)),
    ) {
        Ok(timestamp) => Ok(timestamp),
        Err(e) => Err(DbError::DataIntegrityError(format!("Invalid timestamp: {}", e))),
    }
}

/// Converts a duration into the seconds and nanoseconds pair needed by the database.
///
/// The duration must be positive because `build_duration` also expects it to be positive when
/// recovering its values from the database.
pub fn unpack_duration(d: Duration) -> (i64, i64) {
    let nanos: u128 = d.as_nanos();
    let sec = i64::try_from(nanos / 1_000_000_000).expect("Must have fit");
    let nsec = i64::try_from(nanos % 1_000_000_000).expect("Must have fit");
    (sec, nsec)
}

/// Converts a timestamp into the seconds and nanoseconds pair needed by the database.
///
/// The timestamp must be positive because `build_timestamp` also expects it to be positive when
/// recovering its values from the database.
pub fn unpack_timestamp(ts: OffsetDateTime) -> (i64, i64) {
    let nanos = ts.unix_timestamp_nanos();
    assert!(nanos >= 0, "Cannot store a negative timestamp into the database");
    let sec = i64::try_from(nanos / 1_000_000_000).expect("Must have fit");
    let nsec = i64::try_from(nanos % 1_000_000_000).expect("Must have fit");
    (sec, nsec)
}

/// Test utilities for the SQLite connection.
#[cfg(any(feature = "testutils", test))]
pub mod testutils {
    use super::*;

    /// Initializes the test database.
    pub async fn setup() -> SqliteDb {
        let _can_fail = env_logger::builder().is_test(true).try_init();
        connect(":memory:").await.unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::testutils::*;
    use super::*;
    use crate::db::tests::{generate_db_ro_concurrent_tests, generate_db_rw_tests};
    use std::sync::Arc;

    generate_db_ro_concurrent_tests!({
        let db = Arc::from(setup().await);
        (db.clone(), db)
    });

    generate_db_rw_tests!({
        let db = Arc::from(setup().await);
        (db.clone(), db)
    });

    #[test]
    fn test_build_unpack_duration_zero() {
        let d = Duration::from_secs(0);
        let (secs, nsecs) = unpack_duration(d);
        assert_eq!(0, secs);
        assert_eq!(0, nsecs);
        assert_eq!(Ok(d), build_duration(secs, nsecs));
    }

    #[test]
    fn test_build_unpack_duration_secs_precision() {
        let d = Duration::from_secs(123456789123456789u64);
        let (secs, nsecs) = unpack_duration(d);
        assert_eq!(123456789123456789i64, secs);
        assert_eq!(0, nsecs);
        assert_eq!(Ok(d), build_duration(secs, nsecs));
    }

    #[test]
    fn test_build_unpack_duration_nsecs_precision() {
        let d = Duration::from_nanos(1234567899876543215u64);
        let (secs, nsecs) = unpack_duration(d);
        assert_eq!(1234567899i64, secs);
        assert_eq!(876543215i64, nsecs);
        assert_eq!(Ok(d), build_duration(secs, nsecs));
    }

    #[test]
    fn test_build_duration_negative() {
        match build_duration(-1, 0) {
            Err(DbError::DataIntegrityError(_)) => (),
            e => panic!("Must have failed with a DataIntegrityError but got: {:?}", e),
        }

        match build_duration(0, -1) {
            Err(DbError::DataIntegrityError(_)) => (),
            e => panic!("Must have failed with a DataIntegrityError but got: {:?}", e),
        }
    }

    #[test]
    fn test_build_unpack_timestamp_zero() {
        let d = OffsetDateTime::from_unix_timestamp(0).unwrap();
        let (secs, nsecs) = unpack_timestamp(d);
        assert_eq!(0, secs);
        assert_eq!(0, nsecs);
        assert_eq!(Ok(d), build_timestamp(secs, nsecs));
    }

    #[test]
    fn test_build_unpack_timestamp_secs_precision() {
        let d = OffsetDateTime::from_unix_timestamp(123456789i64).unwrap();
        let (secs, nsecs) = unpack_timestamp(d);
        assert_eq!(123456789i64, secs);
        assert_eq!(0, nsecs);
        assert_eq!(Ok(d), build_timestamp(secs, nsecs));
    }

    #[test]
    fn test_build_unpack_timestamp_nsecs_precision() {
        let d = OffsetDateTime::from_unix_timestamp_nanos(1234567899876543215i128).unwrap();
        let (secs, nsecs) = unpack_timestamp(d);
        assert_eq!(1234567899i64, secs);
        assert_eq!(876543215i64, nsecs);
        assert_eq!(Ok(d), build_timestamp(secs, nsecs));
    }

    #[test]
    fn test_build_timestamp_negative() {
        match build_timestamp(-1, 0) {
            Err(DbError::DataIntegrityError(_)) => (),
            e => panic!("Must have failed with a DataIntegrityError but got: {:?}", e),
        }

        match build_timestamp(0, -1) {
            Err(DbError::DataIntegrityError(_)) => (),
            e => panic!("Must have failed with a DataIntegrityError but got: {:?}", e),
        }
    }

    #[test]
    fn test_build_timestamp_too_big() {
        match build_timestamp(123456789123456789i64, 0) {
            Err(_) => (),
            Ok(_) => panic!("Must have failed"),
        }
    }
}
