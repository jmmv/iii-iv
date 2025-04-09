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

//! Common utilities to interact with a PostgreSQL database.

use crate::db::{Db, DbError, DbResult, Executor, TxExecutor};
use crate::env::{get_optional_var, get_required_var};
use async_trait::async_trait;
use derivative::Derivative;
use futures::future::BoxFuture;
use futures::Future;
use log::warn;
use sqlx::pool::PoolConnection;
use sqlx::postgres::{PgConnectOptions, PgDatabaseError, PgPool, PgPoolOptions, Postgres};
use sqlx::Transaction;
use std::time::Duration;

/// Default value for the `max_retries` configuration property.
const DEFAULT_MAX_RETRIES: u16 = 60;

/// Takes a raw SQLx error `e` and converts it to our generic error type.
pub fn map_sqlx_error(e: sqlx::Error) -> DbError {
    match e {
        sqlx::Error::ColumnDecode { source, .. } => DbError::DataIntegrityError(source.to_string()),
        sqlx::Error::Database(e) => match e.downcast_ref::<PgDatabaseError>().code() {
            "23503" /* foreign_key_violation */ => DbError::NotFound,
            "23505" /* unique_violation */ => DbError::AlreadyExists,
            "53300" /* too_many_connections */ => DbError::Unavailable,
            number => DbError::BackendError(format!("pgsql error {}: {}", number, e)),
        },
        sqlx::Error::PoolTimedOut => DbError::Unavailable,
        sqlx::Error::RowNotFound => DbError::NotFound,
        e => DbError::BackendError(e.to_string()),
    }
}

/// Options to establish a connection to a PostgreSQL database.
#[derive(Derivative)]
#[derivative(Debug, Default)]
#[cfg_attr(test, derivative(PartialEq))]
pub struct PostgresOptions {
    /// Host to connect to.
    pub host: String,

    /// Port to connect to (typically 5432).
    pub port: u16,

    /// Database name to connect to.
    pub database: String,

    /// Username to establish the connection with.
    pub username: String,

    /// Password to establish the connection with.
    #[derivative(Debug = "ignore")]
    pub password: String,

    /// Minimum number of connections to keep open against the database.
    pub min_connections: Option<u32>,

    /// Maximum number of connections to allow against the database.
    pub max_connections: Option<u32>,

    /// Maximum number of attempts to retry a connection operation when the database does not seem
    /// to be available.
    pub max_retries: u16,
}

impl PostgresOptions {
    /// Initializes a set of options from environment variables whose name is prefixed with the
    /// given `prefix`.
    ///
    /// This will use variables such as `<prefix>_HOST`, `<prefix>_PORT`, `<prefix>_DATABASE`,
    /// `<prefix>_USERNAME`, `<prefix>_PASSWORD`, `<prefix>_MIN_CONNECTIONS`,
    /// `<prefix>_MAX_CONNECTIONS` and `<prefix>_MAX_RETRIES`.
    pub fn from_env(prefix: &str) -> Result<PostgresOptions, String> {
        Ok(PostgresOptions {
            host: get_required_var::<String>(prefix, "HOST")?,
            port: get_required_var::<u16>(prefix, "PORT")?,
            database: get_required_var::<String>(prefix, "DATABASE")?,
            username: get_required_var::<String>(prefix, "USERNAME")?,
            password: get_required_var::<String>(prefix, "PASSWORD")?,
            min_connections: get_optional_var::<u32>(prefix, "MIN_CONNECTIONS")?,
            max_connections: get_optional_var::<u32>(prefix, "MAX_CONNECTIONS")?,
            max_retries: get_optional_var::<u16>(prefix, "MAX_RETRIES")?
                .unwrap_or(DEFAULT_MAX_RETRIES),
        })
    }
}

/// A generic database executor implementation for PostgreSQL.
#[derive(Debug)]
pub enum PostgresExecutor {
    /// An executor backed by a connection.
    PoolExec(PoolConnection<Postgres>),

    /// An executor backed by a transaction.
    TxExec(Transaction<'static, Postgres>),
}

impl PostgresExecutor {
    /// Commits the transaction if this executor is backed by one.
    ///
    /// Calling this on a non-transaction-based executor results in a panic.
    pub(super) async fn commit(self) -> DbResult<()> {
        match self {
            PostgresExecutor::PoolExec(_) => unreachable!("Do not call commit on direct executors"),
            PostgresExecutor::TxExec(tx) => tx.commit().await.map_err(map_sqlx_error),
        }
    }
}

impl<'c> sqlx::Executor<'c> for &'c mut PostgresExecutor {
    type Database = Postgres;

    fn describe<'e, 'q: 'e>(
        self,
        sql: &'q str,
    ) -> BoxFuture<'e, Result<sqlx::Describe<Self::Database>, sqlx::Error>>
    where
        'c: 'e,
    {
        match self {
            PostgresExecutor::PoolExec(conn) => conn.describe(sql),
            PostgresExecutor::TxExec(ref mut tx) => tx.describe(sql),
        }
    }

    fn execute<'e, 'q: 'e, E>(
        self,
        query: E,
    ) -> BoxFuture<'e, Result<<Self::Database as sqlx::Database>::QueryResult, sqlx::Error>>
    where
        'c: 'e,
        E: 'q + sqlx::Execute<'q, Self::Database>,
    {
        match self {
            PostgresExecutor::PoolExec(conn) => conn.execute(query),
            PostgresExecutor::TxExec(ref mut tx) => tx.execute(query),
        }
    }

    fn execute_many<'e, 'q: 'e, E>(
        self,
        query: E,
    ) -> futures::stream::BoxStream<
        'e,
        Result<<Self::Database as sqlx::Database>::QueryResult, sqlx::Error>,
    >
    where
        'c: 'e,
        E: 'q + sqlx::Execute<'q, Self::Database>,
    {
        match self {
            PostgresExecutor::PoolExec(conn) => conn.execute_many(query),
            PostgresExecutor::TxExec(ref mut tx) => tx.execute_many(query),
        }
    }

    fn fetch<'e, 'q: 'e, E>(
        self,
        query: E,
    ) -> futures::stream::BoxStream<'e, Result<<Self::Database as sqlx::Database>::Row, sqlx::Error>>
    where
        'c: 'e,
        E: 'q + sqlx::Execute<'q, Self::Database>,
    {
        match self {
            PostgresExecutor::PoolExec(conn) => conn.fetch(query),
            PostgresExecutor::TxExec(ref mut tx) => tx.fetch(query),
        }
    }

    fn fetch_all<'e, 'q: 'e, E>(
        self,
        query: E,
    ) -> BoxFuture<'e, Result<Vec<<Self::Database as sqlx::Database>::Row>, sqlx::Error>>
    where
        'c: 'e,
        E: 'q + sqlx::Execute<'q, Self::Database>,
    {
        match self {
            PostgresExecutor::PoolExec(conn) => conn.fetch_all(query),
            PostgresExecutor::TxExec(ref mut tx) => tx.fetch_all(query),
        }
    }

    fn fetch_many<'e, 'q: 'e, E>(
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
        E: 'q + sqlx::Execute<'q, Self::Database>,
    {
        match self {
            PostgresExecutor::PoolExec(conn) => conn.fetch_many(query),
            PostgresExecutor::TxExec(ref mut tx) => tx.fetch_many(query),
        }
    }

    fn fetch_one<'e, 'q: 'e, E>(
        self,
        query: E,
    ) -> BoxFuture<'e, Result<<Self::Database as sqlx::Database>::Row, sqlx::Error>>
    where
        'c: 'e,
        E: 'q + sqlx::Execute<'q, Self::Database>,
    {
        match self {
            PostgresExecutor::PoolExec(conn) => conn.fetch_one(query),
            PostgresExecutor::TxExec(ref mut tx) => tx.fetch_one(query),
        }
    }

    fn fetch_optional<'e, 'q: 'e, E>(
        self,
        query: E,
    ) -> BoxFuture<'e, Result<Option<<Self::Database as sqlx::Database>::Row>, sqlx::Error>>
    where
        'c: 'e,
        E: 'q + sqlx::Execute<'q, Self::Database>,
    {
        match self {
            PostgresExecutor::PoolExec(conn) => conn.fetch_optional(query),
            PostgresExecutor::TxExec(ref mut tx) => tx.fetch_optional(query),
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
            PostgresExecutor::PoolExec(conn) => conn.prepare(query),
            PostgresExecutor::TxExec(ref mut tx) => tx.prepare(query),
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
            PostgresExecutor::PoolExec(conn) => conn.prepare_with(sql, parameters),
            PostgresExecutor::TxExec(ref mut tx) => tx.prepare_with(sql, parameters),
        }
    }
}

/// Retries a database operation up to `retries` times.
async fn retry<Op, OpFut, T>(op: Op, mut retries: u16) -> DbResult<T>
where
    Op: Fn() -> OpFut,
    OpFut: Future<Output = Result<T, sqlx::Error>>,
    T: Send + Sync,
{
    let mut delay = Duration::from_millis(100 + u64::from(rand::random::<u16>() % 900));
    loop {
        match op().await.map_err(map_sqlx_error) {
            Ok(result) => return Ok(result),
            Err(DbError::Unavailable) => {
                if retries == 0 {
                    return Err(DbError::Unavailable);
                }
                retries -= 1;

                warn!(
                    "Database is unavailable; waiting {}ms before retrying with {} attempts left",
                    delay.as_millis(),
                    retries
                );

                tokio::time::sleep(delay).await;
                if delay < Duration::from_secs(5) {
                    delay += Duration::from_millis(u64::from(rand::random::<u16>() % 1000));
                }
            }
            Err(e) => return Err(e),
        }
    }
}

/// Shareable connection across transactions and `PostgresDb` types.
pub struct PostgresDb {
    /// Shared PostgreSQL connection pool.  This is a cloneable type that all concurrent
    /// transactions can use it concurrently.
    pool: PgPool,

    /// Maximum number of attempts to retry a connection operation when the database does not seem
    /// to be available.
    max_retries: u16,
}

impl Drop for PostgresDb {
    fn drop(&mut self) {
        if !self.pool.is_closed() {
            if cfg!(debug_assertions) {
                panic!("Dropping connection without having called close() first");
            } else {
                warn!("Dropping connection without having called close() first");
            }
        }
    }
}

impl PostgresDb {
    /// Creates a new connection based on a set of options.
    ///
    /// Note that this does *not* establish the connection.
    pub fn connect(opts: PostgresOptions) -> DbResult<Self> {
        let mut pool_options = PgPoolOptions::new();
        if let Some(min_connections) = opts.min_connections {
            pool_options = pool_options.min_connections(min_connections);
        }
        if let Some(max_connections) = opts.max_connections {
            pool_options = pool_options.max_connections(max_connections);
        }
        pool_options = pool_options.acquire_timeout(Duration::from_secs(2));

        let options = PgConnectOptions::new()
            .host(&opts.host)
            .port(opts.port)
            .database(&opts.database)
            .username(&opts.username)
            .password(&opts.password);

        let pool = pool_options.connect_lazy_with(options);
        Ok(Self { pool, max_retries: opts.max_retries })
    }

    /// Returns an executor of the specific type used by this database.
    pub async fn typed_ex(&self) -> DbResult<PostgresExecutor> {
        let conn = retry(|| self.pool.acquire(), self.max_retries).await?;
        Ok(PostgresExecutor::PoolExec(conn))
    }
}

#[async_trait]
impl Db for PostgresDb {
    async fn ex(&self) -> DbResult<Executor> {
        let ex = self.typed_ex().await?;
        Ok(Executor::Postgres(ex))
    }

    async fn begin(&self) -> DbResult<TxExecutor> {
        let tx = retry(|| self.pool.begin(), self.max_retries).await?;
        Ok(TxExecutor(Executor::Postgres(PostgresExecutor::TxExec(tx))))
    }

    async fn close(&self) {
        self.pool.close().await;
    }
}

/// Helper function to initialize the database with a schema.
pub async fn run_schema(e: &mut PostgresExecutor, schema: &str) -> DbResult<()> {
    // Strip out comments from the schema so that we can safely separate the statements by
    // looking for semicolons.
    let schema =
        regex::RegexBuilder::new("--.*$").multi_line(true).build().unwrap().replace_all(schema, "");

    for query_str in schema.split(';') {
        sqlx::query(query_str).execute(&mut *e).await.map_err(map_sqlx_error).unwrap();
    }
    Ok(())
}

/// Test utilities for the PostgreSQL connection.
#[cfg(any(feature = "testutils", test))]
pub mod testutils {
    use super::*;

    /// Creates a new connection to the test database and initializes it.
    ///
    /// This sets up the database to use the `pg_temp` schema by default so that any tables
    /// created during the test are deleted at disconnection time.  Note that for this to work,
    /// the connection pool must maintain a single connection open at all times, but not more.
    ///
    /// Given that this is for testing purposes only, any errors will panic.
    pub async fn setup() -> PostgresDb {
        let _can_fail = env_logger::builder().is_test(true).try_init();

        let mut opts = PostgresOptions::from_env("PGSQL_TEST").unwrap();
        opts.min_connections = Some(1);
        opts.max_connections = Some(1);
        let db = PostgresDb::connect(opts).unwrap();

        let mut ex = db.typed_ex().await.unwrap();
        sqlx::query("SET search_path TO pg_temp").execute(&mut ex).await.unwrap();
        db
    }
}

#[cfg(test)]
mod tests {
    use super::testutils::*;
    use super::*;
    use crate::db::tests::{generate_db_ro_concurrent_tests, generate_db_rw_tests};
    use std::env;
    use std::sync::Arc;

    generate_db_ro_concurrent_tests!(
        {
            let _can_fail = env_logger::builder().is_test(true).try_init();

            // We don't use testutils::setup() here because that function limits concurrent
            // connections to 1 but we need at least 2 for the concurrent tests to succeed.
            // This means that the tests cannot write to the database because we did not set
            // up the `search_path`.
            let db = Arc::from(PostgresDb::connect(PostgresOptions::from_env("PGSQL_TEST").unwrap()).unwrap());
            (db.clone(), db)
        },
        #[ignore = "Requires environment configuration and is expensive"]
    );

    generate_db_rw_tests!(
        {
            let db = Arc::from(setup().await);
            (db.clone(), db)
        },
        #[ignore = "Requires environment configuration and is expensive"]
    );

    #[test]
    pub fn test_postgres_options_from_env_all_required_present() {
        temp_env::with_vars(
            [
                ("PGSQL_HOST", Some("the-host")),
                ("PGSQL_PORT", Some("1234")),
                ("PGSQL_DATABASE", Some("the-database")),
                ("PGSQL_USERNAME", Some("the-username")),
                ("PGSQL_PASSWORD", Some("the-password")),
            ],
            || {
                let opts = PostgresOptions::from_env("PGSQL").unwrap();
                assert_eq!(
                    PostgresOptions {
                        host: "the-host".to_owned(),
                        port: 1234,
                        database: "the-database".to_owned(),
                        username: "the-username".to_owned(),
                        password: "the-password".to_owned(),
                        min_connections: None,
                        max_connections: None,
                        max_retries: DEFAULT_MAX_RETRIES,
                    },
                    opts
                );
            },
        );
    }

    #[test]
    pub fn test_postgres_options_from_env_all_required_and_optional_present() {
        temp_env::with_vars(
            [
                ("PGSQL_HOST", Some("the-host")),
                ("PGSQL_PORT", Some("1234")),
                ("PGSQL_DATABASE", Some("the-database")),
                ("PGSQL_USERNAME", Some("the-username")),
                ("PGSQL_PASSWORD", Some("the-password")),
                ("PGSQL_MIN_CONNECTIONS", Some("10")),
                ("PGSQL_MAX_CONNECTIONS", Some("20")),
                ("PGSQL_MAX_RETRIES", Some("30")),
            ],
            || {
                let opts = PostgresOptions::from_env("PGSQL").unwrap();
                assert_eq!(
                    PostgresOptions {
                        host: "the-host".to_owned(),
                        port: 1234,
                        database: "the-database".to_owned(),
                        username: "the-username".to_owned(),
                        password: "the-password".to_owned(),
                        min_connections: Some(10),
                        max_connections: Some(20),
                        max_retries: 30,
                    },
                    opts
                );
            },
        );
    }

    #[test]
    pub fn test_postgres_options_from_env_missing() {
        let overrides = [
            ("MISSING_HOST", Some("the-host")),
            ("MISSING_PORT", Some("1234")),
            ("MISSING_DATABASE", Some("the-database")),
            ("MISSING_USERNAME", Some("the-username")),
            ("MISSING_PASSWORD", Some("the-password")),
        ];
        for (var, _) in overrides {
            temp_env::with_vars(overrides, || {
                env::remove_var(var);
                let err = PostgresOptions::from_env("MISSING").unwrap_err();
                assert!(err.contains(&format!("{} not present", var)));
            });
        }
    }

    #[test]
    pub fn test_postgres_options_bad_port_type() {
        let overrides = [
            ("MISSING_HOST", Some("the-host")),
            ("MISSING_PORT", Some("not a number")),
            ("MISSING_DATABASE", Some("the-database")),
            ("MISSING_USERNAME", Some("the-username")),
            ("MISSING_PASSWORD", Some("the-password")),
        ];
        temp_env::with_vars(overrides, || {
            let err = PostgresOptions::from_env("MISSING").unwrap_err();
            assert!(err.contains("MISSING_PORT"));
            assert!(err.contains("Invalid u16"));
        });
    }
}
