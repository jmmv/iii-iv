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

// Keep these in sync with other top-level files.
#![warn(anonymous_parameters, bad_style, clippy::missing_docs_in_private_items, missing_docs)]
#![warn(unused, unused_extern_crates, unused_import_braces, unused_qualifications)]
#![warn(unsafe_code)]

use derivative::Derivative;
use iii_iv_core::db::{BareTx, Db, DbError, DbResult};
use iii_iv_core::env::{get_optional_var, get_required_var};
use sqlx::postgres::{PgConnectOptions, PgDatabaseError, PgPool, PgPoolOptions, Postgres};
use sqlx::Transaction;
use std::marker::PhantomData;
#[cfg(test)]
use std::sync::Arc;

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
}

impl PostgresOptions {
    /// Initializes a set of options from environment variables whose name is prefixed with the
    /// given `prefix`.
    ///
    /// This will use variables such as `<prefix>_HOST`, `<prefix>_PORT`, `<prefix>_DATABASE`,
    /// `<prefix>_USERNAME`, `<prefix>_PASSWORD`, `<prefix>_MIN_CONNECTIONS` and
    /// `<prefix>_MAX_CONNECTIONS`.
    pub fn from_env(prefix: &str) -> Result<PostgresOptions, String> {
        Ok(PostgresOptions {
            host: get_required_var::<String>(prefix, "HOST")?,
            port: get_required_var::<u16>(prefix, "PORT")?,
            database: get_required_var::<String>(prefix, "DATABASE")?,
            username: get_required_var::<String>(prefix, "USERNAME")?,
            password: get_required_var::<String>(prefix, "PASSWORD")?,
            min_connections: get_optional_var::<u32>(prefix, "MIN_CONNECTIONS")?,
            max_connections: get_optional_var::<u32>(prefix, "MAX_CONNECTIONS")?,
        })
    }
}

#[cfg(test)]
struct PoolCloser {
    pool: PgPool,
}

#[cfg(test)]
impl Drop for PoolCloser {
    #[allow(unused_must_use)]
    fn drop(&mut self) {
        // Forcibly terminate open connections to release server resources early.  This is required
        // to prevent other tests from stalling, even if running with low parallelism.
        //
        // Note that this is a best-effort operation so, if the server is slow in releasing
        // resources, other threads might not be able to gather new connections.  To handle this
        // case, the connection logic in `connect_lazy_for_test` implements retries.
        self.pool.close();
    }
}

/// Shareable connection across transactions and `PostgresDb` types.
#[derive(Derivative)]
#[derivative(Clone(bound = ""))]
pub struct PostgresPool {
    /// Shared PostgreSQL connection pool.  This is a cloneable type that all concurrent
    /// transactions can use it concurrently.
    pool: PgPool,

    /// Automatic connection closer for tests to limit concurrent connections.
    #[cfg(test)]
    closer: Arc<PoolCloser>,
}

impl PostgresPool {
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

        let options = PgConnectOptions::new()
            .host(&opts.host)
            .port(opts.port)
            .database(&opts.database)
            .username(&opts.username)
            .password(&opts.password);

        let pool = pool_options.connect_lazy_with(options);

        #[cfg(not(test))]
        let db = Self { pool };

        #[cfg(test)]
        let db = Self { pool: pool.clone(), closer: Arc::from(PoolCloser { pool }) };

        Ok(db)
    }

    /// Opens a new transaction.
    async fn begin(&self) -> DbResult<Transaction<'static, Postgres>> {
        self.pool.begin().await.map_err(map_sqlx_error)
    }
}

/// A database instance backed by a PostgreSQL database.
#[derive(Derivative)]
#[derivative(Clone(bound = ""))]
pub struct PostgresDb<T>
where
    T: BareTx + From<Transaction<'static, Postgres>> + Send + Sync + 'static,
{
    /// Shared PostgreSQL connection pool.
    pool: PostgresPool,

    /// Marker for the unused type `T`.
    _phantom_tx: PhantomData<T>,
}

impl<T> PostgresDb<T>
where
    T: BareTx + From<Transaction<'static, Postgres>> + Send + Sync + 'static,
{
    /// Attaches a new database of type `T` to an existing pool.
    ///
    /// This takes care of running the migration process for the type `T`, which in turn results
    /// in the database connection being established.
    pub async fn attach(pool: PostgresPool) -> DbResult<PostgresDb<T>> {
        let db = Self { pool, _phantom_tx: PhantomData };

        let mut tx: T = db.begin().await?;
        tx.migrate().await?;
        tx.commit().await?;

        Ok(db)
    }
}

#[async_trait::async_trait]
impl<T> Db for PostgresDb<T>
where
    T: BareTx + From<Transaction<'static, Postgres>> + Send + Sync + 'static,
{
    type Tx = T;

    async fn begin(&self) -> DbResult<Self::Tx> {
        let tx = self.pool.begin().await?;
        Ok(Self::Tx::from(tx))
    }
}

/// Helper function to initialize the database with a schema.  Use in implementations of
/// `BareTx::migrate`.
pub async fn run_schema(tx: &mut Transaction<'static, Postgres>, schema: &str) -> DbResult<()> {
    // Strip out comments from the schema so that we can safely separate the statements by
    // looking for semicolons.
    let schema =
        regex::RegexBuilder::new("--.*$").multi_line(true).build().unwrap().replace_all(schema, "");

    for query_str in schema.split(';') {
        sqlx::query(query_str).execute(&mut *tx).await.map_err(map_sqlx_error).unwrap();
    }
    Ok(())
}

/// Test utilities for the PostgreSQL connection.
#[cfg(any(feature = "testutils", test))]
pub mod testutils {
    use super::*;
    use std::time::Duration;

    /// A transaction backed by a PostgreSQL database.
    pub(crate) struct PostgresTestTx {
        /// Inner transaction type to obtain access to the raw sqlx transaction.
        tx: Transaction<'static, Postgres>,
    }

    impl From<Transaction<'static, Postgres>> for PostgresTestTx {
        fn from(tx: Transaction<'static, Postgres>) -> Self {
            Self { tx }
        }
    }

    #[async_trait::async_trait]
    impl BareTx for PostgresTestTx {
        async fn commit(mut self) -> DbResult<()> {
            self.tx.commit().await.map_err(map_sqlx_error)
        }
    }

    /// Creates a new connection to the test database and initializes it.
    ///
    /// This sets up the database to use the `pg_temp` schema by default so that any tables
    /// created during the test are deleted at disconnection time.  Note that for this to work,
    /// the connection pool must maintain a single connection open at all times, but not more.
    ///
    /// Given that this is for testing purposes only, any errors will panic.
    pub async fn setup<T>() -> PostgresDb<T>
    where
        T: BareTx + From<Transaction<'static, Postgres>> + Send + Sync + 'static,
    {
        let _can_fail = env_logger::builder().is_test(true).try_init();

        let mut opts = PostgresOptions::from_env("PGSQL_TEST").unwrap();
        opts.min_connections = Some(1);
        opts.max_connections = Some(1);
        let pool = PostgresPool::connect(opts).unwrap();
        // We don't use attach because we don't want to run the DB migration code.
        let db = PostgresDb { pool, _phantom_tx: PhantomData };

        let mut tx;
        let mut delay = Duration::from_millis(100 + rand::random::<u64>() % 100);
        loop {
            match db.pool.begin().await {
                Ok(tx2) => {
                    tx = tx2;
                    break;
                }
                Err(DbError::Unavailable) => {
                    std::thread::sleep(delay);
                    if delay < Duration::from_secs(5) {
                        delay += Duration::from_millis(rand::random::<u64>() % 100);
                    }
                }
                Err(e) => panic!("{:?}", e),
            }
        }
        sqlx::query("SET search_path TO pg_temp")
            .execute(&mut tx)
            .await
            .map_err(map_sqlx_error)
            .unwrap();
        tx.commit().await.unwrap();

        // Now that we have prepared the database and set up the temporary schema, initialize the
        // database.
        let mut tx: T = db.begin().await.unwrap();
        tx.migrate_test().await.unwrap();
        tx.commit().await.unwrap();

        db
    }

    /// Initializes another test database sharing the connection of `other`.
    pub async fn setup_attach<T, O>(other: PostgresDb<O>) -> PostgresDb<T>
    where
        T: BareTx + From<Transaction<'static, Postgres>> + Send + Sync + 'static,
        O: BareTx + From<Transaction<'static, Postgres>> + Send + Sync + 'static,
    {
        // We don't use attach because we don't want to run the DB migration code.
        let db = PostgresDb { pool: other.pool, _phantom_tx: PhantomData };

        // Unlike attach, we do not set up the `pg_temp` schema here because we assume this already
        // happened while setting up `other`.

        // Now that we have prepared the database and set up the temporary schema, initialize the
        // database.
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
    use std::env;
    use std::sync::atomic::{AtomicBool, Ordering};

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

    /// Creates a new connection to the test database and initializes it.
    async fn setup() -> PostgresDb<PostgresTestTx> {
        let _can_fail = env_logger::builder().is_test(true).try_init();

        // We don't use connect_lazy_for_test here because that function must limit concurrent
        // connections to 1, yet we need at least 2 connections for our tests here to succeed.
        // This means we cannot write to the database because we did not set up the `search_path`.
        let pool = PostgresPool::connect(PostgresOptions::from_env("PGSQL_TEST").unwrap()).unwrap();
        PostgresDb::attach(pool).await.unwrap()
    }

    generate_core_db_tests!(
        setup().await,
        #[ignore = "Requires environment configuration and is expensive"]
    );

    /// Tracks whether `AttachTx::migrate_test` has been called.  Only one test can exercise
    /// this due to the process-wide nature of the static value.
    static ATTACH_TX_MIGRATE_TEST_CALLED: AtomicBool = AtomicBool::new(false);

    /// A transaction backed by a PostgreSQL database used to verify the behavior of the
    /// `setup_attach` method.
    struct AttachTx {
        /// Inner transaction type to obtain access to the raw sqlx transaction.
        tx: Transaction<'static, Postgres>,
    }

    impl From<Transaction<'static, Postgres>> for AttachTx {
        fn from(tx: Transaction<'static, Postgres>) -> Self {
            Self { tx }
        }
    }

    #[async_trait::async_trait]
    impl BareTx for AttachTx {
        async fn commit(mut self) -> DbResult<()> {
            self.tx.commit().await.map_err(map_sqlx_error)
        }

        async fn migrate(&mut self) -> DbResult<()> {
            unreachable!("Should not be called during tests");
        }

        async fn migrate_test(&mut self) -> DbResult<()> {
            let called = ATTACH_TX_MIGRATE_TEST_CALLED
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .unwrap();
            assert!(!called);
            Ok(())
        }
    }

    #[ignore = "Requires environment configuration and is expensive"]
    #[tokio::test]
    async fn test_setup_attach() {
        let db1: PostgresDb<PostgresTestTx> = setup().await;

        assert!(!ATTACH_TX_MIGRATE_TEST_CALLED.load(Ordering::SeqCst));
        let db2: PostgresDb<AttachTx> = setup_attach(db1).await;
        assert!(ATTACH_TX_MIGRATE_TEST_CALLED.load(Ordering::SeqCst));

        let tx = db2.begin().await.unwrap();
        tx.commit().await.unwrap();
    }
}
