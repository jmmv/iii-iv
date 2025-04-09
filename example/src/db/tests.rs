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

//! Database tests shared by all implementations.

use crate::db::*;
use iii_iv_core::db::DbError;

async fn test_sequence_one(ex: &mut Executor) {
    let key = Key::new("the-key".to_owned());

    assert_eq!(DbError::NotFound, get_key(ex, &key).await.unwrap_err());
    assert_eq!(None, get_key_version(ex, &key).await.unwrap());

    let entry = Entry::new("insert".to_owned(), Version::from_u32(1).unwrap());
    set_key(ex, &key, &entry).await.unwrap();
    assert_eq!(entry, get_key(ex, &key).await.unwrap());
    assert_eq!(Some(entry.version()), get_key_version(ex, &key).await.unwrap().as_ref());

    let entry = Entry::new("upsert".to_owned(), Version::from_u32(0).unwrap());
    set_key(ex, &key, &entry).await.unwrap();
    assert_eq!(entry, get_key(ex, &key).await.unwrap());
    assert_eq!(Some(entry.version()), get_key_version(ex, &key).await.unwrap().as_ref());

    delete_key(ex, &key).await.unwrap();

    assert_eq!(DbError::NotFound, get_key(ex, &key).await.unwrap_err());
    assert_eq!(None, get_key_version(ex, &key).await.unwrap());
}

async fn test_multiple_keys(ex: &mut Executor) {
    let key1 = Key::new("key 1".to_owned());
    let key2 = Key::new("key 2".to_owned());
    let entry = Entry::new("same value".to_owned(), Version::from_u32(123).unwrap());

    assert_eq!(DbError::NotFound, get_key(ex, &key1).await.unwrap_err());
    assert_eq!(DbError::NotFound, get_key(ex, &key2).await.unwrap_err());

    set_key(ex, &key1, &entry).await.unwrap();

    assert_eq!(entry, get_key(ex, &key1).await.unwrap());
    assert_eq!(DbError::NotFound, get_key(ex, &key2).await.unwrap_err());

    assert_eq!(DbError::NotFound, delete_key(ex, &key2).await.unwrap_err());

    assert_eq!(entry, get_key(ex, &key1).await.unwrap());
    assert_eq!(DbError::NotFound, get_key(ex, &key2).await.unwrap_err());

    set_key(ex, &key2, &entry).await.unwrap();

    assert_eq!(entry, get_key(ex, &key1).await.unwrap());
    assert_eq!(entry, get_key(ex, &key2).await.unwrap());
}

/// Instantiates the database tests for this module.
#[macro_export]
macro_rules! generate_db_tests [
    ( $setup:expr $(, #[$extra:meta])? ) => {
        iii_iv_core::db::testutils::generate_tests!(
            $( #[$extra], )?
            $setup,
            $crate::db::tests,
            test_sequence_one,
            test_multiple_keys
        );
    }
];

use generate_db_tests;

mod postgres {
    use super::*;
    use crate::db::init_schema;
    use iii_iv_core::db::Db;
    use iii_iv_core::db::postgres::PostgresDb;
    use std::sync::Arc;

    async fn setup() -> PostgresDb {
        let db = iii_iv_core::db::postgres::testutils::setup().await;
        init_schema(&mut db.ex().await.unwrap()).await.unwrap();
        db
    }

    generate_db_tests!(
        {
            let db = Arc::from(setup().await);
            (db.clone(), &mut db.ex().await.unwrap())
        },
        #[ignore = "Requires environment configuration and is expensive"]
    );
}

mod sqlite {
    use super::*;
    use crate::db::init_schema;
    use iii_iv_core::db::Db;
    use iii_iv_core::db::sqlite::SqliteDb;
    use std::sync::Arc;

    async fn setup() -> SqliteDb {
        let db = iii_iv_core::db::sqlite::testutils::setup().await;
        init_schema(&mut db.ex().await.unwrap()).await.unwrap();
        db
    }

    generate_db_tests!({
        let db = Arc::from(setup().await);
        (db.clone(), &mut db.ex().await.unwrap())
    });
}
