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

    let entry = Entry::new("insert".to_owned(), Version::from_i32(1).unwrap());
    set_key(ex, &key, &entry).await.unwrap();
    assert_eq!(entry, get_key(ex, &key).await.unwrap());
    assert_eq!(Some(&entry.version), get_key_version(ex, &key).await.unwrap().as_ref());

    let entry = Entry::new("upsert".to_owned(), Version::from_i32(0).unwrap());
    set_key(ex, &key, &entry).await.unwrap();
    assert_eq!(entry, get_key(ex, &key).await.unwrap());
    assert_eq!(Some(&entry.version), get_key_version(ex, &key).await.unwrap().as_ref());

    delete_key(ex, &key).await.unwrap();

    assert_eq!(DbError::NotFound, get_key(ex, &key).await.unwrap_err());
    assert_eq!(None, get_key_version(ex, &key).await.unwrap());
}

async fn test_multiple_keys(ex: &mut Executor) {
    let key1 = Key::new("key 1".to_owned());
    let key2 = Key::new("key 2".to_owned());
    let entry = Entry::new("same value".to_owned(), Version::from_i32(123).unwrap());

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

async fn test_negative_version(ex: &mut Executor) {
    let key = Key::new("negative-version".to_owned());
    let (query, value) = match ex {
        Executor::Postgres(_) => ("UPDATE store SET version = $1 WHERE key = $2", -1_i32),
        #[cfg(test)]
        Executor::Sqlite(_) => ("UPDATE store SET version = ? WHERE key = ?", -1_i32),
    };
    set_key(ex, &key, &Entry::new("value".to_owned(), Version::initial())).await.unwrap();
    match ex {
        Executor::Postgres(ex) => {
            sqlx::query(query).bind(value).bind(key.as_ref()).execute(ex).await.unwrap();
        }
        #[cfg(test)]
        Executor::Sqlite(ex) => {
            sqlx::query(query).bind(value).bind(key.as_ref()).execute(ex).await.unwrap();
        }
    }
    assert!(get_key(ex, &key).await.is_err());
    assert!(get_key_version(ex, &key).await.is_err());
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
            test_multiple_keys,
            test_negative_version
        );
    }
];

mod postgres {
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

    #[tokio::test]
    async fn test_get_key_version_rejects_out_of_range_integer() {
        use crate::model::{Key, Version};
        use iii_iv_core::db::Db;

        let db = setup().await;
        let mut ex = db.ex().await.unwrap();
        let key = Key::new("out-of-range-version".to_owned());
        super::set_key(
            &mut ex,
            &key,
            &crate::model::Entry::new("value".to_owned(), Version::initial()),
        )
        .await
        .unwrap();
        sqlx::query("UPDATE store SET version = 2147483648 WHERE key = ?")
            .bind(key.as_ref())
            .execute(match &mut ex {
                iii_iv_core::db::Executor::Sqlite(ex) => ex,
                _ => unreachable!(),
            })
            .await
            .unwrap();
        assert!(super::get_key_version(&mut ex, &key).await.is_err());
    }
}
