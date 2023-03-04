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

use crate::db::Tx;
use crate::model::*;
use iii_iv_core::db::{BareTx, Db, DbError};

pub(crate) async fn test_sequence_one<D>(db: D)
where
    D: Db,
    D::Tx: Tx,
{
    let key = Key::new("the-key".to_owned());

    let mut tx = db.begin().await.unwrap();

    assert_eq!(DbError::NotFound, tx.get_key(&key).await.unwrap_err());
    assert_eq!(None, tx.get_key_version(&key).await.unwrap());

    let entry = Entry::new("insert".to_owned(), Version::from_u32(1).unwrap());
    tx.set_key(&key, &entry).await.unwrap();
    assert_eq!(entry, tx.get_key(&key).await.unwrap());
    assert_eq!(Some(entry.version()), tx.get_key_version(&key).await.unwrap().as_ref());

    let entry = Entry::new("upsert".to_owned(), Version::from_u32(0).unwrap());
    tx.set_key(&key, &entry).await.unwrap();
    assert_eq!(entry, tx.get_key(&key).await.unwrap());
    assert_eq!(Some(entry.version()), tx.get_key_version(&key).await.unwrap().as_ref());

    tx.delete_key(&key).await.unwrap();

    assert_eq!(DbError::NotFound, tx.get_key(&key).await.unwrap_err());
    assert_eq!(None, tx.get_key_version(&key).await.unwrap());

    tx.commit().await.unwrap();
}

pub(crate) async fn test_multiple_keys<D>(db: D)
where
    D: Db,
    D::Tx: Tx,
{
    let key1 = Key::new("key 1".to_owned());
    let key2 = Key::new("key 2".to_owned());
    let entry = Entry::new("same value".to_owned(), Version::from_u32(123).unwrap());

    let mut tx = db.begin().await.unwrap();

    assert_eq!(DbError::NotFound, tx.get_key(&key1).await.unwrap_err());
    assert_eq!(DbError::NotFound, tx.get_key(&key2).await.unwrap_err());

    tx.set_key(&key1, &entry).await.unwrap();

    assert_eq!(entry, tx.get_key(&key1).await.unwrap());
    assert_eq!(DbError::NotFound, tx.get_key(&key2).await.unwrap_err());

    assert_eq!(DbError::NotFound, tx.delete_key(&key2).await.unwrap_err());

    assert_eq!(entry, tx.get_key(&key1).await.unwrap());
    assert_eq!(DbError::NotFound, tx.get_key(&key2).await.unwrap_err());

    tx.set_key(&key2, &entry).await.unwrap();

    assert_eq!(entry, tx.get_key(&key1).await.unwrap());
    assert_eq!(entry, tx.get_key(&key2).await.unwrap());

    tx.commit().await.unwrap();
}

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

pub(crate) use generate_db_tests;
