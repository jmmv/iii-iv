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

//! Common tests for any database implementation.

use crate::db::*;
use iii_iv_core::db::Executor;
use time::macros::{date, datetime};

async fn test_email_log(ex: &mut Executor) {
    // The message contents should be completely irrelevant for counting purposes, so keeping
    // them all identical helps assert that.
    let message = Message::builder()
        .from("from@example.com".parse().unwrap())
        .to("to@example.com".parse().unwrap())
        .subject("Foo")
        .body("Bar".to_owned())
        .unwrap();

    put_email_log(ex, &message, datetime!(2023-06-11 00:00:00.000000 UTC)).await.unwrap();
    put_email_log(ex, &message, datetime!(2023-06-12 06:20:00.000001 UTC)).await.unwrap();
    put_email_log(ex, &message, datetime!(2023-06-12 06:20:00.000002 UTC)).await.unwrap();
    put_email_log(ex, &message, datetime!(2023-06-12 23:59:59.999999 UTC)).await.unwrap();

    assert_eq!(0, count_email_log(ex, date!(2023 - 06 - 10)).await.unwrap());
    assert_eq!(1, count_email_log(ex, date!(2023 - 06 - 11)).await.unwrap());
    assert_eq!(3, count_email_log(ex, date!(2023 - 06 - 12)).await.unwrap());
    assert_eq!(0, count_email_log(ex, date!(2023 - 06 - 13)).await.unwrap());
}

macro_rules! generate_db_tests [
    ( $setup:expr $(, #[$extra:meta] )? ) => {
        iii_iv_core::db::testutils::generate_tests!(
            $(#[$extra],)?
            $setup,
            $crate::db::tests,
            test_email_log
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
