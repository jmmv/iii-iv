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
use iii_iv_core::db::sqlite::unpack_timestamp;
use time::macros::{date, datetime};

async fn raw_insert_email_log_with_id(ex: &mut Executor, id: i64) -> Result<(), sqlx::Error> {
    let sent = datetime!(2023-06-11 00:00:00.000000 UTC);
    match ex {
        Executor::Postgres(ex) => {
            sqlx::query("INSERT INTO email_log (id, sent, message) VALUES ($1, $2, $3)")
                .bind(id)
                .bind(sent)
                .bind(vec![0_u8])
                .execute(ex)
                .await?;
        }

        Executor::Sqlite(ex) => {
            let (sent_sec, sent_nsec) = unpack_timestamp(sent);
            sqlx::query(
                "INSERT INTO email_log (id, sent_sec, sent_nsec, message) VALUES (?, ?, ?, ?)",
            )
            .bind(id)
            .bind(sent_sec)
            .bind(sent_nsec)
            .bind(vec![0_u8])
            .execute(ex)
            .await?;
        }
    }
    Ok(())
}

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

async fn test_email_log_id_domain(ex: &mut Executor) {
    let message = Message::builder()
        .from("from@example.com".parse().unwrap())
        .to("to@example.com".parse().unwrap())
        .subject("Foo")
        .body("Bar".to_owned())
        .unwrap();

    let id = put_email_log(ex, &message, datetime!(2026-11-01 08:11:00 UTC)).await.unwrap();
    assert!(id > 0);
    update_email_log(ex, id, "OK").await.unwrap();
    assert_eq!(Some("OK"), get_email_log(ex).await.unwrap()[0].2.as_deref());

    raw_insert_email_log_with_id(ex, i64::from(i32::MIN)).await.unwrap();
    raw_insert_email_log_with_id(ex, i64::from(i32::MAX)).await.unwrap();
    assert!(raw_insert_email_log_with_id(ex, i64::from(i32::MIN) - 1).await.is_err());
    assert!(raw_insert_email_log_with_id(ex, i64::from(i32::MAX) + 1).await.is_err());
}

async fn test_delete_email_logs_by_recipient(ex: &mut Executor) {
    let recipient = iii_iv_core::model::email_address!("owner@example.com");
    let now = datetime!(2026-11-19 00:00 UTC);
    for message in [
        Message::builder()
            .from("from@example.com".parse().unwrap())
            .to("Owner <owner@example.com>".parse().unwrap())
            .body("Direct".to_owned())
            .unwrap(),
        Message::builder()
            .from("from@example.com".parse().unwrap())
            .to("other@example.com".parse().unwrap())
            .cc("owner@example.com".parse().unwrap())
            .body("Copy".to_owned())
            .unwrap(),
        Message::builder()
            .from("from@example.com".parse().unwrap())
            .to("other@example.com".parse().unwrap())
            .bcc("owner@example.com".parse().unwrap())
            .keep_bcc()
            .body("Blind".to_owned())
            .unwrap(),
        Message::builder()
            .from("owner@example.com".parse().unwrap())
            .to("other-owner@example.com".parse().unwrap())
            .subject("owner@example.com")
            .body("owner@example.com".to_owned())
            .unwrap(),
    ] {
        let id = put_email_log(ex, &message, now).await.unwrap();
        update_email_log(ex, id, "retained SMTP result").await.unwrap();
    }
    assert_eq!(3, delete_email_logs_by_recipient(ex, &recipient).await.unwrap());
    let logs = get_email_log(ex).await.unwrap();
    assert_eq!(1, logs.len());
    assert_eq!(Some("retained SMTP result"), logs[0].2.as_deref());
    assert_eq!(0, delete_email_logs_by_recipient(ex, &recipient).await.unwrap());
}

async fn test_delete_email_logs_malformed(ex: &mut Executor) {
    let recipient = iii_iv_core::model::email_address!("owner@example.com");
    let message = Message::builder()
        .from("from@example.com".parse().unwrap())
        .to("owner@example.com".parse().unwrap())
        .body("Direct".to_owned())
        .unwrap();
    put_email_log(ex, &message, datetime!(2026-11-19 00:00 UTC)).await.unwrap();
    raw_insert_email_log_with_id(ex, 100).await.unwrap();
    assert!(matches!(
        delete_email_logs_by_recipient(ex, &recipient).await,
        Err(DbError::DataIntegrityError(_))
    ));
    assert_eq!(2, get_email_log(ex).await.unwrap().len());
}

#[test]
fn test_recipient_header_parsing() {
    let recipient = iii_iv_core::model::email_address!("owner@example.com");
    for headers in [
        "To: Friends: Other <other@example.com>, Owner <owner@example.com>;\r\n",
        "tO: Other <other@example.com>,\r\n Owner <owner@example.com>\r\n",
        "To: =?utf-8?b?T3duZXI=?= <owner@example.com>\r\n",
    ] {
        assert!(has_recipient(format!("{}\r\nBody", headers).as_bytes(), &recipient).unwrap());
    }
    assert!(
        !has_recipient(b"To: other-owner@example.com\r\n\r\nowner@example.com", &recipient)
            .unwrap()
    );
    assert!(has_recipient(b"To: invalid-mailbox\r\n\r\n", &recipient).is_err());
}

macro_rules! generate_db_tests [
    ( $setup:expr $(, #[$extra:meta] )? ) => {
        iii_iv_core::db::testutils::generate_tests!(
            $(#[$extra],)?
            $setup,
            $crate::db::tests,
            test_email_log,
            test_email_log_id_domain,
            test_delete_email_logs_by_recipient,
            test_delete_email_logs_malformed
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
    use super::raw_insert_email_log_with_id;
    use crate::db::init_schema;
    use iii_iv_core::db::Db;
    use iii_iv_core::db::sqlite::SqliteDb;
    use std::sync::Arc;
    use time::macros::datetime;

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
    async fn test_generated_email_id_cannot_cross_int4_maximum() {
        let db = setup().await;
        let mut ex = db.ex().await.unwrap();

        raw_insert_email_log_with_id(&mut ex, i64::from(i32::MAX)).await.unwrap();
        let message = lettre::Message::builder()
            .from("from@example.com".parse().unwrap())
            .to("to@example.com".parse().unwrap())
            .subject("Foo")
            .body("Bar".to_owned())
            .unwrap();
        assert!(
            crate::db::put_email_log(&mut ex, &message, datetime!(2026-11-01 08:15:00 UTC))
                .await
                .is_err()
        );
    }
}
