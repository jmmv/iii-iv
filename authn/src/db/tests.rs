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
use crate::model::{AccessToken, HashedPassword, Session, User};
use iii_iv_core::clocks::testutils::utc_datetime;
use iii_iv_core::db::{DbError, Executor};
use iii_iv_core::model::{EmailAddress, Username};

/// Syntactic sugar to create a user with default settings given only its username.
async fn create_simple_user(ex: &mut Executor, username: &'static str) -> User {
    create_user(
        ex,
        Username::from(username),
        None,
        EmailAddress::new(format!("{}@example.com", username)).unwrap(),
    )
    .await
    .unwrap()
}

async fn test_users_ok(ex: &mut Executor) {
    let user = create_user(
        ex,
        Username::from("some-username"),
        Some(HashedPassword::new("some-hash")),
        EmailAddress::from("a@example.com"),
    )
    .await
    .unwrap();

    let exp_user = User::new(Username::from("some-username"), EmailAddress::from("a@example.com"))
        .with_password(HashedPassword::new("some-hash"));
    assert_eq!(exp_user, user);

    let user1 = get_user_by_username(ex, Username::from("some-username")).await.unwrap();
    assert_eq!(user, user1);
}

async fn test_users_not_found(ex: &mut Executor) {
    assert_eq!(
        DbError::NotFound,
        get_user_by_username(ex, Username::from("some-username")).await.unwrap_err()
    );
}

async fn test_user_corrupted_name(ex: &mut Executor) {
    let invalid = Username::new_invalid("this@is!invalid");
    create_user(ex, invalid.clone(), None, EmailAddress::from("a@example.com")).await.unwrap();
    match get_user_by_username(ex, invalid).await.unwrap_err() {
        DbError::DataIntegrityError(msg) if msg.contains("Unsupported character") => (),
        e => panic!("Unexpected error: {:?}", e),
    }
}

async fn test_user_corrupted_email(ex: &mut Executor) {
    let invalid = EmailAddress::new_invalid("this_is_invalid");
    create_user(ex, Username::from("a"), None, invalid).await.unwrap();
    match get_user_by_username(ex, Username::from("a")).await.unwrap_err() {
        DbError::DataIntegrityError(msg) if msg.contains("valid address") => (),
        e => panic!("Unexpected error: {:?}", e),
    }
}

async fn test_users_update_ok(ex: &mut Executor) {
    create_user(
        ex,
        Username::from("some-username"),
        Some(HashedPassword::new("some-hash")),
        EmailAddress::from("a@example.com"),
    )
    .await
    .unwrap();
    update_user(ex, Username::from("some-username"), utc_datetime(2022, 4, 2, 5, 50, 10))
        .await
        .unwrap();

    let exp_user = User::new(Username::from("some-username"), EmailAddress::from("a@example.com"))
        .with_password(HashedPassword::new("some-hash"))
        .with_last_login(utc_datetime(2022, 4, 2, 5, 50, 10));
    assert_eq!(exp_user, get_user_by_username(ex, Username::from("some-username")).await.unwrap());
}

async fn test_users_update_not_found(ex: &mut Executor) {
    match update_user(ex, Username::from("foo"), utc_datetime(2022, 4, 2, 6, 32, 0))
        .await
        .unwrap_err()
    {
        DbError::NotFound => (),
        e => panic!("{}", e),
    }

    match get_user_by_username(ex, Username::from("foo")).await.unwrap_err() {
        DbError::NotFound => (),
        e => panic!("{}", e),
    }
}

async fn test_set_user_activation_code_ok(ex: &mut Executor) {
    let mut user = create_user(
        ex,
        Username::from("some-username"),
        Some(HashedPassword::new("some-hash")),
        EmailAddress::from("a@example.com"),
    )
    .await
    .unwrap();
    assert!(user.activation_code().is_none());

    user = set_user_activation_code(ex, user, Some(123456)).await.unwrap();
    assert_eq!(Some(123456), user.activation_code());

    let read_user = get_user_by_username(ex, user.username().clone()).await.unwrap();
    assert_eq!(Some(123456), read_user.activation_code());

    user = set_user_activation_code(ex, user, None).await.unwrap();
    assert!(user.activation_code().is_none());

    let read_user = get_user_by_username(ex, user.username().clone()).await.unwrap();
    assert!(read_user.activation_code().is_none());
}

async fn test_set_user_activation_code_not_found(ex: &mut Executor) {
    let user = User::new(Username::from("foo"), EmailAddress::from("a@example.com"));

    match set_user_activation_code(ex, user, Some(1)).await.unwrap_err() {
        DbError::NotFound => (),
        e => panic!("{}", e),
    }

    match get_user_by_username(ex, Username::from("foo")).await.unwrap_err() {
        DbError::NotFound => (),
        e => panic!("{}", e),
    }
}

async fn test_sessions_ok(ex: &mut Executor) {
    create_simple_user(ex, "testuser1").await;
    let session1 = Session::new(
        AccessToken::generate(),
        Username::from("testuser1"),
        utc_datetime(2022, 5, 17, 6, 29, 28),
    );
    put_session(ex, &session1).await.unwrap();

    create_simple_user(ex, "testuser2").await;
    let session2 = Session::new(
        AccessToken::generate(),
        Username::from("testuser1"),
        utc_datetime(2022, 5, 17, 6, 29, 28),
    );
    put_session(ex, &session2).await.unwrap();

    assert_eq!(session1, get_session(ex, session1.access_token()).await.unwrap());
    assert_eq!(session2, get_session(ex, session2.access_token()).await.unwrap());

    // Mark one of the sessions as deleted.
    let access_token1 = session1.access_token().clone();
    delete_session(ex, session1, utc_datetime(2022, 5, 26, 8, 38, 10)).await.unwrap();
    match get_session(ex, &access_token1).await {
        Err(DbError::NotFound) => (),
        e => panic!("{:?}", e),
    }

    // Make sure the other session was unaffected.
    assert_eq!(session2, get_session(ex, session2.access_token()).await.unwrap());
}

async fn test_sessions_missing(ex: &mut Executor) {
    create_simple_user(ex, "testuser1").await;
    let session = Session::new(
        AccessToken::generate(),
        Username::from("testuser1"),
        utc_datetime(2022, 5, 17, 6, 29, 28),
    );
    put_session(ex, &session).await.unwrap();

    match get_session(ex, &AccessToken::generate()).await {
        Err(DbError::NotFound) => (),
        e => panic!("{:?}", e),
    }
}

macro_rules! generate_db_tests [
    ( $setup:expr $(, #[$extra:meta] )? ) => {
        iii_iv_core::db::testutils::generate_tests!(
            $(#[$extra],)?
            $setup,
            $crate::db::tests,
            test_users_ok,
            test_users_not_found,
            test_user_corrupted_name,
            test_user_corrupted_email,
            test_users_update_ok,
            test_users_update_not_found,
            test_set_user_activation_code_ok,
            test_set_user_activation_code_not_found,
            test_sessions_ok,
            test_sessions_missing
        );
    }
];

use generate_db_tests;

mod postgres {
    use super::*;
    use crate::db::init_schema;
    use iii_iv_core::db::postgres::PostgresDb;
    use iii_iv_core::db::Db;

    async fn setup() -> PostgresDb {
        let db = iii_iv_core::db::postgres::testutils::setup().await;
        init_schema(&mut db.ex()).await.unwrap();
        db
    }

    generate_db_tests!(
        &mut setup().await.ex(),
        #[ignore = "Requires environment configuration and is expensive"]
    );
}

mod sqlite {
    use super::*;
    use crate::db::init_schema;
    use iii_iv_core::db::sqlite::SqliteDb;
    use iii_iv_core::db::Db;

    async fn setup() -> SqliteDb {
        let db = iii_iv_core::db::sqlite::testutils::setup().await;
        init_schema(&mut db.ex()).await.unwrap();
        db
    }

    generate_db_tests!(&mut setup().await.ex());
}
