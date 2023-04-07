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

use crate::db::AuthnTx;
use crate::model::{AccessToken, HashedPassword, Session, User};
use iii_iv_core::clocks::testutils::utc_datetime;
use iii_iv_core::db::{Db, DbError};
use iii_iv_core::model::{EmailAddress, Username};

/// Syntactic sugar to create a user with default settings given only its username.
async fn create_simple_user<T: AuthnTx>(tx: &mut T, username: &'static str) -> User {
    tx.create_user(
        Username::from(username),
        None,
        EmailAddress::new(format!("{}@example.com", username)).unwrap(),
    )
    .await
    .unwrap()
}

pub(crate) async fn test_users_ok<D>(db: D)
where
    D: Db,
    D::Tx: AuthnTx,
{
    let mut tx = db.begin().await.unwrap();

    let user = tx
        .create_user(
            Username::from("some-username"),
            Some(HashedPassword::new("some-hash")),
            EmailAddress::from("a@example.com"),
        )
        .await
        .unwrap();

    let exp_user = User::new(Username::from("some-username"), EmailAddress::from("a@example.com"))
        .with_password(HashedPassword::new("some-hash"));
    assert_eq!(exp_user, user);

    let user1 = tx.get_user_by_username(Username::from("some-username")).await.unwrap();
    assert_eq!(user, user1);
}

pub(crate) async fn test_users_abort_creation_and_not_found<D>(db: D)
where
    D: Db,
    D::Tx: AuthnTx,
{
    {
        let mut tx = db.begin().await.unwrap();
        create_simple_user(&mut tx, "some-username").await;
    }

    let mut tx = db.begin().await.unwrap();
    assert_eq!(
        DbError::NotFound,
        tx.get_user_by_username(Username::from("some-username")).await.unwrap_err()
    );
}

pub(crate) async fn test_user_corrupted_name<D>(db: D)
where
    D: Db,
    D::Tx: AuthnTx,
{
    let mut tx = db.begin().await.unwrap();

    let invalid = Username::new_invalid("this@is!invalid");
    tx.create_user(invalid.clone(), None, EmailAddress::from("a@example.com")).await.unwrap();
    match tx.get_user_by_username(invalid).await.unwrap_err() {
        DbError::DataIntegrityError(msg) if msg.contains("Unsupported character") => (),
        e => panic!("Unexpected error: {:?}", e),
    }
}

pub(crate) async fn test_user_corrupted_email<D>(db: D)
where
    D: Db,
    D::Tx: AuthnTx,
{
    let mut tx = db.begin().await.unwrap();

    let invalid = EmailAddress::new_invalid("this_is_invalid");
    tx.create_user(Username::from("a"), None, invalid).await.unwrap();
    match tx.get_user_by_username(Username::from("a")).await.unwrap_err() {
        DbError::DataIntegrityError(msg) if msg.contains("valid address") => (),
        e => panic!("Unexpected error: {:?}", e),
    }
}

pub(crate) async fn test_users_update_ok<D>(db: D)
where
    D: Db,
    D::Tx: AuthnTx,
{
    let mut tx = db.begin().await.unwrap();

    tx.create_user(
        Username::from("some-username"),
        Some(HashedPassword::new("some-hash")),
        EmailAddress::from("a@example.com"),
    )
    .await
    .unwrap();
    tx.update_user(Username::from("some-username"), utc_datetime(2022, 4, 2, 5, 50, 10))
        .await
        .unwrap();

    let exp_user = User::new(Username::from("some-username"), EmailAddress::from("a@example.com"))
        .with_password(HashedPassword::new("some-hash"))
        .with_last_login(utc_datetime(2022, 4, 2, 5, 50, 10));
    assert_eq!(exp_user, tx.get_user_by_username(Username::from("some-username")).await.unwrap());
}

pub(crate) async fn test_users_update_not_found<D>(db: D)
where
    D: Db,
    D::Tx: AuthnTx,
{
    let mut tx = db.begin().await.unwrap();

    match tx
        .update_user(Username::from("foo"), utc_datetime(2022, 4, 2, 6, 32, 0))
        .await
        .unwrap_err()
    {
        DbError::NotFound => (),
        e => panic!("{}", e),
    }

    match tx.get_user_by_username(Username::from("foo")).await.unwrap_err() {
        DbError::NotFound => (),
        e => panic!("{}", e),
    }
}

pub(crate) async fn test_set_user_activation_code_ok<D>(db: D)
where
    D: Db,
    D::Tx: AuthnTx,
{
    let mut tx = db.begin().await.unwrap();

    let mut user = tx
        .create_user(
            Username::from("some-username"),
            Some(HashedPassword::new("some-hash")),
            EmailAddress::from("a@example.com"),
        )
        .await
        .unwrap();
    assert!(user.activation_code().is_none());

    user = tx.set_user_activation_code(user, Some(123456)).await.unwrap();
    assert_eq!(Some(123456), user.activation_code());

    let read_user = tx.get_user_by_username(user.username().clone()).await.unwrap();
    assert_eq!(Some(123456), read_user.activation_code());

    user = tx.set_user_activation_code(user, None).await.unwrap();
    assert!(user.activation_code().is_none());

    let read_user = tx.get_user_by_username(user.username().clone()).await.unwrap();
    assert!(read_user.activation_code().is_none());
}

pub(crate) async fn test_set_user_activation_code_not_found<D>(db: D)
where
    D: Db,
    D::Tx: AuthnTx,
{
    let mut tx = db.begin().await.unwrap();

    let user = User::new(Username::from("foo"), EmailAddress::from("a@example.com"));

    match tx.set_user_activation_code(user, Some(1)).await.unwrap_err() {
        DbError::NotFound => (),
        e => panic!("{}", e),
    }

    match tx.get_user_by_username(Username::from("foo")).await.unwrap_err() {
        DbError::NotFound => (),
        e => panic!("{}", e),
    }
}

pub(crate) async fn test_sessions_ok<D>(db: D)
where
    D: Db,
    D::Tx: AuthnTx,
{
    let mut tx = db.begin().await.unwrap();

    create_simple_user(&mut tx, "testuser1").await;
    let session1 = Session::new(
        AccessToken::generate(),
        Username::from("testuser1"),
        utc_datetime(2022, 5, 17, 6, 29, 28),
    );
    tx.put_session(&session1).await.unwrap();

    create_simple_user(&mut tx, "testuser2").await;
    let session2 = Session::new(
        AccessToken::generate(),
        Username::from("testuser1"),
        utc_datetime(2022, 5, 17, 6, 29, 28),
    );
    tx.put_session(&session2).await.unwrap();

    assert_eq!(session1, tx.get_session(session1.access_token()).await.unwrap());
    assert_eq!(session2, tx.get_session(session2.access_token()).await.unwrap());

    // Mark one of the sessions as deleted.
    let access_token1 = session1.access_token().clone();
    tx.delete_session(session1, utc_datetime(2022, 5, 26, 8, 38, 10)).await.unwrap();
    match tx.get_session(&access_token1).await {
        Err(DbError::NotFound) => (),
        e => panic!("{:?}", e),
    }

    // Make sure the other session was unaffected.
    assert_eq!(session2, tx.get_session(session2.access_token()).await.unwrap());
}

pub(crate) async fn test_sessions_missing<D>(db: D)
where
    D: Db,
    D::Tx: AuthnTx,
{
    let mut tx = db.begin().await.unwrap();

    create_simple_user(&mut tx, "testuser1").await;
    let session = Session::new(
        AccessToken::generate(),
        Username::from("testuser1"),
        utc_datetime(2022, 5, 17, 6, 29, 28),
    );
    tx.put_session(&session).await.unwrap();

    match tx.get_session(&AccessToken::generate()).await {
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
            test_users_abort_creation_and_not_found,
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

pub(crate) use generate_db_tests;
