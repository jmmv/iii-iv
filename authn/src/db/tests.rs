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
use crate::model::{
    AccessToken, ActivationState, Coupon, Session, User, coupon_name, hashed_password,
};
use iii_iv_core::db::{Db, DbError, Executor};
use iii_iv_core::model::{EmailAddress, Username, email_address, username};
use std::sync::Arc;
use std::time::Duration;
use time::macros::datetime;
use uuid::Uuid;

/// Syntactic sugar to create a user with default settings given only its username.
async fn create_simple_user(ex: &mut Executor, username: &'static str) -> User {
    create_user(
        ex,
        Some(username!(username)),
        None,
        EmailAddress::new(format!("{}@example.com", username)).unwrap(),
        None,
    )
    .await
    .unwrap()
}

async fn test_coupons_ok(ex: &mut Executor) {
    let coupon = Coupon::new(
        coupon_name!("BETA100"),
        datetime!(2026-01-01 0:00 UTC),
        datetime!(2026-02-01 0:00 UTC),
        100,
    )
    .unwrap();
    create_coupon(ex, &coupon).await.unwrap();
    assert_eq!(coupon, get_coupon(ex, &coupon_name!("BETA100")).await.unwrap());

    assert_eq!(DbError::AlreadyExists, create_coupon(ex, &coupon).await.unwrap_err());
    assert_eq!(DbError::NotFound, get_coupon(ex, &coupon_name!("UNKNOWN")).await.unwrap_err());
}

async fn test_coupon_redemption(ex: &mut Executor) {
    let valid_from = datetime!(2026-01-01 0:00 UTC);
    let valid_until = datetime!(2026-02-01 0:00 UTC);
    let coupon = Coupon::new(coupon_name!("LIMITED"), valid_from, valid_until, 2).unwrap();
    create_coupon(ex, &coupon).await.unwrap();

    redeem_coupon(ex, &coupon.name).await.unwrap();
    redeem_coupon(ex, &coupon.name).await.unwrap();
    assert_eq!(2, get_coupon(ex, &coupon.name).await.unwrap().usages);
    assert_eq!(DbError::NotFound, redeem_coupon(ex, &coupon.name).await.unwrap_err());
    assert_eq!(DbError::NotFound, redeem_coupon(ex, &coupon_name!("UNKNOWN")).await.unwrap_err());
}

async fn test_put_user_ok(ex: &mut Executor) {
    let user = User::new(
        Uuid::parse_str("3f6333ef-443c-4528-88b7-d369675a2884").unwrap(),
        Some(username!("fixture-user")),
        email_address!("fixture@example.com"),
    )
    .with_last_login(datetime!(2026-05-10 11:12:13.456 UTC))
    .with_password(hashed_password!("fixture-hash"));

    put_user(ex, &user).await.unwrap();

    assert_eq!(user, get_user_by_id(ex, user.id).await.unwrap());
}

async fn test_user_with_coupon(ex: &mut Executor) {
    let coupon = Coupon::new(
        coupon_name!("ATTRIBUTED"),
        datetime!(2026-01-01 0:00 UTC),
        datetime!(2026-02-01 0:00 UTC),
        1,
    )
    .unwrap();
    create_coupon(ex, &coupon).await.unwrap();
    redeem_coupon(ex, &coupon.name).await.unwrap();

    let user = create_user(
        ex,
        Some(username!("coupon-user")),
        None,
        email_address!("coupon@example.com"),
        Some(coupon.name.clone()),
    )
    .await
    .unwrap();
    assert_eq!(Some(&coupon.name), user.coupon.as_ref());
    assert_eq!(user, get_user_by_id(ex, user.id).await.unwrap());

    delete_user(ex, user.id).await.unwrap();
    assert_eq!(1, get_coupon(ex, &coupon.name).await.unwrap().usages);
}

async fn test_users_ok(ex: &mut Executor) {
    let user = create_user(
        ex,
        Some(username!("some-username")),
        Some(hashed_password!("some-hash")),
        email_address!("a@example.com"),
        None,
    )
    .await
    .unwrap();

    let exp_user =
        User::new(user.id, Some(username!("some-username")), email_address!("a@example.com"))
            .with_password(hashed_password!("some-hash"));
    assert_eq!(exp_user, user);

    let user1 = get_user_by_username(ex, username!("some-username")).await.unwrap();
    assert_eq!(user, user1);
}

async fn test_users_not_found(ex: &mut Executor) {
    assert_eq!(
        DbError::NotFound,
        get_user_by_username(ex, username!("some-username")).await.unwrap_err()
    );
}

async fn test_user_without_username(ex: &mut Executor) {
    let email = email_address!("email-only@example.com");
    let user = create_user(ex, None, None, email.clone(), None).await.unwrap();

    assert!(user.username.is_none());
    assert_eq!(user, get_user_by_email(ex, email).await.unwrap());
    assert_eq!(user, get_user_by_id(ex, user.id).await.unwrap());
}

async fn test_user_corrupted_name(ex: &mut Executor) {
    let invalid = Username::new_invalid("this@is!invalid");
    create_user(ex, Some(invalid.clone()), None, email_address!("a@example.com"), None)
        .await
        .unwrap();
    match get_user_by_username(ex, invalid).await.unwrap_err() {
        DbError::DataIntegrityError(msg) if msg.contains("Unsupported character") => (),
        e => panic!("Unexpected error: {:?}", e),
    }
}

async fn test_user_corrupted_email(ex: &mut Executor) {
    let invalid = EmailAddress::new_invalid("this_is_invalid");
    create_user(ex, Some(username!("a")), None, invalid, None).await.unwrap();
    match get_user_by_username(ex, username!("a")).await.unwrap_err() {
        DbError::DataIntegrityError(msg) if msg.contains("valid address") => (),
        e => panic!("Unexpected error: {:?}", e),
    }
}

async fn test_users_delete_ok(ex: &mut Executor) {
    let user1 = create_simple_user(ex, "some-username-1").await;
    let user2 = create_simple_user(ex, "some-username-2").await;

    delete_user(ex, user1.id).await.unwrap();

    assert_eq!(DbError::NotFound, get_user_by_id(ex, user1.id).await.unwrap_err());
    assert_eq!(user2, get_user_by_id(ex, user2.id).await.unwrap());
}

async fn test_users_delete_not_found(ex: &mut Executor) {
    assert_eq!(DbError::NotFound, delete_user(ex, Uuid::new_v4()).await.unwrap_err());
}

async fn test_users_update_ok(ex: &mut Executor) {
    let user = create_user(
        ex,
        Some(username!("some-username")),
        Some(hashed_password!("some-hash")),
        email_address!("a@example.com"),
        None,
    )
    .await
    .unwrap();
    update_user(ex, user.id, datetime!(2022-04-02 05:50:10 UTC)).await.unwrap();

    let exp_user =
        User::new(user.id, Some(username!("some-username")), email_address!("a@example.com"))
            .with_password(hashed_password!("some-hash"))
            .with_last_login(datetime!(2022-04-02 05:50:10 UTC));
    assert_eq!(exp_user, get_user_by_username(ex, username!("some-username")).await.unwrap());
}

async fn test_users_update_not_found(ex: &mut Executor) {
    match update_user(ex, Uuid::new_v4(), datetime!(2022-04-02 06:32:00 UTC)).await.unwrap_err() {
        DbError::NotFound => (),
        e => panic!("{}", e),
    }

    match get_user_by_username(ex, username!("foo")).await.unwrap_err() {
        DbError::NotFound => (),
        e => panic!("{}", e),
    }
}

async fn test_set_user_activation_ok(ex: &mut Executor) {
    let mut user = create_user(
        ex,
        Some(username!("some-username")),
        Some(hashed_password!("some-hash")),
        email_address!("a@example.com"),
        None,
    )
    .await
    .unwrap();
    assert!(user.is_active);

    user = set_user_activation(
        ex,
        user,
        Some(ActivationState::new(
            123456,
            datetime!(2023-12-01 05:50:00 UTC),
            Duration::from_secs(86400),
        )),
    )
    .await
    .unwrap();
    assert!(!user.is_active);

    let read_user = get_user_by_id(ex, user.id).await.unwrap();
    assert!(!read_user.is_active);

    user = set_user_activation(ex, user, None).await.unwrap();
    assert!(user.is_active);

    let read_user = get_user_by_id(ex, user.id).await.unwrap();
    assert!(read_user.is_active);
}

async fn test_activation_expiry(ex: &mut Executor) {
    let user = create_simple_user(ex, "expiry").await;
    let id = user.id;
    let issued = datetime!(2026-01-01 0:00:00.123456 UTC);
    let age = Duration::from_secs(10);
    let activation = ActivationState::new(u64::MAX, issued, age);
    let expires = activation.expires_at;
    let user = set_user_activation(ex, user, Some(activation)).await.unwrap();
    assert_eq!(
        Some(ActivationState::new(u64::MAX, issued, age)),
        get_user_activation(ex, id).await.unwrap()
    );

    assert!(!consume_user_activation(ex, id, 1, issued).await.unwrap());
    assert!(!consume_user_activation(ex, id, u64::MAX, expires).await.unwrap());
    assert!(
        !consume_user_activation(ex, id, u64::MAX, expires + Duration::from_secs(1)).await.unwrap()
    );
    assert!(!get_user_by_id(ex, id).await.unwrap().is_active);
    assert!(
        consume_user_activation(ex, id, u64::MAX, expires - Duration::from_nanos(1000))
            .await
            .unwrap()
    );
    assert!(!consume_user_activation(ex, id, u64::MAX, issued).await.unwrap());
    assert!(get_user_by_id(ex, id).await.unwrap().is_active);

    set_user_activation(ex, user, Some(ActivationState::new(7, issued, Duration::ZERO)))
        .await
        .unwrap();
    assert!(!consume_user_activation(ex, id, 7, issued).await.unwrap());
    assert!(!consume_user_activation(ex, Uuid::new_v4(), 7, issued).await.unwrap());
}

async fn test_activation_consume_race(db: Arc<dyn Db + Send + Sync>) {
    let user = create_simple_user(&mut db.ex().await.unwrap(), "race").await;
    let id = user.id;
    let now = datetime!(2026-01-01 0:00 UTC);
    set_user_activation(
        &mut db.ex().await.unwrap(),
        user,
        Some(ActivationState::new(7, now, Duration::from_secs(10))),
    )
    .await
    .unwrap();

    let attempt = || async {
        let mut tx = db.begin().await.unwrap();
        let result = consume_user_activation(tx.ex(), id, 7, now).await.unwrap();
        tx.commit().await.unwrap();
        result
    };
    let (first, second) = tokio::join!(attempt(), attempt());
    assert_ne!(first, second);

    let user = get_user_by_id(&mut db.ex().await.unwrap(), id).await.unwrap();
    set_user_activation(
        &mut db.ex().await.unwrap(),
        user,
        Some(ActivationState::new(8, now, Duration::from_secs(10))),
    )
    .await
    .unwrap();
    {
        let mut tx = db.begin().await.unwrap();
        assert!(consume_user_activation(tx.ex(), id, 8, now).await.unwrap());
    }
    assert!(get_user_activation(&mut db.ex().await.unwrap(), id).await.unwrap().is_some());
}

async fn test_activation_rollback(db: Arc<dyn Db + Send + Sync>) {
    let user = create_simple_user(&mut db.ex().await.unwrap(), "activation").await;
    let id = user.id;
    {
        let mut tx = db.begin().await.unwrap();
        set_user_activation(
            tx.ex(),
            user,
            Some(ActivationState::new(
                7,
                datetime!(2023-12-01 05:50:00 UTC),
                Duration::from_secs(86400),
            )),
        )
        .await
        .unwrap();
        assert!(!get_user_by_id(tx.ex(), id).await.unwrap().is_active);
    }
    assert!(get_user_by_id(&mut db.ex().await.unwrap(), id).await.unwrap().is_active);
}

async fn test_set_user_activation_not_found(ex: &mut Executor) {
    let user = User::new(Uuid::new_v4(), Some(username!("foo")), email_address!("a@example.com"));

    match set_user_activation(
        ex,
        user,
        Some(ActivationState::new(
            1,
            datetime!(2023-12-01 05:50:00 UTC),
            Duration::from_secs(86400),
        )),
    )
    .await
    .unwrap_err()
    {
        DbError::NotFound => (),
        e => panic!("{}", e),
    }

    match get_user_by_username(ex, username!("foo")).await.unwrap_err() {
        DbError::NotFound => (),
        e => panic!("{}", e),
    }
}

async fn test_update_user_password_ok(ex: &mut Executor) {
    let user = create_user(
        ex,
        Some(username!("some-username")),
        Some(hashed_password!("original-hash")),
        email_address!("a@example.com"),
        None,
    )
    .await
    .unwrap();

    update_user_password(
        ex,
        user.id,
        &hashed_password!("original-hash"),
        hashed_password!("new-hash"),
    )
    .await
    .unwrap();

    let read_user = get_user_by_id(ex, user.id).await.unwrap();
    assert_eq!(Some(&hashed_password!("new-hash")), read_user.password.as_ref());
}

async fn test_update_user_password_not_found(ex: &mut Executor) {
    create_user(
        ex,
        Some(username!("some-username")),
        Some(hashed_password!("original-hash")),
        email_address!("a@example.com"),
        None,
    )
    .await
    .unwrap();

    match update_user_password(
        ex,
        Uuid::new_v4(),
        &hashed_password!("original-hash"),
        hashed_password!("new-hash"),
    )
    .await
    .unwrap_err()
    {
        DbError::NotFound => (),
        e => panic!("{}", e),
    }
}

async fn test_update_user_password_wrong_old_password(ex: &mut Executor) {
    let user = create_user(
        ex,
        Some(username!("some-username")),
        Some(hashed_password!("original-hash")),
        email_address!("a@example.com"),
        None,
    )
    .await
    .unwrap();

    match update_user_password(
        ex,
        user.id,
        &hashed_password!("wrong-old-hash"),
        hashed_password!("new-hash"),
    )
    .await
    .unwrap_err()
    {
        DbError::NotFound => (),
        e => panic!("{}", e),
    }

    let read_user = get_user_by_id(ex, user.id).await.unwrap();
    assert_eq!(Some(&hashed_password!("original-hash")), read_user.password.as_ref());
}

async fn test_delete_sessions_for_user_ok(ex: &mut Executor) {
    let user = create_simple_user(ex, "testuser1").await;
    let session1 = Session::new(
        AccessToken::generate(),
        user.id,
        datetime!(2022-05-17 06:29:28 UTC),
        datetime!(2022-05-17 07:29:28 UTC),
    );
    put_session(ex, &session1).await.unwrap();

    let session2 = Session::new(
        AccessToken::generate(),
        user.id,
        datetime!(2022-05-17 06:29:28 UTC),
        datetime!(2022-05-17 07:29:28 UTC),
    );
    put_session(ex, &session2).await.unwrap();

    assert_eq!(session1, get_session(ex, &session1.access_token).await.unwrap());
    assert_eq!(session2, get_session(ex, &session2.access_token).await.unwrap());

    delete_sessions_for_user(ex, user.id, datetime!(2022-05-26 08:38:10 UTC)).await.unwrap();

    match get_session(ex, &session1.access_token).await {
        Err(DbError::NotFound) => (),
        e => panic!("{:?}", e),
    }
    match get_session(ex, &session2.access_token).await {
        Err(DbError::NotFound) => (),
        e => panic!("{:?}", e),
    }
}

async fn test_sessions_ok(ex: &mut Executor) {
    let user1 = create_simple_user(ex, "testuser1").await;
    let session1 = Session::new(
        AccessToken::generate(),
        user1.id,
        datetime!(2022-05-17 06:29:28 UTC),
        datetime!(2022-05-17 07:29:28 UTC),
    );
    put_session(ex, &session1).await.unwrap();

    create_simple_user(ex, "testuser2").await;
    let session2 = Session::new(
        AccessToken::generate(),
        user1.id,
        datetime!(2022-05-17 06:29:28 UTC),
        datetime!(2022-05-17 07:29:28 UTC),
    );
    put_session(ex, &session2).await.unwrap();

    assert_eq!(session1, get_session(ex, &session1.access_token).await.unwrap());
    assert_eq!(session2, get_session(ex, &session2.access_token).await.unwrap());

    // Mark one of the sessions as deleted.
    let access_token1 = session1.access_token.clone();
    delete_session(ex, session1, datetime!(2022-05-26 08:38:10 UTC)).await.unwrap();
    match get_session(ex, &access_token1).await {
        Err(DbError::NotFound) => (),
        e => panic!("{:?}", e),
    }

    // Make sure the other session was unaffected.
    assert_eq!(session2, get_session(ex, &session2.access_token).await.unwrap());
}

async fn test_sessions_missing(ex: &mut Executor) {
    let user = create_simple_user(ex, "testuser1").await;
    let session = Session::new(
        AccessToken::generate(),
        user.id,
        datetime!(2022-05-17 06:29:28 UTC),
        datetime!(2022-05-17 07:29:28 UTC),
    );
    put_session(ex, &session).await.unwrap();

    match get_session(ex, &AccessToken::generate()).await {
        Err(DbError::NotFound) => (),
        e => panic!("{:?}", e),
    }
}

async fn test_login_failures_persistence(ex: &mut Executor) {
    let user = create_simple_user(ex, "backoff").await;
    let now = datetime!(2026-01-01 0:00:00.123456 UTC);

    assert_eq!(None, get_login_failures(ex, user.id).await.unwrap());

    let mut state = lock_login_failures(ex, user.id, now).await.unwrap();
    assert_eq!(0, state.count);
    for _ in 0..3 {
        state.count += 1;
        state.last_failure = now;
    }
    save_login_failures(ex, user.id, &state).await.unwrap();
    assert_eq!(Some(state), get_login_failures(ex, user.id).await.unwrap());

    clear_login_failures(ex, user.id).await.unwrap();
    assert_eq!(None, get_login_failures(ex, user.id).await.unwrap());
    lock_login_failures(ex, user.id, now).await.unwrap();

    delete_user(ex, user.id).await.unwrap();
    assert_eq!(None, get_login_failures(ex, user.id).await.unwrap());
}

async fn test_login_failures_rollback(db: Arc<dyn Db + Send + Sync>) {
    let user = create_simple_user(&mut db.ex().await.unwrap(), "backoff").await;
    let now = datetime!(2026-01-01 0:00 UTC);
    {
        let mut tx = db.begin().await.unwrap();
        let mut state = lock_login_failures(tx.ex(), user.id, now).await.unwrap();
        state.count = 3;
        save_login_failures(tx.ex(), user.id, &state).await.unwrap();
        clear_login_failures(tx.ex(), user.id).await.unwrap();
    }
    assert_eq!(None, get_login_failures(&mut db.ex().await.unwrap(), user.id).await.unwrap());
}

macro_rules! generate_db_tests [
    ( $setup:expr $(, #[$extra:meta] )? ) => {
        generate_tests!(
            $(#[$extra],)?
            $setup,
            $crate::db::tests,
            test_activation_expiry,
            test_login_failures_persistence,
            test_users_ok,
            test_users_not_found,
            test_coupons_ok,
            test_coupon_redemption,
            test_put_user_ok,
            test_user_with_coupon,
            test_user_without_username,
            test_user_corrupted_name,
            test_user_corrupted_email,
            test_users_delete_ok,
            test_users_delete_not_found,
            test_users_update_ok,
            test_users_update_not_found,
            test_set_user_activation_ok,
            test_set_user_activation_not_found,
            test_update_user_password_ok,
            test_update_user_password_not_found,
            test_update_user_password_wrong_old_password,
            test_delete_sessions_for_user_ok,
            test_sessions_ok,
            test_sessions_missing
        );
    }
];

mod postgres {
    use crate::db::init_schema;
    use iii_iv_core::db::Db;
    use iii_iv_core::db::postgres::PostgresDb;
    use iii_iv_core::db::testutils::generate_tests;
    use std::sync::Arc;

    async fn setup() -> PostgresDb {
        let db = iii_iv_core::db::postgres::testutils::setup().await;
        init_schema(&mut db.ex().await.unwrap()).await.unwrap();
        db
    }

    generate_tests!(
        #[ignore = "Requires environment configuration and is expensive"],
        { let db = Arc::from(setup().await); (db.clone(), db) },
        crate::db::tests,
        test_activation_consume_race,
        test_activation_rollback,
        test_login_failures_rollback
    );

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
    use iii_iv_core::db::testutils::generate_tests;
    use std::sync::Arc;

    async fn setup() -> SqliteDb {
        let db = iii_iv_core::db::sqlite::testutils::setup().await;
        init_schema(&mut db.ex().await.unwrap()).await.unwrap();
        db
    }

    generate_tests!(
        {
            let db = Arc::from(setup().await);
            (db.clone(), db)
        },
        crate::db::tests,
        test_activation_consume_race,
        test_activation_rollback,
        test_login_failures_rollback
    );

    generate_db_tests!({
        let db = Arc::from(setup().await);
        (db.clone(), &mut db.ex().await.unwrap())
    });
}
