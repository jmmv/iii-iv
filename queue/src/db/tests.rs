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
use crate::model::{RunnableTask, TaskResult};
use iii_iv_core::db::{DbError, Executor};
use serde::de::{self, Visitor};
use serde::ser::{self, SerializeStruct};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use time::OffsetDateTime;
use time::macros::datetime;
use uuid::Uuid;

/// A trivial task to validate (de)serialization behavior.
#[derive(Debug, Deserialize, Eq, PartialEq)]
struct MockTask {
    /// The "payload" for the task.
    ///
    /// In most cases, the value is irrelevant but can be used to validate that we are getting the
    /// specific task we expect from the database.
    ///
    /// The magic `TRIGGER_SER_ERROR` and `TRIGGER_DE_ERROR` values can be used to enqueue failures
    /// during JSON (de)serialization.
    #[serde(deserialize_with = "crate::db::tests::deserialize_i")]
    i: u32,
}

impl MockTask {
    /// Causes serialization to fail.
    const TRIGGER_SER_ERROR: u32 = 12345;

    /// Causes deserialization to fail.
    const TRIGGER_DE_ERROR: u32 = 54321;
}

impl Serialize for MockTask {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if self.i == Self::TRIGGER_SER_ERROR {
            return Err(ser::Error::custom("Custom ser error"));
        }

        let mut task = serializer.serialize_struct("MockTask", 1)?;
        task.serialize_field("i", &self.i)?;
        task.end()
    }
}

/// A visitor for the `i` field of `MockTask`.
struct IVisitor;

impl Visitor<'_> for IVisitor {
    type Value = u32;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str(r#"a u32 number"#)
    }

    fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let v = u32::try_from(v).expect("Value must have fit");
        if v == MockTask::TRIGGER_DE_ERROR {
            return Err(de::Error::custom("Custom de error"));
        }
        Ok(v)
    }
}

/// Deserializes the `i` field of `MockTask`, returning errors if requested.
fn deserialize_i<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserializer.deserialize_u32(IVisitor)
}

/// Helper function to enqueue a new task (one that has never run yet) with a data value `i`
/// into the database `db`.
async fn put_new_mock_task(
    ex: &mut Executor,
    i: u32,
    created: OffsetDateTime,
    only_after: Option<OffsetDateTime>,
) -> Uuid {
    let task = MockTask { i };

    put_new_task(ex, &task, created, only_after).await.unwrap()
}

/// Enqueues a task that is running or has finished running with a data value `i` into the
/// database.  `runs` indicates how many runs we expect to be recorded for the task, and the
/// optional `result` indicates whether the task has completed or not.
///
/// This is a helper to the `put_running_task` and `put_done_task` functions and should not be
/// invoked directly by tests.
async fn put_active_task(
    ex: &mut Executor,
    i: u32,
    result: Option<&TaskResult>,
    max_runtime: Duration,
    updated: OffsetDateTime,
    runs: u8,
) -> Uuid {
    assert!(runs > 0, "Running tasks must have at least one recorded run attempt");

    let task = MockTask { i };

    // Creation time should not matter in our queries, so set it to something far in the past.
    let created = datetime!(1984-01-01 0:00 UTC);

    let id = put_new_task(ex, &task, created, None).await.unwrap();

    set_task_running(ex, RunnableTask::new(id, Ok(task), runs - 1), max_runtime, updated)
        .await
        .unwrap();
    if let Some(result) = result {
        set_task_result(ex, id, result, updated).await.unwrap();
    }

    id
}

/// Helper function to enqueue a task that is running with a data value `i` into the database.
/// `runs` indicates how many runs we expect to be recorded for the task.
async fn put_running_task(
    ex: &mut Executor,
    i: u32,
    max_runtime: Duration,
    updated: OffsetDateTime,
    runs: u8,
) -> Uuid {
    put_active_task(ex, i, None, max_runtime, updated, runs).await
}

/// Helper function to enqueue a task that has finished running with a data value `i` into the
/// database.  `runs` indicates how many runs we expect to be recorded for the task, and `result`
/// indicates the outcome of the task.
async fn put_done_task(
    ex: &mut Executor,
    i: u32,
    result: &TaskResult,
    max_runtime: Duration,
    updated: OffsetDateTime,
    runs: u8,
) -> Uuid {
    put_active_task(ex, i, Some(result), max_runtime, updated, runs).await
}

async fn test_put_get_runnable_all_new(ex: &mut Executor) {
    let max_runtime = Duration::from_secs(60);
    let now = datetime!(2023-05-17 5:47 UTC);

    let id1 = put_new_mock_task(ex, 3, datetime!(2023-05-17 5:40 UTC), None).await;
    let id2 = put_new_mock_task(ex, 1, datetime!(2023-05-17 5:55 UTC), None).await;
    let id3 = put_new_mock_task(ex, 2, datetime!(2023-05-17 5:50 UTC), None).await;

    let runnable = get_runnable_tasks(ex, 10, max_runtime, now).await.unwrap();

    let exp_runnable = vec![
        RunnableTask::new(id1, Ok(MockTask { i: 3 }), 0),
        RunnableTask::new(id3, Ok(MockTask { i: 2 }), 0),
        RunnableTask::new(id2, Ok(MockTask { i: 1 }), 0),
    ];
    assert_eq!(exp_runnable, runnable);
}

async fn test_put_get_runnable_mix(ex: &mut Executor) {
    let max_runtime = Duration::from_secs(5 * 60);
    let now = datetime!(2023-05-18 17:10 UTC);

    // Put a task with 0 reruns that's outside the max_runtime window.
    // Must be considered as runnable.
    let id1 = put_new_mock_task(ex, 1, datetime!(2023-05-18 16:00 UTC), None).await;

    // Put a task with 0 reruns that's inside the max_runtime window.
    // Must be considered as runnable.
    let id2 = put_new_mock_task(ex, 2, datetime!(2023-05-18 17:08 UTC), None).await;

    // Put a task with multiple reruns that's outside of the max_runtime window.
    // Must be considered as runnable.
    let id3 = put_running_task(ex, 3, max_runtime, datetime!(2023-05-18 17:04 UTC), 4).await;

    // Put a task with multiple reruns that's inside of the max_runtime window.
    // Must NOT be considered as runnable yet.
    let _ = put_running_task(ex, 4, max_runtime, datetime!(2023-05-18 17:06 UTC), 5).await;

    for result in [
        TaskResult::Done(None),
        TaskResult::Failed("".to_owned()),
        TaskResult::Abandoned("".to_owned()),
    ] {
        // Put a few tasks that are done and that are outside of the max_runtime window.
        // Must NOT be considered as runnable anymore.
        put_done_task(ex, 5, &result, max_runtime, datetime!(2023-05-18 16:10 UTC), 2).await;

        // Put a few tasks that are done and that are inside of the max_runtime window.
        // Must NOT be considered as runnable anymore.
        put_done_task(ex, 6, &result, max_runtime, datetime!(2023-05-18 17:06 UTC), 2).await;
    }

    // Put a task that was deferred and is in the past.
    // Must be considered as runnable already.
    let id4 = put_done_task(
        ex,
        7,
        &TaskResult::Retry(now - Duration::from_secs(1), "".to_owned()),
        max_runtime,
        datetime!(2023-05-18 17:04 UTC),
        100,
    )
    .await;

    // Put a task that was deferred and is in the future.
    // Must NOT be considered as runnable yet.
    put_done_task(
        ex,
        8,
        &TaskResult::Retry(now + Duration::from_secs(1), "".to_owned()),
        max_runtime,
        datetime!(2023-05-18 17:04 UTC),
        100,
    )
    .await;

    let runnable = get_runnable_tasks(ex, 10, max_runtime, now).await.unwrap();

    let exp_runnable = vec![
        RunnableTask::new(id1, Ok(MockTask { i: 1 }), 0),
        RunnableTask::new(id3, Ok(MockTask { i: 3 }), 4),
        RunnableTask::new(id4, Ok(MockTask { i: 7 }), 100),
        RunnableTask::new(id2, Ok(MockTask { i: 2 }), 0),
    ];
    assert_eq!(exp_runnable, runnable);
}

async fn test_put_get_runnable_limit(ex: &mut Executor) {
    let max_runtime = Duration::from_secs(60);
    let now = datetime!(2023-05-19 8:00 UTC);

    for _ in 0..100 {
        let _id = put_new_mock_task(ex, 0, datetime!(2023-05-19 7:15 UTC), None).await;
    }

    let runnable = get_runnable_tasks::<MockTask>(ex, 10, max_runtime, now).await.unwrap();
    assert_eq!(10, runnable.len());
}

async fn test_put_get_runnable_only_after(ex: &mut Executor) {
    let max_runtime = Duration::from_secs(1);
    let now = datetime!(2023-06-11 6:27 UTC);
    let created = now - Duration::from_secs(3600);
    let delta = Duration::from_millis(1);

    let past = put_new_mock_task(ex, 2, created, Some(now - delta)).await;
    let present = put_new_mock_task(ex, 3, created, Some(now)).await;
    let future = put_new_mock_task(ex, 1, created, Some(now + delta)).await;

    let runnable = get_runnable_tasks(ex, 10, max_runtime, now).await.unwrap();

    let exp_runnable = vec![
        RunnableTask::new(past, Ok(MockTask { i: 2 }), 0),
        RunnableTask::new(present, Ok(MockTask { i: 3 }), 0),
    ];
    assert_eq!(exp_runnable, runnable);

    let runnable = get_runnable_tasks(ex, 10, max_runtime, now + delta).await.unwrap();

    let exp_runnable = vec![
        RunnableTask::new(past, Ok(MockTask { i: 2 }), 0),
        RunnableTask::new(present, Ok(MockTask { i: 3 }), 0),
        RunnableTask::new(future, Ok(MockTask { i: 1 }), 0),
    ];
    assert_eq!(exp_runnable, runnable);
}

async fn test_put_ser_error_aborts_put(ex: &mut Executor) {
    let now = datetime!(2023-05-19 8:30 UTC);

    let error = put_new_task(
        ex,
        &MockTask { i: MockTask::TRIGGER_SER_ERROR },
        now - Duration::from_secs(10),
        None,
    )
    .await
    .unwrap_err();
    assert!(format!("{}", error).contains("Custom ser error"));

    let runnable =
        get_runnable_tasks::<MockTask>(ex, 10, Duration::from_secs(1), now).await.unwrap();
    assert!(runnable.is_empty());
}

async fn test_set_task_running_fails_if_already_running(ex: &mut Executor) {
    let max_runtime = Duration::from_secs(5 * 60);
    let now = datetime!(2023-06-01 06:50 UTC);

    let id = put_running_task(ex, 0, max_runtime, now, 1).await;

    // Try to mark the task as running again before its `max_runtime` has elapsed, which must fail.
    match set_task_running(
        ex,
        RunnableTask::new(id, Ok(MockTask { i: 0 }), 0),
        max_runtime,
        now + max_runtime,
    )
    .await
    {
        Err(DbError::BackendError(e)) => assert!(e.contains("already running")),
        e => panic!("Expected not found error, but got: {:?}", e),
    }

    // Try to mark the task as running again after its `max_runtime` has elapsed, which must work.
    set_task_running(
        ex,
        RunnableTask::new(id, Ok(MockTask { i: 0 }), 0),
        max_runtime,
        now + max_runtime + Duration::from_millis(1),
    )
    .await
    .unwrap();
}

async fn test_set_task_running_fails_if_already_completed(ex: &mut Executor) {
    let max_runtime = Duration::from_secs(5 * 60);
    let now = datetime!(2023-06-01 06:50 UTC);

    for result in [
        TaskResult::Done(None),
        TaskResult::Failed("foo".to_owned()),
        TaskResult::Abandoned("bar".to_owned()),
    ] {
        let id = put_done_task(ex, 0, &result, max_runtime, now, 1).await;

        // Try to mark the task as running after it has already completed, which must fail.
        match set_task_running(
            ex,
            RunnableTask::new(id, Ok(MockTask { i: 0 }), 0),
            max_runtime,
            now + max_runtime * 2,
        )
        .await
        {
            Err(DbError::BackendError(e)) => assert!(e.contains("already running/done")),
            e => panic!("Expected not found error, but got: {:?}", e),
        }
    }
}

async fn test_get_runnable_propagates_de_error(ex: &mut Executor) {
    let max_runtime = Duration::from_secs(60);
    let now = datetime!(2023-05-17 5:47 UTC);

    let id =
        put_new_mock_task(ex, MockTask::TRIGGER_DE_ERROR, datetime!(2023-05-17 5:40 UTC), None)
            .await;

    let mut runnable = get_runnable_tasks::<MockTask>(ex, 10, max_runtime, now).await.unwrap();

    let task = runnable.pop().expect("Must have found exactly one task");
    assert!(runnable.is_empty(), "Must have found exactly one task");

    assert_eq!(id, task.id());
    let task = task.try_run(); // Needed to access the underlying JSON result.
    let error = task.into_json_task().unwrap_err();
    assert!(format!("{}", error).contains("Custom de error"));
}

async fn test_get_result_new(ex: &mut Executor) {
    let id = put_new_mock_task(ex, 0, datetime!(2023-05-26 14:35 UTC), None).await;

    let result = get_result(ex, id).await.unwrap();

    assert_eq!(None, result);
}

async fn test_get_result_still_running(ex: &mut Executor) {
    let max_runtime = Duration::from_millis(10);
    let id = put_running_task(ex, 0, max_runtime, datetime!(2023-05-26 14:35 UTC), 10).await;

    let result = get_result(ex, id).await.unwrap();

    assert_eq!(None, result);
}

async fn test_get_result_done(ex: &mut Executor) {
    let max_runtime = Duration::from_millis(10);
    for exp_result in [
        TaskResult::Done(None),
        TaskResult::Failed("foo".to_owned()),
        TaskResult::Abandoned("bar".to_owned()),
    ] {
        let id =
            put_done_task(ex, 0, &exp_result, max_runtime, datetime!(2023-05-26 14:35 UTC), 10)
                .await;

        let result = get_result(ex, id).await.unwrap();

        assert_eq!(Some(exp_result), result);
    }
}

async fn test_get_results_since(ex: &mut Executor) {
    let since = datetime!(2023-05-19 7:30 UTC);
    let before = since - Duration::from_secs(30);
    let after = since + Duration::from_secs(30);
    let max_runtime = Duration::from_millis(10);

    put_new_mock_task(ex, 1, before, None).await;
    put_new_mock_task(ex, 2, after, None).await;

    put_running_task(ex, 3, max_runtime, before, 4).await;
    put_running_task(ex, 4, max_runtime, after, 5).await;

    let mut exp_results = vec![];
    for (i, result) in [
        TaskResult::Done(None),
        TaskResult::Failed("".to_owned()),
        TaskResult::Abandoned("".to_owned()),
    ]
    .iter()
    .enumerate()
    {
        // The results of the query are sorted by timestamp, so make sure they are stable by using
        // different values for each task.
        //
        // It is important for `i` to start at 0 to assert the behavior of a task that completes at
        // exactly `since` time.
        let before = before + Duration::from_secs(i as u64);
        let after = after + Duration::from_secs(i as u64);

        put_done_task(ex, 0, result, max_runtime, before, 10).await;

        let id = put_done_task(ex, 0, result, max_runtime, after, 10).await;
        exp_results.push((id, result.clone()));
    }

    let results = get_results_since(ex, since).await.unwrap();

    assert_eq!(exp_results, results);
}

macro_rules! generate_db_tests [
    ( $setup:expr $(, #[$extra:meta] )? ) => {
        iii_iv_core::db::testutils::generate_tests!(
            $(#[$extra],)?
            $setup,
            $crate::db::tests,
            test_put_get_runnable_all_new,
            test_put_get_runnable_mix,
            test_put_get_runnable_limit,
            test_put_get_runnable_only_after,
            test_put_ser_error_aborts_put,
            test_set_task_running_fails_if_already_running,
            test_set_task_running_fails_if_already_completed,
            test_get_runnable_propagates_de_error,
            test_get_result_new,
            test_get_result_still_running,
            test_get_result_done,
            test_get_results_since
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
