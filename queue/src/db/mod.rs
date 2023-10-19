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

//! Database abstractions to manipulate queue tasks.

use crate::db::status::{result_to_status, status_to_result, TaskStatus};
use crate::model::{RunnableTask, RunningTask, TaskResult};
use futures::TryStreamExt;
#[cfg(feature = "postgres")]
use iii_iv_core::db::postgres;
#[cfg(any(feature = "sqlite", test))]
use iii_iv_core::db::sqlite;
use iii_iv_core::db::{DbError, DbResult, Executor};
use serde::de::DeserializeOwned;
use serde::Serialize;
use sqlx::Row;
use std::time::Duration;
use time::OffsetDateTime;
use uuid::Uuid;

mod status;

#[cfg(test)]
mod tests;

/// Converts an unpacked `OffsetDateTime` expressed as `sec`/`nsec` into milliseconds.
///
/// This ensures that the given quantities do not require sub-millisecond precision because
/// our queries do not support that.
///
/// The `field` name is only used for error-logging purposes.
#[cfg(any(feature = "sqlite", test))]
fn as_msec(field: &str, sec: i64, nsec: i64) -> DbResult<i64> {
    if nsec % 1000000 != 0 {
        return Err(DbError::BackendError(format!(
            "Cannot handle sub-millisecond precision in '{}': sec={}, nsec={}",
            field, sec, nsec
        )));
    }
    Ok(sec * 1000 + nsec / 1000000)
}

/// Validates that an `UPDATE` statement for a task `id` only touched 1 row.
fn ensure_one_update(id: Uuid, affected: u64) -> DbResult<()> {
    match affected {
        0 => Err(DbError::BackendError(format!("Task {} not found or already running/done", id))),
        1 => Ok(()),
        _ => Err(DbError::BackendError(format!("Update of {} affected {} rows", id, affected))),
    }
}

/// Initializes the database schema.
pub async fn init_schema(ex: &mut Executor) -> DbResult<()> {
    match ex {
        Executor::Postgres(ref mut ex) => {
            postgres::run_schema(ex, include_str!("postgres.sql")).await
        }

        #[cfg(any(feature = "sqlite", test))]
        Executor::Sqlite(ref mut ex) => sqlite::run_schema(ex, include_str!("sqlite.sql")).await,

        #[allow(unused)]
        _ => unreachable!(),
    }
}

/// Stores a new task with a serialized `task` descriptor, marks it as runnable, and
/// tracks that it was enqueue at the `created` timestamp.  The task is postponed until
/// `only_after` if specified.  Returns the ID of the created task.
pub(crate) async fn put_new_task<T>(
    ex: &mut Executor,
    task: &T,
    created: OffsetDateTime,
    only_after: Option<OffsetDateTime>,
) -> DbResult<Uuid>
where
    T: Serialize,
{
    let id = Uuid::new_v4();

    let json_task = match serde_json::to_string(task) {
        Ok(json) => json,
        Err(e) => {
            return Err(DbError::BackendError(format!("Cannot serialize task for storage: {}", e)))
        }
    };

    let rows_affected = match ex {
        #[cfg(feature = "postgres")]
        Executor::Postgres(ref mut ex) => {
            let query_str = "
                INSERT INTO tasks
                    (id, json, status_code, status_reason, runs, created, updated, only_after)
                VALUES
                    ($1, $2,   $3,          NULL,          0,    $4,      $4,      $5)
            ";
            sqlx::query(query_str)
                .bind(id)
                .bind(&json_task)
                .bind(TaskStatus::Runnable as i16)
                .bind(created)
                .bind(only_after)
                .execute(ex)
                .await
                .map_err(postgres::map_sqlx_error)?
                .rows_affected()
        }

        #[cfg(any(feature = "sqlite", test))]
        Executor::Sqlite(ref mut ex) => {
            let (created_sec, created_nsec) = sqlite::unpack_timestamp(created);
            let only_after = only_after.map(sqlite::unpack_timestamp);

            let query_str = "
                INSERT INTO tasks
                    (id, json, status_code, status_reason, runs,
                    created_sec, created_nsec, updated_sec, updated_nsec,
                    only_after_sec, only_after_nsec)
                VALUES (?, ?, ?, NULL, 0, ?, ?, ?, ?, ?, ?)
            ";
            sqlx::query(query_str)
                .bind(id)
                .bind(&json_task)
                .bind(TaskStatus::Runnable as i8)
                .bind(created_sec)
                .bind(created_nsec)
                .bind(created_sec) // updated_sec
                .bind(created_nsec) // updated_nsec
                .bind(only_after.map(|(sec, _nsec)| sec))
                .bind(only_after.map(|(_sec, nsec)| nsec))
                .execute(ex)
                .await
                .map_err(sqlite::map_sqlx_error)?
                .rows_affected()
        }

        #[allow(unused)]
        _ => unreachable!(),
    };
    if rows_affected != 1 {
        return Err(DbError::BackendError(format!("Insert created {} rows", rows_affected)));
    }
    Ok(id)
}

/// Fetches the result of task `id` if it has completed, or `None` otherwise.
pub(crate) async fn get_result(ex: &mut Executor, id: Uuid) -> DbResult<Option<TaskResult>> {
    match ex {
        #[cfg(feature = "postgres")]
        Executor::Postgres(ref mut ex) => {
            let query_str = "
                SELECT status_code, status_reason, runs, only_after
                FROM tasks
                WHERE id = $1 AND (
                    status_code != $2
                    OR (
                        status_code = $2 AND status_reason IS NOT NULL
                        AND runs > 0 AND only_after IS NOT NULL
                    )
                )
            ";
            match sqlx::query(query_str)
                .bind(id)
                .bind(TaskStatus::Runnable as i16)
                .fetch_optional(ex)
                .await
                .map_err(postgres::map_sqlx_error)?
            {
                Some(row) => {
                    let code: i16 = row.try_get("status_code").map_err(postgres::map_sqlx_error)?;
                    let reason: Option<String> =
                        row.try_get("status_reason").map_err(postgres::map_sqlx_error)?;
                    let runs: i16 = row.try_get("runs").map_err(postgres::map_sqlx_error)?;
                    let only_after: Option<OffsetDateTime> =
                        row.try_get("only_after").map_err(postgres::map_sqlx_error)?;

                    let code = match i8::try_from(code) {
                        Ok(code) => code,
                        Err(e) => {
                            return Err(DbError::DataIntegrityError(format!(
                                "Invalid status_code {}: {}",
                                code, e
                            )))
                        }
                    };

                    let result = status_to_result(id, code, reason, runs, only_after)?
                        .expect("Must not have queried runnable tasks");
                    Ok(Some(result))
                }
                None => Ok(None),
            }
        }

        #[cfg(any(feature = "sqlite", test))]
        Executor::Sqlite(ref mut ex) => {
            let query_str = "
                SELECT status_code, status_reason, runs, only_after_sec, only_after_nsec
                FROM tasks
                WHERE id = ? AND (
                    status_code != ?
                    OR (
                        status_code = ? AND status_reason IS NOT NULL
                        AND runs > 0 AND only_after_sec IS NOT NULL
                    )
                )
            ";
            match sqlx::query(query_str)
                .bind(id)
                .bind(TaskStatus::Runnable as i8)
                .bind(TaskStatus::Runnable as i8)
                .fetch_optional(ex)
                .await
                .map_err(sqlite::map_sqlx_error)?
            {
                Some(row) => {
                    let code: i8 = row.try_get("status_code").map_err(sqlite::map_sqlx_error)?;
                    let reason: Option<String> =
                        row.try_get("status_reason").map_err(sqlite::map_sqlx_error)?;
                    let runs: i16 = row.try_get("runs").map_err(postgres::map_sqlx_error)?;
                    let only_after_sec: Option<i64> =
                        row.try_get("only_after_sec").map_err(sqlite::map_sqlx_error)?;
                    let only_after_nsec: Option<i64> =
                        row.try_get("only_after_nsec").map_err(sqlite::map_sqlx_error)?;

                    let only_after = match (only_after_sec, only_after_nsec) {
                        (Some(sec), Some(nsec)) => Some(sqlite::build_timestamp(sec, nsec)?),
                        (None, None) => None,
                        (_, _) => {
                            return Err(DbError::DataIntegrityError(format!(
                                "Inconsistent only_after sec ({:?}) and nsec ({:?}) values",
                                only_after_sec, only_after_nsec
                            )));
                        }
                    };

                    let result = status_to_result(id, code, reason, runs, only_after)?
                        .expect("Must not have queried runnable tasks");
                    Ok(Some(result))
                }
                None => Ok(None),
            }
        }

        #[allow(unused)]
        _ => unreachable!(),
    }
}

/// Fetches all completed task results since the specified time, ordered by oldest completed
/// task first.
pub(crate) async fn get_results_since(
    ex: &mut Executor,
    since: OffsetDateTime,
) -> DbResult<Vec<(Uuid, TaskResult)>> {
    let mut results = vec![];

    match ex {
        #[cfg(feature = "postgres")]
        Executor::Postgres(ref mut ex) => {
            let query_str = "
                SELECT id, status_code, status_reason, runs, only_after
                FROM tasks
                WHERE (
                    status_code != $1
                    OR (status_code = $1 AND runs > 0 AND only_after IS NOT NULL)
                ) AND updated >= $2
                ORDER BY updated ASC
            ";
            let mut rows =
                sqlx::query(query_str).bind(TaskStatus::Runnable as i16).bind(since).fetch(ex);

            while let Some(row) = rows.try_next().await.map_err(postgres::map_sqlx_error)? {
                let id: Uuid = row.try_get("id").map_err(postgres::map_sqlx_error)?;
                let code: i16 = row.try_get("status_code").map_err(postgres::map_sqlx_error)?;
                let reason: Option<String> =
                    row.try_get("status_reason").map_err(postgres::map_sqlx_error)?;
                let runs: i16 = row.try_get("runs").map_err(postgres::map_sqlx_error)?;
                let only_after: Option<OffsetDateTime> =
                    row.try_get("only_after").map_err(postgres::map_sqlx_error)?;

                let code = match i8::try_from(code) {
                    Ok(code) => code,
                    Err(e) => {
                        return Err(DbError::DataIntegrityError(format!(
                            "Invalid status_code {}: {}",
                            code, e
                        )))
                    }
                };

                let result = status_to_result(id, code, reason, runs, only_after)?
                    .expect("Must not have queried runnable tasks");
                results.push((id, result));
            }
        }

        #[cfg(any(feature = "sqlite", test))]
        Executor::Sqlite(ref mut ex) => {
            let (since_sec, since_nsec) = sqlite::unpack_timestamp(since);

            let query_str = "
                SELECT id, status_code, status_reason, runs, only_after_sec, only_after_nsec
                FROM tasks
                WHERE (
                    status_code != ?
                    OR (status_code = ? AND runs > 0 AND only_after_sec IS NOT NULL)
                ) AND (updated_sec >= ? OR (updated_sec = ? AND updated_nsec >= ?))
                ORDER BY updated_sec ASC, updated_nsec ASC
            ";
            let mut rows = sqlx::query(query_str)
                .bind(TaskStatus::Runnable as i8)
                .bind(TaskStatus::Runnable as i8)
                .bind(since_sec)
                .bind(since_sec)
                .bind(since_nsec)
                .fetch(ex);

            while let Some(row) = rows.try_next().await.map_err(sqlite::map_sqlx_error)? {
                let id: Uuid = row.try_get("id").map_err(sqlite::map_sqlx_error)?;
                let code: i8 = row.try_get("status_code").map_err(sqlite::map_sqlx_error)?;
                let reason: Option<String> =
                    row.try_get("status_reason").map_err(sqlite::map_sqlx_error)?;
                let runs: i16 = row.try_get("runs").map_err(postgres::map_sqlx_error)?;
                let only_after_sec: Option<i64> =
                    row.try_get("only_after_sec").map_err(sqlite::map_sqlx_error)?;
                let only_after_nsec: Option<i64> =
                    row.try_get("only_after_nsec").map_err(sqlite::map_sqlx_error)?;

                let only_after = match (only_after_sec, only_after_nsec) {
                    (Some(sec), Some(nsec)) => Some(sqlite::build_timestamp(sec, nsec)?),
                    (None, None) => None,
                    (_, _) => {
                        return Err(DbError::DataIntegrityError(format!(
                            "Inconsistent only_after sec ({:?}) and msec ({:?}) values",
                            only_after_sec, only_after_nsec
                        )));
                    }
                };

                let result = status_to_result(id, code, reason, runs, only_after)?
                    .expect("Must not have queried runnable tasks");
                results.push((id, result));
            }
        }

        #[allow(unused)]
        _ => unreachable!(),
    }

    Ok(results)
}

/// Gets the oldest (by last created/updated time) `limit` tasks that can be processed.
///
/// This includes idle tasks (those that never started) and lost tasks (those that already
/// attempted to run but for which we have no completion report at time `now` after
/// `max_runtime` since the task reported a status).
// TODO(jmmv): This should probably not be public but some tests need it. Maybe it should
// be part of the driver.
pub async fn get_runnable_tasks<T>(
    ex: &mut Executor,
    limit: u16,
    max_runtime: Duration,
    now: OffsetDateTime,
) -> DbResult<Vec<RunnableTask<T>>>
where
    T: DeserializeOwned + Send + Sync,
{
    let mut tasks = vec![];

    /// Creates a `RunnableTask` from the given raw fields from the database.
    fn make_runnable_task<T>(id: Uuid, json: &str, runs: i16) -> DbResult<RunnableTask<T>>
    where
        T: DeserializeOwned + Send + Sync,
    {
        let task = serde_json::from_str::<T>(json);
        let runs = match u8::try_from(runs) {
            Ok(runs) => runs,
            Err(e) => {
                return Err(DbError::DataIntegrityError(format!("Invalid runs {}: {}", runs, e)))
            }
        };

        Ok(RunnableTask::new(id, task, runs))
    }

    match ex {
        #[cfg(feature = "postgres")]
        Executor::Postgres(ref mut ex) => {
            let query_str = "
                SELECT id, json, runs
                FROM tasks
                WHERE
                    status_code = $1
                    AND (runs = 0 OR updated + $2 < $3)
                    AND (only_after IS NULL OR $3 >= only_after)
                ORDER BY updated ASC
                LIMIT $4
            ";
            let mut rows = sqlx::query(query_str)
                .bind(TaskStatus::Runnable as i16)
                .bind(max_runtime)
                .bind(now)
                .bind(i32::from(limit))
                .fetch(ex);

            while let Some(row) = rows.try_next().await.map_err(postgres::map_sqlx_error)? {
                let id: Uuid = row.try_get("id").map_err(postgres::map_sqlx_error)?;
                let json: String = row.try_get("json").map_err(postgres::map_sqlx_error)?;
                let runs: i16 = row.try_get("runs").map_err(postgres::map_sqlx_error)?;
                tasks.push(make_runnable_task(id, &json, runs)?);
            }
        }

        #[cfg(any(feature = "sqlite", test))]
        Executor::Sqlite(ref mut ex) => {
            let max_runtime_msec = {
                let (max_runtime_sec, max_runtime_nsec) = sqlite::unpack_duration(max_runtime);
                as_msec("max_runtime", max_runtime_sec, max_runtime_nsec)?
            };

            let now_msec = {
                let (now_sec, now_nsec) = sqlite::unpack_timestamp(now);
                as_msec("now", now_sec, now_nsec)?
            };

            let query_str = "
                SELECT
                    id, json, runs,
                    updated_sec * 1000 + updated_nsec / 1000000 AS updated_msec,
                    only_after_sec * 1000 + only_after_nsec / 1000000 AS only_after_msec
                FROM tasks
                WHERE
                    status_code = ?
                    AND (runs = 0 OR updated_msec + ? < ?)
                    AND (only_after_sec IS NULL OR ? >= only_after_msec)
                ORDER BY updated_sec ASC, updated_nsec ASC
                LIMIT ?
            ";
            let mut rows = sqlx::query(query_str)
                .bind(TaskStatus::Runnable as i8)
                .bind(max_runtime_msec)
                .bind(now_msec)
                .bind(now_msec)
                .bind(i32::from(limit))
                .fetch(ex);

            while let Some(row) = rows.try_next().await.map_err(sqlite::map_sqlx_error)? {
                let id: Uuid = row.try_get("id").map_err(sqlite::map_sqlx_error)?;
                let json: String = row.try_get("json").map_err(sqlite::map_sqlx_error)?;
                let runs: i16 = row.try_get("runs").map_err(sqlite::map_sqlx_error)?;
                tasks.push(make_runnable_task(id, &json, runs)?);
            }
        }

        #[allow(unused)]
        _ => unreachable!(),
    }

    Ok(tasks)
}

/// Marks the already-stored `task` as running and returns a handle to run the task.
///
/// The task's `updated` timestamp must represent the current time, as this will be later
/// used to identify lost tasks.
///
/// Note that the task must be considered runnable, either by being new or by having
/// exceeded its `max_runtime`.  This is to prevent executing the same task more than once
/// concurrently.
pub(crate) async fn set_task_running<T>(
    ex: &mut Executor,
    task: RunnableTask<T>,
    max_runtime: Duration,
    updated: OffsetDateTime,
) -> DbResult<RunningTask<T>>
where
    T: Send + Sync,
{
    let task = task.try_run();

    let rows_affected = match ex {
        #[cfg(feature = "postgres")]
        Executor::Postgres(ref mut ex) => {
            let query_str = "
                UPDATE tasks
                SET status_code = $1, updated = $2, runs = $3
                WHERE
                    id = $4
                    AND status_code = $1
                    AND (runs = 0 OR updated + $5 < $2)
            ";
            sqlx::query(query_str)
                .bind(TaskStatus::Runnable as i16)
                .bind(updated)
                .bind(i16::from(task.runs()))
                .bind(task.id())
                .bind(max_runtime)
                .execute(ex)
                .await
                .map_err(postgres::map_sqlx_error)?
                .rows_affected()
        }

        #[cfg(any(feature = "sqlite", test))]
        Executor::Sqlite(ref mut ex) => {
            let max_runtime_msec = {
                let (max_runtime_sec, max_runtime_nsec) = sqlite::unpack_duration(max_runtime);
                as_msec("max_runtime", max_runtime_sec, max_runtime_nsec)?
            };

            let (updated_sec, updated_nsec) = sqlite::unpack_timestamp(updated);
            let updated_msec = as_msec("updated", updated_sec, updated_nsec)?;

            let query_str = "
                UPDATE tasks
                SET status_code = ?, updated_sec = ?, updated_nsec = ?, runs = ?
                WHERE
                    id = ?
                    AND status_code = ?
                    AND (
                        runs = 0
                        OR (updated_sec * 1000 + updated_nsec / 1000000) + ? < ?
                    )
            ";
            sqlx::query(query_str)
                .bind(TaskStatus::Runnable as i8)
                .bind(updated_sec)
                .bind(updated_nsec)
                .bind(task.runs() as i8)
                .bind(task.id())
                .bind(TaskStatus::Runnable as i8)
                .bind(max_runtime_msec)
                .bind(updated_msec)
                .execute(ex)
                .await
                .map_err(sqlite::map_sqlx_error)?
                .rows_affected()
        }

        #[allow(unused)]
        _ => unreachable!(),
    };

    ensure_one_update(task.id(), rows_affected)?;
    Ok(task)
}

/// Marks the already-stored task `id` as completed with the given `result`.
///
/// The task's `updated` timestamp should represent the current time, as it will help
/// troubleshoot issues after completion.
pub(crate) async fn set_task_result(
    ex: &mut Executor,
    id: Uuid,
    result: &TaskResult,
    updated: OffsetDateTime,
) -> DbResult<()> {
    let (status, reason, only_after) = result_to_status(result);

    let rows_affected = match ex {
        #[cfg(feature = "postgres")]
        Executor::Postgres(ref mut ex) => {
            let query_str = "
                UPDATE tasks
                SET status_code = $1, status_reason = $2, updated = $3, only_after = $4
                WHERE id = $5
            ";
            sqlx::query(query_str)
                .bind(status as i16)
                .bind(reason)
                .bind(updated)
                .bind(only_after)
                .bind(id)
                .execute(ex)
                .await
                .map_err(postgres::map_sqlx_error)?
                .rows_affected()
        }

        #[cfg(any(feature = "sqlite", test))]
        Executor::Sqlite(ref mut ex) => {
            let (updated_sec, updated_nsec) = sqlite::unpack_timestamp(updated);
            let only_after = only_after.map(sqlite::unpack_timestamp);

            let query_str = "
                UPDATE tasks
                SET
                    status_code = ?, status_reason = ?, updated_sec = ?, updated_nsec = ?,
                    only_after_sec = ?, only_after_nsec = ?
                WHERE id = ?
            ";
            sqlx::query(query_str)
                .bind(status as i8)
                .bind(reason)
                .bind(updated_sec)
                .bind(updated_nsec)
                .bind(only_after.map(|(sec, _nsec)| sec))
                .bind(only_after.map(|(_sec, nsec)| nsec))
                .bind(id)
                .execute(ex)
                .await
                .map_err(sqlite::map_sqlx_error)?
                .rows_affected()
        }

        #[allow(unused)]
        _ => unreachable!(),
    };

    ensure_one_update(id, rows_affected)?;
    Ok(())
}
