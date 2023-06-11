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

//! Implementation of the database abstractions using SQLite.

use crate::db::status::{result_to_status, status_to_result, TaskStatus};
use crate::db::{ensure_one_update, ClientTx, WorkerTx};
use crate::model::{RunnableTask, RunningTask, TaskResult};
use futures::lock::Mutex;
use futures::TryStreamExt;
use iii_iv_core::db::{BareTx, DbError, DbResult};
use iii_iv_sqlite::{map_sqlx_error, run_schema, unpack_duration, unpack_timestamp};
use serde::de::DeserializeOwned;
use serde::Serialize;
use sqlx::{Row, Sqlite, Transaction};
use std::marker::PhantomData;
use std::time::Duration;
use time::OffsetDateTime;
use uuid::Uuid;

/// Schema to use to initialize the test database.
const SCHEMA: &str = include_str!("sqlite_schema.sql");

/// Converts an unpacked `OffsetDateTime` expressed as `sec`/`nsec` into milliseconds.
///
/// This ensures that the given quantities do not require sub-millisecond precision because
/// our queries do not support that.
///
/// The `field` name is only used for error-logging purposes.
fn as_msec(field: &str, sec: i64, nsec: i64) -> DbResult<i64> {
    if nsec % 1000000 != 0 {
        return Err(DbError::BackendError(format!(
            "Cannot handle sub-millisecond precision in '{}': sec={}, nsec={}",
            field, sec, nsec
        )));
    }
    Ok(sec * 1000 + nsec / 1000000)
}

/// A queue client transaction backed by a SQLite database.
pub struct SqliteClientTx<T: Send + Sync + Serialize> {
    /// Inner transaction type to obtain access to the raw sqlx transaction.
    tx: Mutex<Transaction<'static, Sqlite>>,

    /// Marker for the task type.
    _data: PhantomData<T>,
}

impl<T: Send + Sync + Serialize> From<Mutex<Transaction<'static, Sqlite>>> for SqliteClientTx<T> {
    fn from(tx: Mutex<Transaction<'static, Sqlite>>) -> Self {
        Self { tx, _data: PhantomData }
    }
}

#[async_trait::async_trait]
impl<T: Send + Sync + Serialize> BareTx for SqliteClientTx<T> {
    async fn commit(mut self) -> DbResult<()> {
        let tx = self.tx.into_inner();
        tx.commit().await.map_err(map_sqlx_error)
    }

    async fn migrate(&mut self) -> DbResult<()> {
        run_schema(&mut self.tx, SCHEMA).await
    }
}

#[async_trait::async_trait]
impl<T: Send + Sync + Serialize> ClientTx for SqliteClientTx<T> {
    type T = T;

    async fn put_new_task(
        &mut self,
        task: &Self::T,
        created: OffsetDateTime,
        only_after: Option<OffsetDateTime>,
    ) -> DbResult<Uuid> {
        let mut tx = self.tx.lock().await;

        let id = Uuid::new_v4();
        let (created_sec, created_nsec) = unpack_timestamp(created);
        let only_after = only_after.map(unpack_timestamp);

        let json_task = match serde_json::to_string(task) {
            Ok(json) => json,
            Err(e) => {
                return Err(DbError::BackendError(format!(
                    "Cannot serialize task for storage: {}",
                    e
                )))
            }
        };

        let query_str = "
            INSERT INTO tasks
                (id, json, status_code, status_reason, runs,
                created_sec, created_nsec, updated_sec, updated_nsec,
                only_after_sec, only_after_nsec)
            VALUES (?, ?, ?, NULL, 0, ?, ?, ?, ?, ?, ?)
        ";
        let done = sqlx::query(query_str)
            .bind(id)
            .bind(&json_task)
            .bind(TaskStatus::Runnable as i8)
            .bind(created_sec)
            .bind(created_nsec)
            .bind(created_sec) // updated_sec
            .bind(created_nsec) // updated_nsec
            .bind(only_after.map(|(sec, _nsec)| sec))
            .bind(only_after.map(|(_sec, nsec)| nsec))
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx_error)?;
        if done.rows_affected() != 1 {
            return Err(DbError::BackendError(format!(
                "Insert created {} rows",
                done.rows_affected()
            )));
        }
        Ok(id)
    }

    async fn get_result(&mut self, id: Uuid) -> DbResult<Option<TaskResult>> {
        let mut tx = self.tx.lock().await;

        let query_str = "
            SELECT status_code, status_reason
            FROM tasks
            WHERE id = ? AND status_code != ?
        ";
        match sqlx::query(query_str)
            .bind(id)
            .bind(TaskStatus::Runnable as i8)
            .fetch_optional(&mut *tx)
            .await
            .map_err(map_sqlx_error)?
        {
            Some(row) => {
                let code: i8 = row.try_get("status_code").map_err(map_sqlx_error)?;
                let reason: Option<String> =
                    row.try_get("status_reason").map_err(map_sqlx_error)?;

                let result = status_to_result(id, code, reason)?
                    .expect("Must not have queried runnable tasks");
                Ok(Some(result))
            }
            None => Ok(None),
        }
    }

    async fn get_results_since(
        &mut self,
        since: OffsetDateTime,
    ) -> DbResult<Vec<(Uuid, TaskResult)>> {
        let mut tx = self.tx.lock().await;

        let (since_sec, since_nsec) = unpack_timestamp(since);

        let query_str = "
            SELECT id, status_code, status_reason
            FROM tasks
            WHERE
                status_code != ?
                AND (updated_sec >= ? OR (updated_sec = ? AND updated_nsec >= ?))
            ORDER BY updated_sec ASC, updated_nsec ASC
        ";
        let mut rows = sqlx::query(query_str)
            .bind(TaskStatus::Runnable as i8)
            .bind(since_sec)
            .bind(since_sec)
            .bind(since_nsec)
            .fetch(&mut *tx);

        let mut results = vec![];
        while let Some(row) = rows.try_next().await.map_err(map_sqlx_error)? {
            let id: Uuid = row.try_get("id").map_err(map_sqlx_error)?;
            let code: i8 = row.try_get("status_code").map_err(map_sqlx_error)?;
            let reason: Option<String> = row.try_get("status_reason").map_err(map_sqlx_error)?;

            let result =
                status_to_result(id, code, reason)?.expect("Must not have queried runnable tasks");
            results.push((id, result));
        }
        Ok(results)
    }
}

/// A queue worker transaction backed by a SQLite database.
pub struct SqliteWorkerTx<T: Send + Sync + DeserializeOwned> {
    /// Inner transaction type to obtain access to the raw sqlx transaction.
    tx: Mutex<Transaction<'static, Sqlite>>,

    /// Marker for the task type.
    _data: PhantomData<T>,
}

impl<T: Send + Sync + DeserializeOwned> From<Mutex<Transaction<'static, Sqlite>>>
    for SqliteWorkerTx<T>
{
    fn from(tx: Mutex<Transaction<'static, Sqlite>>) -> Self {
        Self { tx, _data: PhantomData }
    }
}

#[async_trait::async_trait]
impl<T: Send + Sync + DeserializeOwned> BareTx for SqliteWorkerTx<T> {
    async fn commit(mut self) -> DbResult<()> {
        let tx = self.tx.into_inner();
        tx.commit().await.map_err(map_sqlx_error)
    }

    async fn migrate(&mut self) -> DbResult<()> {
        run_schema(&mut self.tx, SCHEMA).await
    }
}

#[async_trait::async_trait]
impl<T: Send + Sync + DeserializeOwned> WorkerTx for SqliteWorkerTx<T> {
    type T = T;

    async fn get_runnable_tasks(
        &mut self,
        limit: u16,
        max_runtime: Duration,
        now: OffsetDateTime,
    ) -> DbResult<Vec<RunnableTask<Self::T>>> {
        let mut tx = self.tx.lock().await;

        let max_runtime_msec = {
            let (max_runtime_sec, max_runtime_nsec) = unpack_duration(max_runtime);
            as_msec("max_runtime", max_runtime_sec, max_runtime_nsec)?
        };

        let now_msec = {
            let (now_sec, now_nsec) = unpack_timestamp(now);
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
            .fetch(&mut *tx);

        let mut tasks = vec![];
        while let Some(row) = rows.try_next().await.map_err(map_sqlx_error)? {
            let id: Uuid = row.try_get("id").map_err(map_sqlx_error)?;
            let json: String = row.try_get("json").map_err(map_sqlx_error)?;
            let runs: i8 = row.try_get("runs").map_err(map_sqlx_error)?;

            let task = serde_json::from_str::<T>(&json);
            let runs = runs as u8;

            tasks.push(RunnableTask::new(id, task, runs));
        }
        Ok(tasks)
    }

    async fn set_task_running(
        &mut self,
        task: RunnableTask<Self::T>,
        max_runtime: Duration,
        updated: OffsetDateTime,
    ) -> DbResult<RunningTask<Self::T>> {
        let mut tx = self.tx.lock().await;

        let max_runtime_msec = {
            let (max_runtime_sec, max_runtime_nsec) = unpack_duration(max_runtime);
            as_msec("max_runtime", max_runtime_sec, max_runtime_nsec)?
        };

        let (updated_sec, updated_nsec) = unpack_timestamp(updated);
        let updated_msec = as_msec("updated", updated_sec, updated_nsec)?;

        let task = task.try_run();

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
        let done = sqlx::query(query_str)
            .bind(TaskStatus::Runnable as i8)
            .bind(updated_sec)
            .bind(updated_nsec)
            .bind(task.runs() as i8)
            .bind(task.id())
            .bind(TaskStatus::Runnable as i8)
            .bind(max_runtime_msec)
            .bind(updated_msec)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx_error)?;
        ensure_one_update(task.id(), done.rows_affected())?;

        Ok(task)
    }

    async fn set_task_result(
        &mut self,
        id: Uuid,
        result: &TaskResult,
        updated: OffsetDateTime,
    ) -> DbResult<()> {
        let mut tx = self.tx.lock().await;

        let (status, reason) = result_to_status(result);
        let (updated_sec, updated_nsec) = unpack_timestamp(updated);

        let query_str = "
            UPDATE tasks
            SET status_code = ?, status_reason = ?, updated_sec = ?, updated_nsec = ?
            WHERE id = ?
        ";
        let done = sqlx::query(query_str)
            .bind(status as i8)
            .bind(reason)
            .bind(updated_sec)
            .bind(updated_nsec)
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx_error)?;
        ensure_one_update(id, done.rows_affected())?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::tests::{generate_db_tests, MockTask};
    use iii_iv_sqlite::SqliteDb;

    async fn setup() -> (SqliteDb<SqliteClientTx<MockTask>>, SqliteDb<SqliteWorkerTx<MockTask>>) {
        let client_db = iii_iv_sqlite::testutils::setup().await;
        let worker_db = iii_iv_sqlite::testutils::setup_attach(client_db.clone()).await;
        (client_db, worker_db)
    }

    generate_db_tests!(setup().await);
}
