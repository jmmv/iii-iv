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

//! Implementation of the database abstractions using PostgreSQL.

use crate::db::status::{result_to_status, status_to_result, TaskStatus};
use crate::db::{ensure_one_update, ClientTx, WorkerTx};
use crate::model::{RunnableTask, RunningTask, TaskResult};
use futures::TryStreamExt;
use iii_iv_core::db::{BareTx, DbError, DbResult};
use iii_iv_postgres::{map_sqlx_error, run_schema};
use serde::de::DeserializeOwned;
use serde::Serialize;
use sqlx::{Postgres, Row, Transaction};
use std::marker::PhantomData;
use std::time::Duration;
use time::OffsetDateTime;
use uuid::Uuid;

/// Schema to use to initialize the database.
const SCHEMA: &str = include_str!("postgres_schema.sql");

/// A queue client transaction backed by a PostgreSQL database.
pub struct PostgresClientTx<T: Send + Sync + Serialize> {
    /// The PostgreSQL transaction itself.
    tx: Transaction<'static, Postgres>,

    /// Marker for the task type.
    _data: PhantomData<T>,
}

impl<T: Send + Sync + Serialize> From<Transaction<'static, Postgres>> for PostgresClientTx<T> {
    fn from(tx: Transaction<'static, Postgres>) -> Self {
        Self { tx, _data: PhantomData }
    }
}

#[async_trait::async_trait]
impl<T: Send + Sync + Serialize> BareTx for PostgresClientTx<T> {
    async fn commit(mut self) -> DbResult<()> {
        self.tx.commit().await.map_err(map_sqlx_error)
    }

    async fn migrate(&mut self) -> DbResult<()> {
        run_schema(&mut self.tx, SCHEMA).await
    }
}

#[async_trait::async_trait]
impl<T: Send + Sync + Serialize> ClientTx for PostgresClientTx<T> {
    type T = T;

    async fn put_new_task(&mut self, task: &Self::T, created: OffsetDateTime) -> DbResult<Uuid> {
        let id = Uuid::new_v4();

        let json_task = match serde_json::to_string(task) {
            Ok(json) => json,
            Err(e) => {
                return Err(DbError::BackendError(format!(
                    "Cannot serialize task for storage: {}",
                    e
                )))
            }
        };

        let query_str = "INSERT INTO tasks VALUES ($1, $2, $3, NULL, 0, $4, $4)";
        let done = sqlx::query(query_str)
            .bind(id)
            .bind(&json_task)
            .bind(TaskStatus::Runnable as i16)
            .bind(created)
            .execute(&mut self.tx)
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
        let query_str = "
            SELECT status_code, status_reason
            FROM tasks
            WHERE id = $1 AND status_code != $2
        ";
        match sqlx::query(query_str)
            .bind(id)
            .bind(TaskStatus::Runnable as i16)
            .fetch_optional(&mut self.tx)
            .await
            .map_err(map_sqlx_error)?
        {
            Some(row) => {
                let code: i16 = row.try_get("status_code").map_err(map_sqlx_error)?;
                let reason: Option<String> =
                    row.try_get("status_reason").map_err(map_sqlx_error)?;

                let code = match i8::try_from(code) {
                    Ok(code) => code,
                    Err(e) => {
                        return Err(DbError::DataIntegrityError(format!(
                            "Invalid status_code {}: {}",
                            code, e
                        )))
                    }
                };

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
        let query_str = "
            SELECT id, status_code, status_reason
            FROM tasks
            WHERE status_code != $1 AND updated >= $2
            ORDER BY updated ASC
        ";
        let mut rows = sqlx::query(query_str)
            .bind(TaskStatus::Runnable as i16)
            .bind(since)
            .fetch(&mut self.tx);

        let mut results = vec![];
        while let Some(row) = rows.try_next().await.map_err(map_sqlx_error)? {
            let id: Uuid = row.try_get("id").map_err(map_sqlx_error)?;
            let code: i16 = row.try_get("status_code").map_err(map_sqlx_error)?;
            let reason: Option<String> = row.try_get("status_reason").map_err(map_sqlx_error)?;

            let code = match i8::try_from(code) {
                Ok(code) => code,
                Err(e) => {
                    return Err(DbError::DataIntegrityError(format!(
                        "Invalid status_code {}: {}",
                        code, e
                    )))
                }
            };

            let result =
                status_to_result(id, code, reason)?.expect("Must not have queried runnable tasks");
            results.push((id, result));
        }
        Ok(results)
    }
}

/// A queue worker transaction backed by a PostgreSQL database.
pub struct PostgresWorkerTx<T: Send + Sync + DeserializeOwned> {
    /// The PostgreSQL transaction itself.
    tx: Transaction<'static, Postgres>,

    /// Marker for the task type.
    _data: PhantomData<T>,
}

impl<T: Send + Sync + DeserializeOwned> From<Transaction<'static, Postgres>>
    for PostgresWorkerTx<T>
{
    fn from(tx: Transaction<'static, Postgres>) -> Self {
        Self { tx, _data: PhantomData }
    }
}

#[async_trait::async_trait]
impl<T: Send + Sync + DeserializeOwned> BareTx for PostgresWorkerTx<T> {
    async fn commit(mut self) -> DbResult<()> {
        self.tx.commit().await.map_err(map_sqlx_error)
    }

    async fn migrate(&mut self) -> DbResult<()> {
        run_schema(&mut self.tx, SCHEMA).await
    }
}

#[async_trait::async_trait]
impl<T: Send + Sync + DeserializeOwned> WorkerTx for PostgresWorkerTx<T> {
    type T = T;

    async fn get_runnable_tasks(
        &mut self,
        limit: u16,
        max_runtime: Duration,
        now: OffsetDateTime,
    ) -> DbResult<Vec<RunnableTask<Self::T>>> {
        let query_str = "
            SELECT id, json, runs
            FROM tasks
            WHERE
                status_code = $1
                AND (runs = 0 OR updated + $2 < $3)
            ORDER BY updated ASC
            LIMIT $4
        ";
        let mut rows = sqlx::query(query_str)
            .bind(TaskStatus::Runnable as i16)
            .bind(max_runtime)
            .bind(now)
            .bind(i32::from(limit))
            .fetch(&mut self.tx);

        let mut tasks = vec![];
        while let Some(row) = rows.try_next().await.map_err(map_sqlx_error)? {
            let id: Uuid = row.try_get("id").map_err(map_sqlx_error)?;
            let json: String = row.try_get("json").map_err(map_sqlx_error)?;
            let runs: i16 = row.try_get("runs").map_err(map_sqlx_error)?;

            let task = serde_json::from_str::<T>(&json);
            let runs = match u8::try_from(runs) {
                Ok(runs) => runs,
                Err(e) => {
                    return Err(DbError::DataIntegrityError(format!(
                        "Invalid runs {}: {}",
                        runs, e
                    )))
                }
            };

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
        let task = task.try_run();

        let query_str = "
            UPDATE tasks
            SET status_code = $1, updated = $2, runs = $3
            WHERE
                id = $4
                AND status_code = $1
                AND (runs = 0 OR updated + $5 < $2)
        ";
        let done = sqlx::query(query_str)
            .bind(TaskStatus::Runnable as i16)
            .bind(updated)
            .bind(i16::from(task.runs()))
            .bind(task.id())
            .bind(max_runtime)
            .execute(&mut self.tx)
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
        let (status, reason) = result_to_status(result);

        let query_str = "
            UPDATE tasks
            SET status_code = $1, status_reason = $2, updated = $3
            WHERE id = $4
        ";
        let done = sqlx::query(query_str)
            .bind(status as i16)
            .bind(reason)
            .bind(updated)
            .bind(id)
            .execute(&mut self.tx)
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
    use iii_iv_postgres::PostgresDb;

    async fn setup(
    ) -> (PostgresDb<PostgresClientTx<MockTask>>, PostgresDb<PostgresWorkerTx<MockTask>>) {
        let client_db = iii_iv_postgres::testutils::setup().await;
        let worker_db = iii_iv_postgres::testutils::setup_attach(client_db.clone()).await;
        (client_db, worker_db)
    }

    generate_db_tests!(
        setup().await,
        #[ignore = "Requires environment configuration and is expensive"]
    );
}
