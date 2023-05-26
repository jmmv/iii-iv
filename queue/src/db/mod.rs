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

use crate::model::{RunnableTask, RunningTask, TaskResult};
use async_trait::async_trait;
use iii_iv_core::db::{BareTx, DbError, DbResult};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::time::Duration;
use time::OffsetDateTime;
use uuid::Uuid;

mod status;

#[cfg(feature = "postgres")]
mod postgres;
#[cfg(feature = "postgres")]
pub use postgres::{PostgresClientTx, PostgresWorkerTx};

#[cfg(any(feature = "sqlite", test))]
mod sqlite;
#[cfg(any(feature = "sqlite", test))]
pub use sqlite::{SqliteClientTx, SqliteWorkerTx};

#[cfg(test)]
mod tests;

/// A transaction type to enqueue tasks and query their status.
#[async_trait]
pub trait ClientTx: BareTx {
    /// The task descriptors that this queue can store.
    type T: Send + Sync + Serialize;

    /// Stores a new task with a serialized `task` descriptor, marks it as runnable, and
    /// tracks that it was enqueue at the `created` timestamp.  Returns the ID of the created
    /// task.
    async fn put_new_task(&mut self, task: &Self::T, created: OffsetDateTime) -> DbResult<Uuid>;

    /// Fetches the result of task `id` if it has completed, or `None` otherwise.
    async fn get_result(&mut self, id: Uuid) -> DbResult<Option<TaskResult>>;

    /// Fetches all completed task results since the specified time, ordered by oldest completed
    /// task first.
    async fn get_results_since(
        &mut self,
        since: OffsetDateTime,
    ) -> DbResult<Vec<(Uuid, TaskResult)>>;
}

/// A transaction type to process tasks from the queue.
#[async_trait]
pub trait WorkerTx: BareTx {
    /// The task descriptors that this queue can process.
    type T: Send + Sync + DeserializeOwned;

    /// Gets the oldest (by last created/updated time) `limit` tasks that can be processed.
    ///
    /// This includes idle tasks (those that never started) and lost tasks (those that already
    /// attempted to run but for which we have no completion report at time `now` after
    /// `max_runtime` since the task reported a status).
    async fn get_runnable_tasks(
        &mut self,
        limit: u16,
        max_runtime: Duration,
        now: OffsetDateTime,
    ) -> DbResult<Vec<RunnableTask<Self::T>>>;

    /// Marks the already-stored `task` as running and returns a handle to run the task.
    ///
    /// The task's `updated` timestamp must represent the current time, as this will be later
    /// used to identify lost tasks.
    ///
    /// Note that the task must be considered runnable, either by being new or by having
    /// exceeded its `max_runtime`.  This is to prevent executing the same task more than once
    /// concurrently.
    async fn set_task_running(
        &mut self,
        task: RunnableTask<Self::T>,
        max_runtime: Duration,
        updated: OffsetDateTime,
    ) -> DbResult<RunningTask<Self::T>>;

    /// Marks the already-stored task `id` as completed with the given `result`.
    ///
    /// The task's `updated` timestamp should represent the current time, as it will help
    /// troubleshoot issues after completion.
    async fn set_task_result(
        &mut self,
        id: Uuid,
        result: &TaskResult,
        updated: OffsetDateTime,
    ) -> DbResult<()>;
}

/// Validates that an `UPDATE` statement for a task `id` only touched 1 row.
fn ensure_one_update(id: Uuid, affected: u64) -> DbResult<()> {
    match affected {
        0 => Err(DbError::BackendError(format!("Task {} not found or already running/done", id))),
        1 => Ok(()),
        _ => Err(DbError::BackendError(format!("Update of {} affected {} rows", id, affected))),
    }
}
