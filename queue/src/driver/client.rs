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

//! Provides the task queue client implementation.

use crate::db;
use crate::driver::Worker;
use crate::model::TaskResult;
use derivative::Derivative;
use futures::lock::Mutex;
use iii_iv_core::clocks::Clock;
use iii_iv_core::db::{Db, Executor};
use iii_iv_core::driver::{DriverError, DriverResult};
use log::warn;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;
use uuid::Uuid;

/// The queue client.
///
/// This driver talks to the database to manipulate and query tasks, delegating execution to the
/// worker process.
//
// TODO(jmmv): Now that we receive a database executor via a parameter in all methods that need one,
// this must be rethought.  Having a `Client` struct probably makes no sense...  Converting these
// methods to free functions may work better, and also clarify the "auto-notification" of the
// worker that we do here sometimes.
#[derive(Derivative)]
#[derivative(Clone(bound = ""))]
pub struct Client<T>
where
    T: Serialize + Send + Sync,
{
    /// Clock instance to obtain the current time.
    clock: Arc<dyn Clock + Send + Sync>,

    /// Worker to notify when a task is enqueued for immediate processing.  This is only useful
    /// when the client and worker live in the same process, and thus is why this is optional.
    worker: Option<Arc<Mutex<Worker<T>>>>,
}

impl<T> Client<T>
where
    T: Serialize + Send + Sync,
{
    /// Creates a new queue client.
    pub fn new(clock: Arc<dyn Clock + Send + Sync>) -> Self {
        Self { clock, worker: None }
    }

    /// Configures the client to poke `worker` when new tasks are enqueued.
    pub fn with_worker(mut self, worker: Arc<Mutex<Worker<T>>>) -> Self {
        self.worker = Some(worker);
        self
    }

    /// Attempts to notify the worker, if one is configured, to ensure we make forward progress
    /// as early as possible.  This is only an optimization, so any failures are logged and then
    /// ignored.
    async fn maybe_notify_worker(&mut self) {
        if let Some(worker) = self.worker.clone() {
            let mut worker = worker.lock().await;
            if let Err(e) = worker.notify().await {
                warn!("Failed to notify worker; will run later: {}", e);
            }
        }
    }

    /// Inserts a new `task` into the queue and returns its identifier.
    ///
    /// If the client is configured to notify a worker, this notifies the worker for immediate
    /// task processing.
    pub async fn enqueue(&mut self, ex: &mut Executor, task: &T) -> DriverResult<Uuid> {
        let id = db::put_new_task(ex, task, self.clock.now_utc(), None).await?;

        self.maybe_notify_worker().await;

        Ok(id)
    }

    /// Inserts a new `task` into the queue that will only run after `only_after` and returns
    /// its identifier.
    ///
    /// If the client is configured to notify a worker, this notifies the worker for immediate
    /// task processing.
    pub async fn enqueue_deferred_after_timestamp(
        &mut self,
        ex: &mut Executor,
        task: &T,
        only_after: OffsetDateTime,
    ) -> DriverResult<Uuid> {
        let id = db::put_new_task(ex, task, self.clock.now_utc(), Some(only_after)).await?;

        self.maybe_notify_worker().await;

        Ok(id)
    }

    /// Inserts a new `task` into the queue that will only run after `only_after` time has
    /// passed and returns its identifier.
    ///
    /// If the client is configured to notify a worker, this notifies the worker for immediate
    /// task processing.
    pub async fn enqueue_deferred_after_delay(
        &mut self,
        ex: &mut Executor,
        task: &T,
        only_after: Duration,
    ) -> DriverResult<Uuid> {
        let now = self.clock.now_utc();
        let id = db::put_new_task(ex, task, now, Some(now + only_after)).await?;

        self.maybe_notify_worker().await;

        Ok(id)
    }

    /// Returns the result of task `id` if it is already available.
    pub async fn poll(&mut self, ex: &mut Executor, id: Uuid) -> DriverResult<Option<TaskResult>> {
        let result = db::get_result(ex, id).await?;
        Ok(result)
    }

    /// Waits for task `id` until it has completed execution by polling its state every `period`.
    pub async fn wait(
        &mut self,
        db: Arc<dyn Db + Send + Sync>,
        id: Uuid,
        period: Duration,
    ) -> DriverResult<TaskResult> {
        loop {
            if let Some(result) = self.poll(&mut db.ex().await?, id).await? {
                break Ok(result);
            }

            self.maybe_notify_worker().await;

            tokio::time::sleep(period).await;
        }
    }

    /// Waits until all tasks specified in `ids` have completed execution by polling their state
    /// every `period`.  Only tasks with a result produced at or after `since` are considered.
    pub async fn wait_all(
        &mut self,
        db: Arc<dyn Db + Send + Sync>,
        ids: &[Uuid],
        mut since: OffsetDateTime,
        period: Duration,
    ) -> DriverResult<HashMap<Uuid, TaskResult>> {
        let mut ids = {
            let mut set: HashSet<Uuid> = HashSet::default();
            for id in ids {
                set.insert(*id);
            }
            set
        };

        let mut results = HashMap::default();
        while !ids.is_empty() {
            let partial = db::get_results_since(&mut db.ex().await?, since).await?;

            for (id, result) in partial {
                if !ids.remove(&id) {
                    // Ignore this result given that the caller didn't ask for it.
                    continue;
                }

                let previous = results.insert(id, result);
                if previous.is_some() {
                    // If this happens, we have a bug in the queue implementation because we
                    // somehow reran a task after it completed.  We must handle this gracefully
                    // given that we are dealing with persisted state, we cannot simply assert.
                    return Err(DriverError::BackendError(format!(
                        "Got a result for task {} twice",
                        id
                    )));
                }
            }

            self.maybe_notify_worker().await;

            since += period;
            tokio::time::sleep(period).await;
        }
        Ok(results)
    }
}
