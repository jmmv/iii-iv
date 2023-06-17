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

//! Background task to extract tasks from the queue and run them.

use crate::db::WorkerTx;
use crate::model::{ExecError, ExecResult, RunnableTask, TaskResult};
use derivative::Derivative;
use futures::channel::mpsc::{self, Sender};
use futures::future::join_all;
use futures::stream::StreamExt;
use futures::{Future, SinkExt};
use iii_iv_core::clocks::Clock;
use iii_iv_core::db::{BareTx, Db};
use iii_iv_core::driver::{DriverError, DriverResult};
use iii_iv_core::env::get_optional_var;
use log::{info, warn};
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;

/// Default batch size.
const DEFAULT_BATCH_SIZE: u16 = 16;

/// Default value for the `consume_all` setting.
const DEFAULT_CONSUME_ALL: bool = true;

/// Default max runs for a task.
const DEFAULT_MAX_RUNS: u8 = 4;

/// Default max runtime, in seconds.  We assume that we run on Azure Functions with the default
/// maximum runtime of the Consumption Plan, which is 5 minutes.
const DEFAULT_MAX_RUNTIME_SECS: u64 = 5 * 60;

/// Default delay by which to retry a task that asks to be retried with the default delay.
const DEFAULT_RETRY_DELAY_SECS: u64 = 5 * 60;

/// Configuration options for the queue worker.
#[derive(Clone)]
pub struct WorkerOptions {
    /// Number of tasks to try to process during each processing cycle.
    pub batch_size: u16,

    /// If tasks exist after processing a batch, continue processing the next batch immediately
    /// without waiting for the next notification.  Typically useful for testing only.
    pub consume_all: bool,

    /// Number of times a task is allowed to run before being abandoned.
    //
    // TODO(jmmv): This is being used to limit execution for both lost tasks and deferred tasks,
    // which might not be the right thing to do.  But in order to have two knobs, we would need
    // separate tracking in the database for their respective counters.
    pub max_runs: u8,

    /// Maximum amount of time a task is expected to run.
    ///
    /// This is used to compute task timeouts and thus to decide when it is safe to start retrying
    /// a previously-running task.  This time should be longer than a task is ever allowed to run,
    /// which currently relies on the Azure Functions runtime (or some other serverless runtime)
    /// to cancel execution.
    pub max_runtime: Duration,

    /// Default delay to use when retrying tasks that ask to use the default delay, which is often
    /// used for retryable errors.
    pub retry_delay: Duration,
}

#[cfg(any(test, feature = "testutils"))]
impl Default for WorkerOptions {
    fn default() -> Self {
        Self {
            batch_size: DEFAULT_BATCH_SIZE,
            consume_all: DEFAULT_CONSUME_ALL,
            max_runs: DEFAULT_MAX_RUNS,
            max_runtime: Duration::from_secs(DEFAULT_MAX_RUNTIME_SECS),
            retry_delay: Duration::from_secs(DEFAULT_RETRY_DELAY_SECS),
        }
    }
}

impl WorkerOptions {
    /// Creates a new set of options from environment variables.
    pub fn from_env(prefix: &str) -> Result<Self, String> {
        Ok(Self {
            batch_size: get_optional_var::<u16>(prefix, "BATCH_SIZE")?
                .unwrap_or(DEFAULT_BATCH_SIZE),
            consume_all: get_optional_var::<bool>(prefix, "CONSUME_ALL")?
                .unwrap_or(DEFAULT_CONSUME_ALL),
            max_runs: get_optional_var::<u8>(prefix, "MAX_RUNS")?.unwrap_or(DEFAULT_MAX_RUNS),
            max_runtime: get_optional_var::<Duration>(prefix, "MAX_RUNTIME")?
                .unwrap_or(Duration::from_secs(DEFAULT_MAX_RUNTIME_SECS)),
            retry_delay: get_optional_var::<Duration>(prefix, "RETRY_ON_ERROR_DELAY")?
                .unwrap_or(Duration::from_secs(DEFAULT_RETRY_DELAY_SECS)),
        })
    }
}

/// Runs the runnable `task`, recording state transitions in `db` and using `clock` to stamp
/// them.
///
/// If the task has already attempted to run `max_runs` times, the task is marked as abandoned
/// and no further processing is attempted.
///
/// If the task is already running according to its state (a computation that requires knowing
/// `max_runtime`), returns an error.
///
/// `retry_on_error_delay` is used to compute the retry delay for those tasks that failed with
/// a retryable error and ask to be retried with the default configured delay.
///
/// Task errors are recorded within the task's result.  Therefore, this function only returns
/// errors if it encounters problems persisting state to the database.
async fn run_task<C, D, Exec, ExecFut, T>(
    task: RunnableTask<T>,
    exec: Exec,
    max_runs: u8,
    max_runtime: Duration,
    retry_on_error_delay: Duration,
    db: D,
    clock: C,
) -> DriverResult<Option<TaskResult>>
where
    C: Clock + Clone + Send + Sync,
    D: Db + Clone + Send + Sync,
    D::Tx: WorkerTx<T = T> + From<D::SqlxTx> + Send + Sync,
    Exec: Fn(T) -> ExecFut,
    ExecFut: Future<Output = ExecResult>,
    T: Send + Sync,
{
    let id = task.id();

    // This protects against running the same task concurrently more than once if we think it is
    // still running.
    let mut tx = db.begin().await?;
    let task = tx.set_task_running(task, max_runtime, clock.now_utc()).await?;
    tx.commit().await?;

    let result = if task.runs() >= max_runs {
        TaskResult::Abandoned(format!(
            "Attempted to run {} times, but max_runs is {}",
            task.runs(),
            max_runs
        ))
    } else {
        match task.into_json_task() {
            Ok(task) => match exec(task).await {
                Ok(msg) => TaskResult::Done(msg),

                Err(ExecError::Failed(msg)) => TaskResult::Failed(msg),

                Err(ExecError::RetryAfterDelay(only_after, msg)) => {
                    if only_after == Duration::ZERO {
                        TaskResult::Retry(clock.now_utc() + retry_on_error_delay, msg)
                    } else {
                        TaskResult::Retry(clock.now_utc() + only_after, msg)
                    }
                }

                Err(ExecError::RetryAfterTimestamp(only_after, msg)) => {
                    TaskResult::Retry(only_after, msg)
                }

                #[cfg(test)]
                Err(ExecError::SimulatedCrash) => {
                    // If we want to simulate a crash during execution, return now before committing
                    // any result to the database.
                    return Ok(None);
                }
            },
            Err(e) => TaskResult::Abandoned(format!("JSON deserialization failed: {}", e)),
        }
    };

    // A this point, the task has already completed execution and we recorded that it did run in
    // its `runs` counter.  Unfortunately, if we fail to persist the task's result here, the task
    // will be considered for execution again in the future, and thus it is possible for it to
    // run more than once.
    //
    // TODO(jmmv): Consider adding some form of retries here given the criticality of the situation
    // to minimize the chances of this being a problem.  And also expose the `runs` counter to the
    // task so that it can decide whether it actually wants to retry non-idempotent steps.
    let mut tx = db.begin().await?;
    tx.set_task_result(id, &result, clock.now_utc()).await?;
    tx.commit().await?;

    Ok(Some(result))
}

/// Performs one cycle to process tasks from the queue until no more runnable tasks are found.
///
/// The loop extracts tasks from `db` according to `opts` and executes each of them with `exec`.
///
/// This returns an error only if there are problems talking to the database.  The caller has to
/// decide if it's worth retrying the cycle or not.
pub(super) async fn loop_once<C, D, T, Exec, ExecFut>(
    db: D,
    clock: C,
    opts: &WorkerOptions,
    exec: Exec,
) -> DriverResult<()>
where
    C: Clock + Clone + Send + Sync,
    D: Db + Clone + Send + Sync,
    D::Tx: WorkerTx<T = T> + From<D::SqlxTx> + Send + Sync,
    Exec: Fn(T) -> ExecFut + Clone,
    ExecFut: Future<Output = ExecResult>,
    T: Send + Sync,
{
    loop {
        let tasks = {
            let mut tx = db.begin().await?;
            let tasks =
                tx.get_runnable_tasks(opts.batch_size, opts.max_runtime, clock.now_utc()).await?;
            tx.commit().await?;
            tasks
        };

        if tasks.is_empty() {
            // No more tasks at this point.  Terminate cycle.
            break Ok(());
        }

        let mut ids = Vec::with_capacity(tasks.len());
        let mut futures = Vec::with_capacity(tasks.len());
        for task in tasks {
            info!("Task {}: starting", task.id());
            ids.push(task.id());
            futures.push(run_task(
                task,
                exec.clone(),
                opts.max_runs,
                opts.max_runtime,
                opts.retry_delay,
                db.clone(),
                clock.clone(),
            ));
        }

        let mut failed = 0;
        let results = join_all(futures).await;
        for (id, result) in ids.into_iter().zip(results) {
            match result {
                Ok(Some(result)) => {
                    info!("Task {}: finished with {:?}", id, result);
                }

                Ok(None) => {
                    // If we are simulating a crash, abort processing of this whole loop early.
                    // This isn't exactly what would happen in real life, but attempting to panic
                    // in the task handler and trying to gracefully handle this condition is
                    // pretty difficult.
                    if cfg!(test) {
                        warn!("Task {}: simulated crash", id);
                        failed += 1;
                        break;
                    } else {
                        unreachable!("Simulated crashes should only happen in tests");
                    }
                }

                Err(e) => {
                    // There is not much we can do if trying to run a task failed due to
                    // problems talking to the database.  Log the fact and move on.  The task
                    // will be retried later once `max_runtime` has elapsed.
                    warn!("Task {}: failed to persist state: {}", id, e);
                    failed += 1;
                }
            }
        }
        if failed > 0 {
            // If one or more tasks failed, it is likely that we won't be able to process any more
            // right now.  Give up and hope that the next cycle will succeed.
            break Err(DriverError::BackendError(format!("Failed to process {} tasks", failed)));
        }

        if !opts.consume_all {
            // The configuration doesn't allow us to drain the queue.  Exit after just one loop.
            break Ok(());
        }
    }
}

/// The queue worker used to run tasks of type `T` with an `Exec`/`ExecFut` function.
///
/// This driver wraps a single queue worker and offers mechanisms to interact with it in an async
/// manner.
///
/// This worker is clonable to support having multiple call sites interacting with the single
/// worker at once.
#[derive(Derivative)]
#[derivative(Clone(bound = ""))]
pub struct Worker<T>
where
    T: Send + Sync,
{
    /// Background task processing loop.
    _worker: Arc<JoinHandle<()>>,

    /// Communication channel with the `worker` to trigger processing cycles.
    control_tx: Sender<()>,

    /// The type of the tasks handled by this worker.
    _data: PhantomData<T>,
}

impl<T> Worker<T>
where
    T: Send + Sync,
{
    /// Creates a new driver backed by `db` and a `clock`, configured to handle tasks according
    /// to `opts` and using `exec` to run the tasks.
    pub fn new<C, D, Exec, ExecFut>(db: D, clock: C, opts: WorkerOptions, exec: Exec) -> Self
    where
        C: Clock + Clone + Send + Sync + 'static,
        D: Db + Clone + Send + Sync + 'static,
        D::Tx: WorkerTx<T = T> + From<D::SqlxTx> + Send + Sync + 'static,
        Exec: Fn(T) -> ExecFut + Clone + Send + Sync + 'static,
        ExecFut: Future<Output = ExecResult> + Send + 'static,
    {
        let (control_tx, mut control_rx) = mpsc::channel(1);
        let worker = tokio::spawn(async move {
            while let Some(()) = control_rx.next().await {
                let result = loop_once(db.clone(), clock.clone(), &opts, exec.clone()).await;
                if let Err(e) = result {
                    warn!("Task processing cycle failed: {}; will retry later", e);
                }
            }
        });
        Self { _worker: Arc::from(worker), control_tx, _data: PhantomData }
    }

    /// Triggers execution of a processing cycle in the background.
    pub async fn notify(&mut self) -> DriverResult<()> {
        match self.control_tx.send(()).await {
            Ok(()) => Ok(()),
            Err(e) if e.is_full() => {
                // The worker task loops until all tasks have been processed, so if we fail to
                // enqueue a notification due to capacity issues, it means that the loop was
                // already busy processing tasks and there is a pending notification to retry
                // the loop.  There is no need to insert another.
                Ok(())
            }
            Err(e) => Err(DriverError::BackendError(format!("Cannot awaken worker task: {}", e))),
        }
    }
}
