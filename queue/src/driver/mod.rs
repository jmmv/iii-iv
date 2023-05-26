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

//! Provides the task queue client and worker implementations.

mod client;
pub use client::Client;

mod worker;
pub use worker::{Worker, WorkerOptions};

#[cfg(test)]
mod testutils {
    use super::*;
    use crate::db::{SqliteClientTx, SqliteWorkerTx};
    use crate::model::{ExecError, ExecResult};
    use futures::lock::Mutex;
    use iii_iv_core::clocks::testutils::MonotonicClock;
    use iii_iv_sqlite::SqliteDb;
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;
    use std::sync::Arc;

    /// A task definition for testing purposes.
    #[derive(Deserialize, Serialize)]
    pub(super) struct MockTask {
        /// The domain-specific identifier of the task.
        pub(super) id: u16,

        /// What the task will return upon execution.
        pub(super) result: Result<(), String>,

        /// Number of times to crash before succeeding.
        pub(super) crash: u16,
    }

    /// Mutable state for one task.
    #[derive(Default)]
    pub(super) struct TaskState {
        /// Number of times the task has attempted to run so far.
        pub(super) runs: u16,

        /// Whether the task completed successfully and returned its stored result.
        pub(super) done: bool,
    }

    /// Mutable state for all tasks keyed by `MockTask::id`.
    type TaskStateById = Arc<Mutex<HashMap<u16, TaskState>>>;

    /// Executes `task`, updating `state` with details for validation.
    async fn run_task(task: MockTask, state_by_id: TaskStateById) -> ExecResult {
        let mut state_by_id = state_by_id.lock().await;
        let mut state = state_by_id.entry(task.id).or_insert_with(TaskState::default);

        state.runs += 1;

        if state.runs <= task.crash {
            return Err(ExecError::SimulatedCrash);
        }

        assert!(!state.done, "Task {} completed twice", task.id);
        state.done = true;

        task.result.map_err(ExecError::Failed)
    }

    /// State of a running test.
    pub(super) struct TestContext {
        /// The client used to enqueue and poll for tasks.
        pub(super) client: Client<MockTask, MonotonicClock, SqliteDb<SqliteClientTx<MockTask>>>,

        /// The workers to execute the tasks with a test-supplied function.
        pub(super) workers: Vec<Arc<Mutex<Worker<MockTask>>>>,

        /// The clock used to track task state changes.
        pub(super) clock: MonotonicClock,

        /// The shared task state updated by task execution for all tasks.
        pub(super) state: TaskStateById,
    }

    impl TestContext {
        /// Initializes an in-memory queue with one in-process worker and a client that is
        /// configured to poke the worker when new tasks are enqueued.
        pub(super) async fn setup_one_connected(opts: WorkerOptions) -> Self {
            let client_db = iii_iv_sqlite::testutils::setup().await;
            let worker_db: SqliteDb<SqliteWorkerTx<MockTask>> =
                iii_iv_sqlite::testutils::setup_attach(client_db.clone()).await;
            let clock = MonotonicClock::new(100000);

            let state = TaskStateById::default();
            let worker = {
                let state = state.clone();
                let worker = Worker::new(worker_db, clock.clone(), opts, move |task| {
                    run_task(task, state.clone())
                });
                Arc::from(Mutex::from(worker))
            };

            let client = Client::new(client_db, clock.clone(), Some(worker.clone()));

            TestContext { client, workers: vec![worker], clock, state }
        }

        /// Initializes an in-memory queue with `num_workers` in-process workers and a client that
        /// is **not** configured to poke any of them when new tasks are enqueued.
        pub(super) async fn setup_stress(opts: WorkerOptions, num_workers: usize) -> Self {
            let client_db = iii_iv_sqlite::testutils::setup().await;
            let worker_db: SqliteDb<SqliteWorkerTx<MockTask>> =
                iii_iv_sqlite::testutils::setup_attach(client_db.clone()).await;
            let clock = MonotonicClock::new(100000);

            let state = TaskStateById::default();
            let mut workers = Vec::with_capacity(num_workers);
            for _ in 0..num_workers {
                let worker = {
                    let state = state.clone();
                    let worker =
                        Worker::new(worker_db.clone(), clock.clone(), opts.clone(), move |task| {
                            run_task(task, state.clone())
                        });
                    Arc::from(Mutex::from(worker))
                };
                workers.push(worker);
            }

            let client = Client::new(client_db, clock.clone(), None);

            TestContext { client, workers, clock, state }
        }

        /// Notifies `n` workers about the availability of new tasks.
        pub(super) async fn notify_workers(&mut self, n: usize) {
            for _ in 0..n {
                let i = rand::random::<usize>() % self.workers.len();
                self.workers[i].lock().await.notify().await.unwrap();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::testutils::*;
    use crate::model::TaskResult;
    use iii_iv_core::clocks::Clock;
    use std::time::Duration;

    async fn do_stress_test(num_workers: usize, num_tasks: u16, batch_size: u16) {
        let opts = WorkerOptions {
            batch_size,
            max_runtime: Duration::from_millis(100000),
            ..Default::default()
        };
        let mut context = TestContext::setup_stress(opts.clone(), num_workers).await;

        let before = context.clock.now_utc();

        // Insert a bunch of tasks.
        let mut ids = vec![];
        for i in 0..num_tasks {
            let task = MockTask { id: i, result: Ok(()), crash: 0 };
            ids.push(context.client.enqueue(&task).await.unwrap());
            if i % (opts.batch_size * 2) == 0 {
                context.notify_workers(num_workers / 4 + 1).await;
            }
        }
        context.notify_workers(1).await;

        // Poll until all tasks complete.
        let period = Duration::from_millis(10);
        context.client.wait_all(&ids, before, period).await.unwrap();

        // Verify that all tasks completed.
        let mut state = context.state.lock().await;
        for i in 0..num_tasks {
            match state.remove(&i) {
                Some(s) => assert_eq!(1, s.runs, "Task {} should have run one time only", i),
                None => panic!("Task {} did not complete", i),
            }
        }
        assert!(state.is_empty());
    }

    #[tokio::test]
    async fn test_stress_smoke_no_threads() {
        do_stress_test(1, 100, 5).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_stress_smoke_multiple_threads() {
        do_stress_test(1, 100, 5).await;
    }

    #[ignore = "Takes longer than a unit test should"]
    #[tokio::test(flavor = "multi_thread")]
    async fn test_stress_one_worker() {
        do_stress_test(1, 10000, 5).await;
    }

    #[ignore = "Takes longer than a unit test should"]
    #[tokio::test(flavor = "multi_thread")]
    async fn test_stress_many_workers() {
        do_stress_test(10, 10000, 20).await;
    }

    #[tokio::test]
    async fn test_retry_on_crash_always_fails() {
        let mut context = TestContext::setup_one_connected(WorkerOptions {
            max_runtime: Duration::from_millis(1),
            max_runs: 5,
            ..Default::default()
        })
        .await;

        let task = MockTask { id: 123, result: Ok(()), crash: 4 };
        let id = context.client.enqueue(&task).await.unwrap();
        let result = context.client.wait(id, Duration::from_millis(1)).await.unwrap();

        let state = context.state.lock().await;
        assert_eq!(1, state.len());
        assert_eq!(4, state.get(&123).unwrap().runs);
        match result {
            TaskResult::Abandoned(_) => (),
            _ => panic!("Unexpected result {:?}", result),
        }
    }

    #[tokio::test]
    async fn test_retry_on_crash_eventually_passes() {
        let mut context = TestContext::setup_one_connected(WorkerOptions {
            max_runtime: Duration::from_millis(1),
            max_runs: 5,
            ..Default::default()
        })
        .await;

        let task = MockTask { id: 123, result: Err("foo bar".to_owned()), crash: 3 };
        let id = context.client.enqueue(&task).await.unwrap();
        let result = context.client.wait(id, Duration::from_millis(1)).await.unwrap();

        let state = context.state.lock().await;
        assert_eq!(1, state.len());
        assert_eq!(4, state.get(&123).unwrap().runs);
        match result {
            TaskResult::Failed(msg) => assert!(msg.contains("foo bar")),
            _ => panic!("Unexpected result {:?}", result),
        }
    }

    #[tokio::test]
    async fn test_retry_on_crash_does_not_run_before_max_runtime() {
        let mut context = TestContext::setup_one_connected(WorkerOptions {
            max_runtime: Duration::from_secs(3600),
            max_runs: 5,
            ..Default::default()
        })
        .await;

        let task = MockTask { id: 123, result: Ok(()), crash: 1 };
        let id = context.client.enqueue(&task).await.unwrap();
        for _ in 0..100 {
            if let Some(_result) = context.client.poll(id).await.unwrap() {
                panic!("Task completed but it should have not");
            }

            tokio::time::sleep(Duration::from_millis(1)).await;
            context.notify_workers(1).await;
        }

        let state = context.state.lock().await;
        assert_eq!(1, state.len());
        assert_eq!(1, state.get(&123).unwrap().runs);
    }
}
