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
    use crate::db;
    use crate::model::{ExecError, ExecResult};
    use futures::lock::Mutex;
    use iii_iv_core::clocks::testutils::SettableClock;
    use iii_iv_core::clocks::Clock;
    use iii_iv_core::db::{Db, Executor};
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Duration;
    use time::macros::datetime;

    /// A queue client backed by mock entities.
    type MockClient = Client<MockTask>;

    /// A task definition for testing purposes.
    #[derive(Deserialize, Serialize)]
    pub(super) struct MockTask {
        /// The domain-specific identifier of the task.
        pub(super) id: u16,

        /// What the task will return upon execution.
        pub(super) result: Result<Option<String>, String>,

        /// Number of times to crash before succeeding.
        pub(super) crash: u16,

        /// Task to enqueue, if any.
        pub(super) chain: Option<Box<MockTask>>,

        /// Number of times to defer a task and the amount of time by which to defer it.
        pub(super) defer: Option<(u16, Duration)>,
    }

    impl Default for MockTask {
        fn default() -> Self {
            Self { id: u16::MAX, result: Ok(None), crash: 0, chain: None, defer: None }
        }
    }

    /// Mutable state for one task.
    #[derive(Default)]
    pub(super) struct TaskState {
        /// Number of times the task has attempted to run so far.
        pub(super) runs: u16,

        /// Whether the task completed successfully and returned its stored result.
        pub(super) done: bool,

        /// Number of times the task has been deferred so far.
        pub(super) deferred: u16,
    }

    /// Mutable state for all tasks keyed by `MockTask::id`.
    type TaskStateById = Arc<Mutex<HashMap<u16, TaskState>>>;

    /// Executes `task`, updating `state` with details for validation.
    async fn run_task(
        task: MockTask,
        state_by_id: TaskStateById,
        db: Arc<dyn Db + Send + Sync>,
        mut client: MockClient,
        clock: Arc<dyn Clock + Send + Sync>,
    ) -> ExecResult {
        let mut state_by_id = state_by_id.lock().await;
        let state = state_by_id.entry(task.id).or_insert_with(TaskState::default);

        state.runs += 1;

        if state.runs <= task.crash {
            return Err(ExecError::SimulatedCrash);
        }

        if let Some(chain) = task.chain {
            client.enqueue(&mut db.ex().await.unwrap(), &chain).await.unwrap();
        }

        if let Some((max_deferred, delay)) = task.defer {
            if state.deferred < max_deferred {
                state.deferred += 1;
                // Flip-flop between the two possible retry return values so that we exercise both.
                if state.deferred % 2 == 1 {
                    return Err(ExecError::RetryAfterDelay(
                        delay,
                        format!("Deferred {} times so far", state.deferred),
                    ));
                } else {
                    assert!(
                        delay > Duration::ZERO,
                        "Zero delay can only be exercised with max_deferred == 1"
                    );
                    return Err(ExecError::RetryAfterTimestamp(
                        clock.now_utc() + delay,
                        format!("Deferred {} times so far", state.deferred),
                    ));
                }
            }
        }

        assert!(!state.done, "Task {} completed twice", task.id);
        state.done = true;

        task.result.map_err(ExecError::Failed)
    }

    /// State of a running test.
    pub(super) struct TestContext {
        /// The database backing the queue.
        pub(super) db: Arc<dyn Db + Send + Sync>,

        /// The client used to enqueue and poll for tasks.
        pub(super) client: MockClient,

        /// The workers to execute the tasks with a test-supplied function.
        pub(super) workers: Vec<Arc<Mutex<Worker<MockTask>>>>,

        /// The clock used to track task state changes.
        pub(super) clock: Arc<SettableClock>,

        /// The shared task state updated by task execution for all tasks.
        pub(super) state: TaskStateById,
    }

    impl TestContext {
        /// Initializes an in-memory queue with one in-process worker and a client that is
        /// configured to poke the worker when new tasks are enqueued.
        pub(super) async fn setup_one_connected(opts: WorkerOptions) -> Self {
            let db = Arc::from(iii_iv_core::db::sqlite::testutils::setup().await);
            db::init_schema(&mut db.ex().await.unwrap()).await.unwrap();
            let clock = Arc::from(SettableClock::new(datetime!(2023-12-01 05:50:00 UTC)));

            let state = TaskStateById::default();
            let client = Client::new(clock.clone());
            let worker = {
                let state = state.clone();
                let db = db.clone();
                let client = client.clone();
                let clock = clock.clone();
                let worker = Worker::new(db.clone(), clock.clone(), opts, move |task| {
                    run_task(task, state.clone(), db.clone(), client.clone(), clock.clone())
                });
                Arc::from(Mutex::from(worker))
            };

            let client = client.with_worker(worker.clone());

            TestContext { db, client, workers: vec![worker], clock, state }
        }

        /// Initializes an in-memory queue with `num_workers` in-process workers and a client that
        /// is **not** configured to poke any of them when new tasks are enqueued.
        pub(super) async fn setup_many_disconnected(
            opts: WorkerOptions,
            num_workers: usize,
        ) -> Self {
            let db = Arc::from(iii_iv_core::db::sqlite::testutils::setup().await);
            db::init_schema(&mut db.ex().await.unwrap()).await.unwrap();
            let clock = Arc::from(SettableClock::new(datetime!(2023-12-01 05:50:00 UTC)));

            let state = TaskStateById::default();
            let client = Client::new(clock.clone());
            let mut workers = Vec::with_capacity(num_workers);
            for _ in 0..num_workers {
                let worker = {
                    let state = state.clone();
                    let db = db.clone();
                    let client = client.clone();
                    let clock = clock.clone();
                    let worker =
                        Worker::new(db.clone(), clock.clone(), opts.clone(), move |task| {
                            run_task(task, state.clone(), db.clone(), client.clone(), clock.clone())
                        });
                    Arc::from(Mutex::from(worker))
                };
                workers.push(worker);
            }

            TestContext { db, client, workers, clock, state }
        }

        /// Gets a direct executor against the database.
        pub(crate) async fn ex(&self) -> Executor {
            self.db.ex().await.unwrap()
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
        let mut context = TestContext::setup_many_disconnected(opts.clone(), num_workers).await;

        let before = context.clock.now_utc();

        // Insert a bunch of tasks.
        let mut ids = vec![];
        for i in 0..num_tasks {
            let task =
                MockTask { id: i, result: Ok(Some(format!("Task {}", i))), ..Default::default() };
            ids.push(context.client.enqueue(&mut context.ex().await, &task).await.unwrap());
            if i % (opts.batch_size * 2) == 0 {
                context.notify_workers(num_workers / 4 + 1).await;
            }
        }
        context.notify_workers(1).await;

        // Poll until all tasks complete.
        let period = Duration::from_millis(10);
        let results =
            context.client.wait_all(context.db.clone(), &ids, before, period).await.unwrap();
        assert_eq!(usize::from(num_tasks), results.len());
        for (i, id) in ids.iter().enumerate().take(usize::from(num_tasks)) {
            assert_eq!(&TaskResult::Done(Some(format!("Task {}", i))), results.get(id).unwrap());
        }

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

        let task = MockTask { id: 123, crash: 4, ..Default::default() };
        let id = context.client.enqueue(&mut context.ex().await, &task).await.unwrap();
        let result =
            context.client.wait(context.db.clone(), id, Duration::from_millis(1)).await.unwrap();

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

        let task =
            MockTask { id: 123, result: Err("foo bar".to_owned()), crash: 3, ..Default::default() };
        let id = context.client.enqueue(&mut context.ex().await, &task).await.unwrap();
        let result =
            context.client.wait(context.db.clone(), id, Duration::from_millis(1)).await.unwrap();

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

        let task = MockTask { id: 123, crash: 1, ..Default::default() };
        let id = context.client.enqueue(&mut context.ex().await, &task).await.unwrap();
        for _ in 0..100 {
            if let Some(_result) = context.client.poll(&mut context.ex().await, id).await.unwrap() {
                panic!("Task completed but it should have not");
            }

            context.clock.sleep(Duration::from_millis(1)).await;
            context.notify_workers(1).await;
        }

        let state = context.state.lock().await;
        assert_eq!(1, state.len());
        assert_eq!(1, state.get(&123).unwrap().runs);
    }

    #[tokio::test]
    async fn test_chained_task_runs_immediately() {
        let opts = WorkerOptions::default();
        assert!(opts.consume_all);
        let mut context = TestContext::setup_many_disconnected(opts, 1).await;

        let chained = MockTask { id: 2, ..Default::default() };
        let task = MockTask { id: 1, chain: Some(Box::from(chained)), ..Default::default() };
        context.client.enqueue(&mut context.ex().await, &task).await.unwrap();
        context.notify_workers(1).await;

        loop {
            {
                let state = context.state.lock().await;
                if state.len() == 2 {
                    assert!(state.get(&1).unwrap().done);
                    assert!(state.get(&2).unwrap().done);
                    break;
                }
            }
            context.clock.sleep(Duration::from_millis(1)).await;
        }
    }

    #[tokio::test]
    async fn test_chained_task_skipped_if_consume_all_is_false() {
        let opts = WorkerOptions { consume_all: false, ..Default::default() };
        let mut context = TestContext::setup_many_disconnected(opts, 1).await;

        let chained = MockTask { id: 2, ..Default::default() };
        let task = MockTask { id: 1, chain: Some(Box::from(chained)), ..Default::default() };
        let id = context.client.enqueue(&mut context.ex().await, &task).await.unwrap();
        context.notify_workers(1).await;

        // Run the task that enqueues another chained task.
        let result =
            context.client.wait(context.db.clone(), id, Duration::from_millis(1)).await.unwrap();
        assert_eq!(TaskResult::Done(None), result);

        // Make sure the chained task did not run yet.  This is racy and we may fail to detect
        // a problem, but it should not result in false positives.
        for _ in 0..10 {
            {
                let state = context.state.lock().await;
                if state.len() > 1 {
                    panic!("The chained task completed but it should not have run");
                }
            }
            context.clock.sleep(Duration::from_millis(1)).await;
        }

        // Explicitly run a second iteration.
        context.notify_workers(1).await;

        // Now wait for the chained task to really complete.
        loop {
            {
                let state = context.state.lock().await;
                if state.len() == 2 {
                    assert!(state.get(&1).unwrap().done);
                    assert!(state.get(&2).unwrap().done);
                    break;
                }
            }
            context.clock.sleep(Duration::from_millis(1)).await;
        }
    }

    #[tokio::test]
    async fn test_deferred_task_only_runs_when_time_passes() {
        let opts = WorkerOptions::default();
        let mut context = TestContext::setup_one_connected(opts).await;

        let now = context.clock.now_utc();

        let delay = Duration::from_secs(60);
        let id1 = context
            .client
            .enqueue_deferred_after_timestamp(
                &mut context.ex().await,
                &MockTask { id: 1, ..Default::default() },
                now + delay,
            )
            .await
            .unwrap();
        let id2 = context
            .client
            .enqueue_deferred_after_delay(
                &mut context.ex().await,
                &MockTask { id: 2, ..Default::default() },
                delay,
            )
            .await
            .unwrap();

        // Make sure the deferred tasks did not run yet.  This is racy and we may fail to detect
        // a problem, but it should not result in false positives.
        for _ in 0..10 {
            {
                let state = context.state.lock().await;
                if !state.is_empty() {
                    panic!("The deferred tasks completed but they should not have run");
                }
            }
            context.clock.sleep(Duration::from_millis(1)).await;
        }

        context.clock.advance(Duration::from_secs(120));

        // The tasks will complete now that enough time has passed.
        let result =
            context.client.wait(context.db.clone(), id1, Duration::from_millis(1)).await.unwrap();
        assert_eq!(TaskResult::Done(None), result);
        let result =
            context.client.wait(context.db.clone(), id2, Duration::from_millis(1)).await.unwrap();
        assert_eq!(TaskResult::Done(None), result);
    }

    #[tokio::test]
    async fn test_task_retry_result_ok() {
        let opts = WorkerOptions { max_runs: 5, ..Default::default() };
        let mut context = TestContext::setup_one_connected(opts.clone()).await;

        let delay = Duration::from_secs(60);
        let task = MockTask {
            id: 123,
            defer: Some((u16::from(opts.max_runs - 2), delay)),
            ..Default::default()
        };
        let id = context.client.enqueue(&mut context.ex().await, &task).await.unwrap();

        // Wait until we know the task has asked to retry the `defer` times we configured.
        loop {
            {
                let state = context.state.lock().await;
                assert!(state.len() <= 1);
                if let Some(state) = state.get(&123) {
                    assert!(!state.done);
                    if state.deferred == task.defer.unwrap().0 {
                        break;
                    }
                }
            }
            context.notify_workers(1).await;
            context.clock.sleep(Duration::from_secs(1)).await;
        }
        match context.client.poll(&mut context.ex().await, id).await {
            Ok(Some(TaskResult::Retry(_, _))) => (),
            e => panic!("{:?}", e),
        }

        context.clock.advance(delay * 2);

        // The task will complete now that it is not in the deferred state any more, so wait for it.
        let result =
            context.client.wait(context.db.clone(), id, Duration::from_secs(1)).await.unwrap();
        assert_eq!(TaskResult::Done(None), result);

        let state = context.state.lock().await;
        assert_eq!(1, state.len());
        let state = state.get(&123).unwrap();
        assert_eq!(3, state.deferred);
        assert!(state.done);
    }

    #[tokio::test]
    async fn test_task_retry_result_zero_delay() {
        let opts = WorkerOptions { retry_delay: Duration::from_secs(300), ..Default::default() };
        let mut context = TestContext::setup_one_connected(opts.clone()).await;

        let task = MockTask { id: 123, defer: Some((1, Duration::ZERO)), ..Default::default() };
        let id = context.client.enqueue(&mut context.ex().await, &task).await.unwrap();

        // Make sure the task does not run if not enough time has passed.
        context.clock.advance(opts.retry_delay - Duration::from_secs(1));
        for _ in 0..10 {
            {
                let state = context.state.lock().await;
                assert!(state.len() <= 1);
                if state.len() == 1 {
                    let state = state.get(&123).unwrap();
                    assert!(!state.done);
                }
            }
            context.notify_workers(1).await;
            context.clock.sleep(Duration::from_secs(1)).await;
        }
        match context.client.poll(&mut context.ex().await, id).await {
            Ok(Some(TaskResult::Retry(_, _))) => (),
            e => panic!("{:?}", e),
        }

        context.clock.advance(Duration::from_secs(1));

        // The task will complete now that it is not in the deferred state any more, so wait for it.
        let result =
            context.client.wait(context.db.clone(), id, Duration::from_secs(1)).await.unwrap();
        assert_eq!(TaskResult::Done(None), result);

        let state = context.state.lock().await;
        assert_eq!(1, state.len());
        let state = state.get(&123).unwrap();
        assert_eq!(1, state.deferred);
        assert!(state.done);
    }

    #[tokio::test]
    async fn test_task_retry_result_exceeds_max_runs() {
        let opts = WorkerOptions { max_runs: 5, ..Default::default() };
        let mut context = TestContext::setup_one_connected(opts.clone()).await;

        let delay = Duration::from_secs(60);
        let task = MockTask {
            id: 123,
            defer: Some((u16::from(opts.max_runs - 1), delay)),
            ..Default::default()
        };
        let id = context.client.enqueue(&mut context.ex().await, &task).await.unwrap();

        context.clock.advance(delay * u32::from(opts.max_runs));

        // The task will complete now that it is not in the deferred state any more, so wait for it.
        let result =
            context.client.wait(context.db.clone(), id, Duration::from_secs(1)).await.unwrap();
        assert_eq!(
            TaskResult::Abandoned("Attempted to run 5 times, but max_runs is 5".to_owned()),
            result
        );

        let state = context.state.lock().await;
        assert_eq!(1, state.len());
        let state = state.get(&123).unwrap();
        assert_eq!(4, state.deferred);
        assert!(!state.done);
    }

    #[tokio::test]
    async fn test_wait_once_returns_retries() {
        let opts = WorkerOptions { max_runs: 5, ..Default::default() };
        let mut context = TestContext::setup_one_connected(opts.clone()).await;

        let delay = Duration::from_secs(60);
        let task = MockTask { id: 123, defer: Some((2, delay)), ..Default::default() };
        let id = context.client.enqueue(&mut context.ex().await, &task).await.unwrap();

        // Wait until we know the task has asked to retry the `defer` times we configured.
        loop {
            {
                let state = context.state.lock().await;
                assert!(state.len() <= 1);
                if let Some(state) = state.get(&123) {
                    assert!(!state.done);
                    if state.deferred == task.defer.unwrap().0 {
                        break;
                    }
                }
            }
            context.notify_workers(1).await;
            context.clock.sleep(Duration::from_secs(1)).await;
        }

        for _ in 0..2 {
            let result =
                context.client.wait_once(context.db.clone(), id, Duration::from_secs(1)).await;
            match result {
                Ok(TaskResult::Retry(_, _)) => (),
                e => panic!("{:?}", e),
            }
        }
        let result = context.client.wait(context.db.clone(), id, Duration::from_secs(1)).await;
        assert_eq!(Ok(TaskResult::Done(None)), result);

        let state = context.state.lock().await;
        assert_eq!(1, state.len());
        let state = state.get(&123).unwrap();
        assert_eq!(2, state.deferred);
        assert!(state.done);
    }
}
