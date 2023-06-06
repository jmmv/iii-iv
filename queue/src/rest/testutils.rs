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

use crate::db::{SqliteClientTx, SqliteWorkerTx};
use crate::driver::{Client, Worker, WorkerOptions};
use crate::model::{ExecError, ExecResult};
use crate::rest::worker_cron_app;
use axum::Router;
use futures::lock::Mutex;
use iii_iv_core::clocks::testutils::MonotonicClock;
use iii_iv_sqlite::SqliteDb;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// A task definition for testing purposes.
#[derive(Deserialize, Serialize)]
pub(super) struct MockTask {
    /// What the task will return upon execution.
    pub(super) result: Result<(), String>,
}

/// Executes `task`.
async fn run_task(task: MockTask) -> ExecResult {
    task.result.map_err(ExecError::Failed)
}

/// State of a running test.
pub(super) struct TestContext {
    /// Instance of the app under test.
    app: Router,

    /// Queue client to interact with the tasks handled by `app`.
    pub(super) client: Client<MockTask, MonotonicClock, SqliteDb<SqliteClientTx<MockTask>>>,
}

impl TestContext {
    /// Initializes a REST app using an in-memory datababase with an in-process worker and a
    /// client that is **not** connected to the worker.
    pub(super) async fn setup() -> TestContext {
        let client_db = iii_iv_sqlite::testutils::setup().await;
        let worker_db: SqliteDb<SqliteWorkerTx<MockTask>> =
            iii_iv_sqlite::testutils::setup_attach(client_db.clone()).await;
        let clock = MonotonicClock::new(100000);

        let worker = {
            let opts = WorkerOptions::default();
            let worker = Worker::new(worker_db, clock.clone(), opts, run_task);
            Arc::from(Mutex::from(worker))
        };

        // The client is not connected to the worker so that we can validate that the worker loop
        // isn't invoked until we ask for it.
        let client = Client::new(client_db, clock);

        let app = worker_cron_app(worker);

        TestContext { client, app }
    }

    /// Gets a clone of the app router.
    pub(super) fn app(&self) -> Router {
        self.app.clone()
    }
}
