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

use crate::db;
use crate::driver::{Client, Worker, WorkerOptions};
use crate::model::{ExecError, ExecResult};
use crate::rest::worker_cron_app;
use axum::Router;
use futures::lock::Mutex;
use iii_iv_core::clocks::testutils::SettableClock;
use iii_iv_core::clocks::Clock;
use iii_iv_core::db::{Db, Executor};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use time::macros::datetime;

/// A task definition for testing purposes.
#[derive(Deserialize, Serialize)]
pub(super) struct MockTask {
    /// What the task will return upon execution.
    pub(super) result: Result<Option<String>, String>,
}

/// Executes `task`.
async fn run_task(task: MockTask) -> ExecResult {
    task.result.map_err(ExecError::Failed)
}

/// State of a running test.
pub(super) struct TestContext {
    /// Instance of the app under test.
    app: Router,

    /// Database backing the queue.
    pub(super) db: Arc<dyn Db + Send + Sync>,

    /// Queue client to interact with the tasks handled by `app`.
    pub(super) client: Client<MockTask>,

    /// Clock used during testing.
    pub(super) clock: Arc<dyn Clock>,
}

impl TestContext {
    /// Initializes a REST app using an in-memory datababase with an in-process worker and a
    /// client that is **not** connected to the worker.
    pub(super) async fn setup() -> TestContext {
        let db = Arc::from(iii_iv_core::db::sqlite::testutils::setup().await);
        db::init_schema(&mut db.ex().await.unwrap()).await.unwrap();
        let clock = Arc::from(SettableClock::new(datetime!(2023-12-01 05:50:00 UTC)));

        let worker = {
            let opts = WorkerOptions::default();
            let worker = Worker::new(db.clone(), clock.clone(), opts, run_task);
            Arc::from(Mutex::from(worker))
        };

        // The client is not connected to the worker so that we can validate that the worker loop
        // isn't invoked until we ask for it.
        let client = Client::new(clock.clone());

        let app = worker_cron_app(worker);

        TestContext { app, db, client, clock }
    }

    /// Gets a direct executor against the database.
    pub(crate) async fn ex(&self) -> Executor {
        self.db.ex().await.unwrap()
    }

    /// Gets a clone of the app router.
    pub(super) fn app(&self) -> Router {
        self.app.clone()
    }
}
