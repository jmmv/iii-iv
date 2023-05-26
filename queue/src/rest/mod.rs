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

//! Common REST endpoints to interact with the queue.
//!
//! In order to use these endpoints, you must copy the contents of the `functions`
//! directory supplied with this crate into the functions that your Azure Functions
//! deployment provides.  You will need a similar triggering mechanism for other
//! runtimes.  Note that the runtime must enforce a maximum execution time for the
//! process to guarantee correctness.

use crate::driver::Worker;
use axum::Router;
use futures::lock::Mutex;
use std::sync::Arc;

mod queue_loop;
#[cfg(test)]
mod testutils;

/// Creates the router for the queue worker endpoints that are directly invoked
/// by the Azure Functions runtime.  These routes **must not** be nested under other
/// paths.
pub fn worker_cron_app<T>(worker: Arc<Mutex<Worker<T>>>) -> Router
where
    T: Send + Sync + 'static,
{
    use axum::routing::post;
    Router::new().route("/queue-loop", post(queue_loop::cron_post_handler)).with_state(worker)
}
