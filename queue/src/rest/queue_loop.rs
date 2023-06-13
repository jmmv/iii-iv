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

//! API to start a processing loop as invoked by the Azure Functions runtime via
//! a `timerTrigger` scheduled trigger.

use crate::driver::Worker;
use axum::extract::State;
use axum::response::IntoResponse;
use axum::{http, Json};
use futures::lock::Mutex;
use iii_iv_core::rest::RestError;
use std::collections::HashMap;
use std::sync::Arc;

/// POST handler for this cron trigger.
///
/// This handler **must** be installed at the root of the web server, not within the standard
/// `/api` path, and its name must match the name of the corresponding `function.json` file.
pub async fn cron_post_handler<T>(
    State(worker): State<Arc<Mutex<Worker<T>>>>,
    // TODO(jmmv): Should deserialize the timer request and do something with it, but for now just
    // consume and ignore it.
    _body: String,
) -> Result<impl IntoResponse, RestError>
where
    T: Send + Sync + 'static,
{
    {
        let mut worker = worker.lock().await;
        worker.notify().await?;
    }

    // The empty JSON dictionary is necessary in the response to keep the Azure Functions runtime
    // happy.  If we don't supply this in the response, the runtime thinks the function has not
    // terminated.  And if we supply a different content type, the runtime raises an error.
    let result: HashMap<String, String> = HashMap::default();
    Ok((http::StatusCode::OK, Json(result)))
}

#[cfg(test)]
mod tests {
    use crate::model::TaskResult;
    use crate::rest::testutils::*;
    use axum::http;
    use iii_iv_core::{clocks::Clock, rest::testutils::*};
    use std::{collections::HashMap, time::Duration};

    /// Constructs a URL to call the method/API under test.
    fn route() -> (http::Method, String) {
        (http::Method::POST, "/queue-loop".to_owned())
    }

    #[tokio::test]
    async fn test_ok() {
        let mut context = TestContext::setup().await;

        let before = context.clock.now_utc();

        let id1 = context
            .client
            .enqueue(&MockTask { result: Ok(Some("diagnostics".to_string())) })
            .await
            .unwrap();
        let id2 = context
            .client
            .enqueue(&MockTask { result: Err("the result".to_string()) })
            .await
            .unwrap();
        let ids = [id1, id2];

        // Give some time to the worker to execute the tasks.  We expect this to *not* happen
        // because the worker has not been notified that new tasks are ready for execution (the
        // client created by `TestContext::setup` is not connected to a worker. Obviously this
        // is racy and might not detect a real bug, but we should not get any false negatives.
        for _ in 0..10 {
            for id in ids {
                let result = context.client.poll(id).await.unwrap();
                assert!(
                    result.is_none(),
                    "Task should not have completed because we didn't poll the worker yet"
                );
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }

        let response = OneShotBuilder::new(context.app(), route())
            .send_empty()
            .await
            .expect_json::<HashMap<String, String>>()
            .await;
        assert!(response.is_empty());

        // Now that we poked the worker via the REST API, we can expect the tasks to complete.
        let results =
            context.client.wait_all(&ids, before, Duration::from_millis(1)).await.unwrap();
        assert_eq!(2, results.len());
        assert_eq!(&TaskResult::Done(Some("diagnostics".to_string())), results.get(&id1).unwrap());
        assert_eq!(&TaskResult::Failed("the result".to_string()), results.get(&id2).unwrap());
    }
}
