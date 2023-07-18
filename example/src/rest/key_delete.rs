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

//! API to delete a key.

use crate::driver::Driver;
use crate::model::Key;
use axum::extract::{Path, State};
use axum::response::IntoResponse;
use iii_iv_core::rest::{EmptyBody, RestError};

/// API handler.
pub(crate) async fn handler(
    State(driver): State<Driver>,
    Path(key): Path<Key>,
    _: EmptyBody,
) -> Result<impl IntoResponse, RestError> {
    driver.delete_key(&key).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::rest::testutils::*;
    use axum::http;
    use iii_iv_core::rest::testutils::*;

    fn route(key: &str) -> (http::Method, String) {
        (http::Method::DELETE, format!("/api/v1/keys/{}", key))
    }

    #[tokio::test]
    async fn test_ok() {
        let mut context = TestContext::setup().await;

        context.set_key("first", "value", 0).await;
        context.set_key("first", "value2", 1).await;
        context.set_key("second", "value", 0).await;

        OneShotBuilder::new(context.app(), route("first")).send_empty().await.expect_empty().await;

        assert!(!context.has_key("first").await);
        assert!(context.has_key("second").await);
    }

    #[tokio::test]
    async fn test_missing() {
        let mut context = TestContext::setup().await;

        context.set_key("first", "value", 0).await;

        OneShotBuilder::new(context.app(), route("second"))
            .send_empty()
            .await
            .expect_status(http::StatusCode::NOT_FOUND)
            .expect_error("not found")
            .await;
    }

    test_payload_must_be_empty!(TestContext::setup().await.into_app(), route("irrelevant"));
}
