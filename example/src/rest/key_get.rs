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

//! API to get the latest version of a key.

use crate::db::Tx;
use crate::driver::Driver;
use crate::model::Key;
use axum::extract::{Path, State};
use axum::response::IntoResponse;
use axum::Json;
use iii_iv_core::db::Db;
use iii_iv_core::rest::{EmptyBody, RestError};

/// API handler.
pub(crate) async fn handler<D>(
    State(driver): State<Driver<D>>,
    Path(key): Path<Key>,
    _: EmptyBody,
) -> Result<impl IntoResponse, RestError>
where
    D: Db + Clone + Send + Sync + 'static,
    D::Tx: Tx + Send + Sync + 'static,
{
    let entry = driver.get_key(&key).await?;
    Ok(Json(entry))
}

#[cfg(test)]
mod tests {
    use crate::model::*;
    use crate::rest::testutils::*;
    use axum::http;
    use iii_iv_core::rest::testutils::*;

    fn route(key: &str) -> (http::Method, String) {
        (http::Method::GET, format!("/api/v1/keys/{}", key))
    }

    #[tokio::test]
    async fn test_ok() {
        let mut context = TestContext::setup().await;

        context.set_key("first", "value", 0).await;
        context.set_key("first", "value2", 1).await;
        context.set_key("second", "value", 0).await;

        let response = OneShotBuilder::new(context.into_app(), route("first"))
            .send_empty()
            .await
            .expect_json::<Entry>()
            .await;
        let exp_response = Entry::new("value2".to_owned(), Version::from_u32(1).unwrap());
        assert_eq!(exp_response, response);
    }

    #[tokio::test]
    async fn test_missing() {
        let mut context = TestContext::setup().await;

        context.set_key("first", "value", 0).await;

        OneShotBuilder::new(context.into_app(), route("second"))
            .send_empty()
            .await
            .expect_status(http::StatusCode::NOT_FOUND)
            .expect_error("not found")
            .await;
    }

    test_payload_must_be_empty!(TestContext::setup().await.into_app(), route("irrelevant"));
}
