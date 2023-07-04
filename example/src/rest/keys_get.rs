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

//! API to get all existing keys.

use crate::db::KVStoreTx;
use crate::driver::Driver;
use axum::extract::State;
use axum::response::IntoResponse;
use axum::Json;
use iii_iv_core::db::Db;
use iii_iv_core::rest::{EmptyBody, RestError};

/// API handler.
pub(crate) async fn handler<D>(
    State(driver): State<Driver<D>>,
    _: EmptyBody,
) -> Result<impl IntoResponse, RestError>
where
    D: Db + Clone + Send + Sync + 'static,
    D::Tx: KVStoreTx + From<D::SqlxTx> + Send + Sync + 'static,
{
    let keys = driver.get_keys().await?;

    Ok(Json(keys))
}

#[cfg(test)]
mod tests {
    use crate::rest::testutils::*;
    use axum::http;
    use iii_iv_core::rest::testutils::*;

    fn route() -> (http::Method, String) {
        (http::Method::GET, "/api/v1/keys".to_owned())
    }

    #[tokio::test]
    async fn test_ok() {
        let mut context = TestContext::setup().await;

        context.set_key("second", "value", 0).await;
        context.set_key("first", "value", 0).await;
        context.set_key("first", "value2", 1).await;

        let response = OneShotBuilder::new(context.app(), route())
            .send_empty()
            .await
            .expect_json::<Vec<String>>()
            .await;
        let exp_response = vec!["first".to_owned(), "second".to_owned()];
        assert_eq!(exp_response, response);
    }

    test_payload_must_be_empty!(TestContext::setup().await.into_app(), route());
}
