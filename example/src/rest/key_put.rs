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

//! API to create or update a key.

use crate::db::Tx;
use crate::driver::Driver;
use crate::model::{Key, Version};
use axum::extract::{Path, State};
use axum::response::IntoResponse;
use axum::{http, Json};
use iii_iv_core::db::Db;
use iii_iv_core::rest::RestError;

/// API handler.
pub(crate) async fn handler<D>(
    State(driver): State<Driver<D>>,
    Path(key): Path<Key>,
    body: String,
) -> Result<(http::StatusCode, impl IntoResponse), RestError>
where
    D: Db + Clone + Send + Sync + 'static,
    D::Tx: Tx + From<D::SqlxTx> + Send + Sync + 'static,
{
    let value = driver.set_key(&key, body).await?;
    let code = if *value.version() == Version::initial() {
        http::StatusCode::CREATED
    } else {
        http::StatusCode::OK
    };
    Ok((code, Json(value)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;
    use crate::rest::testutils::*;
    use iii_iv_core::rest::testutils::*;

    fn route(key: &str) -> (http::Method, String) {
        (http::Method::PUT, format!("/api/v1/keys/{}", key))
    }

    #[tokio::test]
    async fn test_create() {
        let context = TestContext::setup().await;

        let response = OneShotBuilder::new(context.app(), route("first"))
            .send_text("new value")
            .await
            .expect_status(http::StatusCode::CREATED)
            .expect_json::<Entry>()
            .await;
        let exp_response = Entry::new("new value".to_owned(), Version::initial());
        assert_eq!(exp_response, response);

        assert_eq!(exp_response, context.get_key("first").await);
    }

    #[tokio::test]
    async fn test_update() {
        let mut context = TestContext::setup().await;

        context.set_key("first", "old value", 123).await;

        let response = OneShotBuilder::new(context.app(), route("first"))
            .send_text("new value")
            .await
            .expect_json::<Entry>()
            .await;
        let exp_response = Entry::new("new value".to_owned(), Version::from_u32(124).unwrap());
        assert_eq!(exp_response, response);

        assert_eq!(exp_response, context.get_key("first").await);
    }
}
