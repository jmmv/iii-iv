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

//! API to create a new session for an existing user.

use crate::db::AuthnTx;
use crate::driver::AuthnDriver;
use crate::model::AccessToken;
use crate::rest::get_basic_auth;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use axum::Json;
use iii_iv_core::clocks::Clock;
use iii_iv_core::db::Db;
use iii_iv_core::rest::{EmptyBody, RestError};
use iii_iv_lettre::SmtpMailer;
#[cfg(test)]
use serde::Deserialize;
use serde::Serialize;

/// Message returned by the server after a successful login attempt.
#[derive(Debug, Serialize)]
#[cfg_attr(test, derive(Deserialize))]
pub(crate) struct LoginResponse {
    /// Access token for this session.
    pub(crate) access_token: AccessToken,
}

/// POST handler for this API.
pub(crate) async fn handler<C, D, M>(
    State(driver): State<AuthnDriver<C, D, M>>,
    headers: HeaderMap,
    _: EmptyBody,
) -> Result<impl IntoResponse, RestError>
where
    C: Clock + Clone + Send + Sync + 'static,
    D: Db + Clone + Send + Sync + 'static,
    D::Tx: AuthnTx + From<D::SqlxTx> + Send + Sync + 'static,
    M: SmtpMailer + Clone + Send + Sync + 'static,
{
    let (username, password) = get_basic_auth(&headers, driver.realm())?;

    let session = driver.login(username, password).await?;
    let response = LoginResponse { access_token: session.take_access_token() };

    Ok(Json(response))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rest::testutils::*;
    use axum::http;
    use iii_iv_core::rest::testutils::OneShotBuilder;
    use iii_iv_core::test_payload_must_be_empty;

    fn route() -> (http::Method, String) {
        (http::Method::POST, "/api/test/login".to_owned())
    }

    #[tokio::test]
    async fn test_ok() {
        let mut context = TestContextBuilder::new().build().await;

        context.create_whoami_user().await;

        let response = OneShotBuilder::new(context.app(), route())
            .with_basic_auth(context.whoami().as_str(), context.whoami_password().as_str())
            .send_empty()
            .await
            .expect_json::<LoginResponse>()
            .await;

        assert!(context.session_exists(&response.access_token).await);
        assert!(context.user_exists(&context.whoami()).await);
    }

    #[tokio::test]
    async fn test_unknown_user() {
        let context = TestContextBuilder::new().build().await;

        OneShotBuilder::new(context.app(), route())
            .with_basic_auth(context.whoami().as_str(), "password")
            .send_empty()
            .await
            .expect_status(http::StatusCode::FORBIDDEN)
            .expect_error("Unknown user")
            .await;
    }

    #[tokio::test]
    async fn test_bad_whoami() {
        let context = TestContextBuilder::new().with_whoami("not%20valid").build().await;

        OneShotBuilder::new(context.into_app(), route())
            .with_basic_auth("not valid", "password")
            .send_empty()
            .await
            .expect_status(http::StatusCode::BAD_REQUEST)
            .expect_error("Unsupported character")
            .await;
    }

    test_payload_must_be_empty!(TestContextBuilder::new().build().await.into_app(), route());
}
