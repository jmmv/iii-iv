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

use crate::driver::AuthnDriver;
use crate::model::AccessToken;
use crate::rest::get_basic_auth;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use axum::Json;
use iii_iv_core::rest::{EmptyBody, RestError};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Message returned by the server after a successful login attempt.
#[derive(Debug, Deserialize, Serialize)]
pub struct LoginResponse {
    /// Access token for this session.
    pub access_token: AccessToken,

    /// Maximum age of the created session.  The client can use this to set up cookie expiration
    /// times to match.
    pub session_max_age: Duration,
}

/// POST handler for this API.
pub(crate) async fn handler(
    State(driver): State<AuthnDriver>,
    headers: HeaderMap,
    _: EmptyBody,
) -> Result<impl IntoResponse, RestError> {
    let (username, password) = get_basic_auth(&headers, driver.realm())?;

    // The maximum session age is a property of the server, not the session.  This might lead to a
    // situation where this value changes in the server's configuration and the clients have session
    // cookies with expiration times that don't match.  That's OK because the clients need to be
    // prepared to handle authentication problems and session revocation for any reason.  But this
    // is just a choice.  We could as well store this value along each session in the database.
    let session_max_age = driver.opts().session_max_age;

    let session = driver.login(username, password).await?;
    let response = LoginResponse { access_token: session.take_access_token(), session_max_age };

    Ok(Json(response))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::AuthnOptions;
    use crate::rest::testutils::*;
    use axum::http;
    use iii_iv_core::rest::testutils::OneShotBuilder;
    use iii_iv_core::test_payload_must_be_empty;

    fn route() -> (http::Method, String) {
        (http::Method::POST, "/api/test/login".to_owned())
    }

    #[tokio::test]
    async fn test_ok() {
        let opts =
            AuthnOptions { session_max_age: Duration::from_secs(4182), ..Default::default() };
        let mut context = TestContextBuilder::new().with_opts(opts).build().await;

        context.create_whoami_user().await;

        let response = OneShotBuilder::new(context.app(), route())
            .with_basic_auth(context.whoami().as_str(), context.whoami_password().as_str())
            .send_empty()
            .await
            .expect_json::<LoginResponse>()
            .await;

        assert!(context.session_exists(&response.access_token).await);
        assert!(context.user_exists(&context.whoami()).await);
        assert_eq!(4182, response.session_max_age.as_secs());
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
