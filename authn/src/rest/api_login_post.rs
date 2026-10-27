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

use crate::driver::{AuthnDriver, AuthnHooks};
use crate::model::AccessToken;
use crate::rest::get_basic_auth;
use crate::rest::httputils::JsonMultipart;
use axum::extract::Query;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::IntoResponse;
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

/// Parameters to customize a login request.
#[derive(Debug, Deserialize, Serialize)]
pub struct LoginRequest {
    /// Maximum lifetime of the session in seconds.  The server caps this at its configured maximum.
    pub max_age: Option<u64>,
}

/// POST handler for this API.
pub(crate) async fn handler<H: AuthnHooks>(
    State(driver): State<AuthnDriver<H>>,
    headers: HeaderMap,
    Query(request): Query<LoginRequest>,
    _: EmptyBody,
) -> Result<impl IntoResponse, RestError> {
    let realm = driver.realm();
    let (username, password) = get_basic_auth(&headers, realm)
        .map_err(|_| RestError::unauthorized("Basic", realm, "Invalid login credentials"))?;

    let (session, session_max_age, output) = driver
        .login(username, password, request.max_age.map(Duration::from_secs))
        .await
        .map_err(|error| {
            RestError::from_driver_error(error, || {
                RestError::unauthorized("Basic", realm, "Invalid login credentials")
            })
        })?;
    let response = LoginResponse { access_token: session.access_token, session_max_age };

    Ok(JsonMultipart(response, output))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::AuthnOptions;
    use crate::rest::testutils::*;
    use axum::http;
    use iii_iv_core::rest::testutils::{OneShotBuilder, ResponseChecker};
    use iii_iv_core::test_payload_must_be_empty;

    fn route() -> (http::Method, String) {
        (http::Method::POST, "/api/test/login".to_owned())
    }

    /// Checks that a response is the generic login rejection.
    async fn expect_invalid_login(response: ResponseChecker) {
        response
            .expect_status(http::StatusCode::UNAUTHORIZED)
            .expect_header(http::header::WWW_AUTHENTICATE.as_str(), "Basic realm=\"the-realm\"")
            .expect_error("^Unauthorized: Invalid login credentials$")
            .await;
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
    async fn test_ok_by_email() {
        let mut context = TestContextBuilder::new().with_usernames(false).build().await;
        context.create_whoami_user().await;

        let response = OneShotBuilder::new(context.app(), route())
            .with_basic_auth("whoami@example.com", context.whoami_password().as_str())
            .send_empty()
            .await
            .expect_json::<LoginResponse>()
            .await;

        assert!(context.session_exists(&response.access_token).await);
    }

    #[tokio::test]
    async fn test_password_hash_capacity_exhausted() {
        let opts = AuthnOptions { password_hash_concurrency: 0, ..Default::default() };
        let mut context = TestContextBuilder::new().with_opts(opts).build().await;
        context.create_whoami_user().await;

        for whoami in [context.whoami().as_str(), "unknown"] {
            OneShotBuilder::new(context.app(), route())
                .with_basic_auth(whoami, context.whoami_password().as_str())
                .send_empty()
                .await
                .expect_status(http::StatusCode::SERVICE_UNAVAILABLE)
                .expect_error("Service temporarily unavailable")
                .await;
        }
    }

    #[tokio::test]
    async fn test_ok_with_requested_max_age() {
        let opts =
            AuthnOptions { session_max_age: Duration::from_secs(4182), ..Default::default() };
        let mut context = TestContextBuilder::new().with_opts(opts).build().await;

        context.create_whoami_user().await;

        let response = OneShotBuilder::new(context.app(), route())
            .with_query(LoginRequest { max_age: Some(42) })
            .with_basic_auth(context.whoami().as_str(), context.whoami_password().as_str())
            .send_empty()
            .await
            .expect_json::<LoginResponse>()
            .await;

        assert_eq!(42, response.session_max_age.as_secs());
    }

    #[tokio::test]
    async fn test_ok_with_requested_max_age_capped() {
        let opts =
            AuthnOptions { session_max_age: Duration::from_secs(4182), ..Default::default() };
        let mut context = TestContextBuilder::new().with_opts(opts).build().await;

        context.create_whoami_user().await;

        let response = OneShotBuilder::new(context.app(), route())
            .with_query(LoginRequest { max_age: Some(4183) })
            .with_basic_auth(context.whoami().as_str(), context.whoami_password().as_str())
            .send_empty()
            .await
            .expect_json::<LoginResponse>()
            .await;

        assert_eq!(4182, response.session_max_age.as_secs());
    }

    #[tokio::test]
    async fn test_ok_with_hooks() {
        let opts =
            AuthnOptions { session_max_age: Duration::from_secs(4182), ..Default::default() };
        let mut context = TestContextBuilder::new()
            .with_opts(opts)
            .build_with_hooks(AuthnTestHooks::default())
            .await;

        context.create_whoami_user().await;

        let response = OneShotBuilder::new(context.app(), route())
            .with_basic_auth(context.whoami().as_str(), context.whoami_password().as_str())
            .send_empty()
            .await
            .expect_json_multipart::<LoginResponse, LoginTestOutput>()
            .await;

        assert!(context.session_exists(&response.0.access_token).await);
        assert!(context.user_exists(&context.whoami()).await);
        assert_eq!(4182, response.0.session_max_age.as_secs());

        assert_eq!(
            format!("Welcome to the test service, {}", context.whoami().as_str()),
            response.1.welcome_message
        );
    }

    #[tokio::test]
    async fn test_unknown_user() {
        let context = TestContextBuilder::new().build().await;

        expect_invalid_login(
            OneShotBuilder::new(context.app(), route())
                .with_basic_auth(context.whoami().as_str(), "password")
                .send_empty()
                .await,
        )
        .await;
    }

    #[tokio::test]
    async fn test_bad_whoami() {
        let context = TestContextBuilder::new().with_whoami("not%20valid").build().await;

        expect_invalid_login(
            OneShotBuilder::new(context.into_app(), route())
                .with_basic_auth("not valid", "password")
                .send_empty()
                .await,
        )
        .await;
    }

    #[tokio::test]
    async fn test_inactive_user() {
        let mut context = TestContextBuilder::new().build().await;
        context.create_inactive_whoami_user(1234).await;

        expect_invalid_login(
            OneShotBuilder::new(context.app(), route())
                .with_basic_auth(context.whoami().as_str(), context.whoami_password().as_str())
                .send_empty()
                .await,
        )
        .await;
    }

    #[tokio::test]
    async fn test_invalid_password() {
        let mut context = TestContextBuilder::new().build().await;
        context.create_whoami_user().await;

        expect_invalid_login(
            OneShotBuilder::new(context.app(), route())
                .with_basic_auth(context.whoami().as_str(), "wrong-password")
                .send_empty()
                .await,
        )
        .await;
    }

    #[tokio::test]
    async fn test_malformed_basic_auth() {
        let context = TestContextBuilder::new().build().await;

        expect_invalid_login(
            OneShotBuilder::new(context.app(), route())
                .with_header(http::header::AUTHORIZATION, "Basic invalid-base64")
                .send_empty()
                .await,
        )
        .await;
    }

    #[tokio::test]
    async fn test_missing_basic_auth() {
        let context = TestContextBuilder::new().build().await;

        expect_invalid_login(OneShotBuilder::new(context.app(), route()).send_empty().await).await;
    }

    #[tokio::test]
    async fn test_overlong_password() {
        let context = TestContextBuilder::new().build().await;

        expect_invalid_login(
            OneShotBuilder::new(context.app(), route())
                .with_basic_auth(context.whoami().as_str(), "x".repeat(57))
                .send_empty()
                .await,
        )
        .await;
    }

    #[tokio::test]
    async fn test_password_disabled() {
        let mut context = TestContextBuilder::new().build().await;
        context.create_password_disabled_whoami_user().await;

        expect_invalid_login(
            OneShotBuilder::new(context.app(), route())
                .with_basic_auth(context.whoami().as_str(), context.whoami_password().as_str())
                .send_empty()
                .await,
        )
        .await;
    }

    #[tokio::test]
    async fn test_unknown_email() {
        let context = TestContextBuilder::new().with_usernames(false).build().await;

        expect_invalid_login(
            OneShotBuilder::new(context.app(), route())
                .with_basic_auth("unknown@example.com", "password")
                .send_empty()
                .await,
        )
        .await;
    }

    #[tokio::test]
    async fn test_login_hook_failure() {
        let mut context =
            TestContextBuilder::new().build_with_hooks(FailingLoginHook::default()).await;

        context.create_whoami_user().await;

        OneShotBuilder::new(context.app(), route())
            .with_basic_auth(context.whoami().as_str(), context.whoami_password().as_str())
            .send_empty()
            .await
            .expect_status(http::StatusCode::INTERNAL_SERVER_ERROR)
            .expect_error("hook-failure-test")
            .await;
    }

    test_payload_must_be_empty!(TestContextBuilder::new().build().await.into_app(), route());
}
