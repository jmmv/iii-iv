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

//! API to create a new user account.

use crate::driver::{AuthnDriver, AuthnHooks};
use crate::model::Password;
use crate::rest::httputils::JsonMultipart;
use axum::extract::State;
use iii_iv_core::model::{EmailAddress, Username};
use iii_iv_core::rest::RestError;
use serde::{Deserialize, Serialize};

/// Message sent to the server to create an account.
#[derive(Deserialize, Serialize)]
pub struct SignupRequest {
    /// Desired username.
    pub username: Username,

    /// Desired password.
    pub password: Password,

    /// Email address for the user, needed to validate their account signup process and to contact
    /// the user for service changes.
    pub email: EmailAddress,
}

/// POST handler for this API.
pub(crate) async fn handler<H: AuthnHooks>(
    State(driver): State<AuthnDriver<H>>,
    JsonMultipart(request, extensions): JsonMultipart<SignupRequest, H::SignupInput>,
) -> Result<(), RestError> {
    driver.signup(request.username, request.password, request.email, extensions).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::password;
    use crate::rest::testutils::*;
    use axum::http;
    use iii_iv_core::{rest::testutils::OneShotBuilder, test_payload_must_be_json};
    use std::collections::HashMap;

    fn route() -> (http::Method, String) {
        (http::Method::POST, "/api/test/signup".to_owned())
    }

    #[tokio::test]
    async fn test_ok() {
        let mut context = TestContextBuilder::new().build().await;

        let request = SignupRequest {
            username: "new".into(),
            password: password!("hello4World"),
            email: "new@example.com".into(),
        };
        OneShotBuilder::new(context.app(), route()).send_json(request).await.expect_empty().await;

        assert!(context.user_exists(&Username::from("new")).await);
        assert!(!context.user_is_active(&Username::from("new")).await);
    }

    #[tokio::test]
    async fn test_ok_with_hooks_not_present() {
        let mut context =
            TestContextBuilder::new().build_with_hooks(AuthnTestHooks::default()).await;

        let request = SignupRequest {
            username: "new".into(),
            password: password!("hello4World"),
            email: "new@example.com".into(),
        };
        let extensions = SignupTestInput::default();
        OneShotBuilder::new(context.app(), route())
            .send_json_multipart(request, extensions)
            .await
            .expect_empty()
            .await;

        assert!(context.user_exists(&Username::from("new")).await);
        assert!(!context.user_is_active(&Username::from("new")).await);
    }

    #[tokio::test]
    async fn test_ok_with_hooks_present() {
        let mut context =
            TestContextBuilder::new().build_with_hooks(AuthnTestHooks::default()).await;

        let request = SignupRequest {
            username: "new".into(),
            password: password!("hello4World"),
            email: "new@example.com".into(),
        };
        let extensions = SignupTestInput { create_shadow_user: true };
        OneShotBuilder::new(context.app(), route())
            .send_json_multipart(request, extensions)
            .await
            .expect_empty()
            .await;

        assert!(context.user_exists(&Username::from("new")).await);
        assert!(!context.user_is_active(&Username::from("new")).await);
        assert!(context.user_exists(&Username::from("new-shadow")).await);
    }

    #[tokio::test]
    async fn test_already_exists() {
        let mut context = TestContextBuilder::new().build().await;

        context.create_whoami_user().await;

        let request = SignupRequest {
            username: context.whoami(),
            password: password!("hello0World"),
            email: "other@example.com".into(),
        };
        OneShotBuilder::new(context.into_app(), route())
            .send_json(request)
            .await
            .expect_status(http::StatusCode::BAD_REQUEST)
            .expect_error("already registered")
            .await;
    }

    #[tokio::test]
    async fn test_bad_username() {
        let context = TestContextBuilder::new().with_whoami("not valid").build().await;

        let request = SignupRequest {
            username: Username::new_invalid("not valid"),
            password: password!("hello"),
            email: "some@example.com".into(),
        };
        OneShotBuilder::new(context.into_app(), route())
            .send_json(request)
            .await
            .expect_status(http::StatusCode::UNPROCESSABLE_ENTITY)
            .expect_text("Unsupported character")
            .await;
    }

    #[tokio::test]
    async fn test_bad_email() {
        let context = TestContextBuilder::new().with_whoami("not valid").build().await;

        let request = SignupRequest {
            username: "valid".into(),
            password: password!("hello"),
            email: EmailAddress::new_invalid("some.example.com"),
        };
        OneShotBuilder::new(context.into_app(), route())
            .send_json(request)
            .await
            .expect_status(http::StatusCode::UNPROCESSABLE_ENTITY)
            .expect_text("Email.*valid address")
            .await;
    }

    #[tokio::test]
    async fn test_signup_hook_failure() {
        let mut context =
            TestContextBuilder::new().build_with_hooks(FailingSignupHook::default()).await;

        let request: HashMap<&str, &str> = HashMap::from([
            ("username", "new"),
            ("password", "hello4World"),
            ("email", "new@example.com"),
        ]);
        OneShotBuilder::new(context.app(), route())
            .send_json(request)
            .await
            .expect_status(http::StatusCode::INTERNAL_SERVER_ERROR)
            .expect_error("hook-failure-test")
            .await;

        assert!(!context.user_exists(&Username::from("new")).await);
    }

    test_payload_must_be_json!(TestContextBuilder::new().build().await.into_app(), route());
}
