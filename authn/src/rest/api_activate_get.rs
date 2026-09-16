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

//! API to activate a newly-created user account.

use crate::driver::{AuthnDriver, AuthnHooks};
use axum::extract::{Path, Query, State};
use axum::response::{Html, IntoResponse, Redirect};
use iii_iv_core::rest::{EmptyBody, RestError};
use iii_iv_core::template;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use uuid::Uuid;

/// Default HTML to return when an account is successfully activated.
const DEFAULT_ACTIVATED_TEMPLATE: &str = r#"<html>
<head><title>Account activated</title></head>

<body>
<h1>Success!</h1>

<p>%user%, your account has been successfully activated.</p>

</body>
</html>
"#;

/// Message sent to the server to activate a user account.
#[derive(Default, Deserialize, Serialize)]
pub struct ActivateRequest {
    /// Activation code.
    pub code: u64,
}

/// Successful response to return when an account activation completes.
///
/// Custom templates support `email`, `user`, `user_id`, and `username` substitutions.  `user` is
/// the username when present and the email address otherwise, while `username` is empty for
/// username-free services.
#[derive(Clone, Debug, Default)]
pub enum ActivationSuccess {
    /// Returns the built-in success page.
    #[default]
    DefaultHtml,

    /// Returns a custom HTML success page.
    HtmlTemplate(Cow<'static, str>),

    /// Redirects to the given URL after applying any template substitutions.
    RedirectTemplate(String),
}

/// GET handler for this API.
#[allow(clippy::type_complexity)]
pub(crate) async fn handler<H: AuthnHooks>(
    State((driver, activation_success)): State<(AuthnDriver<H>, ActivationSuccess)>,
    Path(user): Path<String>,
    Query(request): Query<ActivateRequest>,
    _: EmptyBody,
) -> Result<impl IntoResponse, RestError> {
    let user_id = Uuid::parse_str(&user)
        .map_err(|e| RestError::InvalidRequest(format!("Invalid user ID: {}", e)))?;

    let user = driver.activate(user_id, request.code).await?;

    let user_id = user.id.to_string();
    let username = user.username.as_ref().map(|username| username.as_str()).unwrap_or("");
    let display_name = user
        .username
        .as_ref()
        .map(|username| username.as_str())
        .unwrap_or_else(|| user.email.as_str());
    let substs = &[
        ("email", user.email.as_str()),
        ("user", display_name),
        ("user_id", user_id.as_str()),
        ("username", username),
    ];

    let response = match activation_success {
        ActivationSuccess::DefaultHtml => {
            Html(template::apply(DEFAULT_ACTIVATED_TEMPLATE, substs)).into_response()
        }

        ActivationSuccess::HtmlTemplate(template) => {
            Html(template::apply(template.as_ref(), substs)).into_response()
        }

        ActivationSuccess::RedirectTemplate(template) => {
            let url = template::apply(&template, substs);
            Redirect::to(&url).into_response()
        }
    };

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rest::testutils::*;
    use axum::http;
    use iii_iv_core::{rest::testutils::OneShotBuilder, test_payload_must_be_empty};

    fn route(user_id: Uuid, query: ActivateRequest) -> (http::Method, String) {
        (
            http::Method::GET,
            format!(
                "/api/test/users/{}/activate?{}",
                user_id,
                serde_urlencoded::to_string(query).unwrap()
            ),
        )
    }

    #[tokio::test]
    async fn test_ok() {
        let mut context = TestContextBuilder::new()
            .with_activation_success(ActivationSuccess::DefaultHtml)
            .build()
            .await;

        let user = context.create_inactive_whoami_user(8991).await;

        let request = ActivateRequest { code: 8991 };
        let body = OneShotBuilder::new(context.app(), route(user.id, request))
            .send_empty()
            .await
            .take_body_as_text()
            .await;

        assert!(body.contains("Success"));
        assert!(body.contains(&format!("{}, your", context.whoami().as_str())));

        assert!(context.user_is_active(user.username.as_ref().unwrap()).await);
    }

    #[tokio::test]
    async fn test_ok_custom_template() {
        let template = "All good, %username%!";
        let mut context = TestContextBuilder::new()
            .with_activation_success(ActivationSuccess::HtmlTemplate(template.into()))
            .build()
            .await;

        let user = context.create_inactive_whoami_user(8991).await;

        let request = ActivateRequest { code: 8991 };
        let body = OneShotBuilder::new(context.app(), route(user.id, request))
            .send_empty()
            .await
            .take_body_as_text()
            .await;

        assert_eq!(format!("All good, {}!", context.whoami().as_str()), body);

        assert!(context.user_is_active(user.username.as_ref().unwrap()).await);
    }

    #[tokio::test]
    async fn test_ok_redirect() {
        let template = "http://frontend.example.com/#/account-activated?username=%username%";
        let mut context = TestContextBuilder::new()
            .with_activation_success(ActivationSuccess::RedirectTemplate(template.to_owned()))
            .build()
            .await;

        let user = context.create_inactive_whoami_user(8991).await;

        let request = ActivateRequest { code: 8991 };
        OneShotBuilder::new(context.app(), route(user.id, request))
            .send_empty()
            .await
            .expect_status(http::StatusCode::SEE_OTHER)
            .expect_header(
                http::header::LOCATION.as_str(),
                format!(
                    "http://frontend.example.com/#/account-activated?username={}",
                    context.whoami().as_str()
                ),
            )
            .expect_empty()
            .await;

        assert!(context.user_is_active(user.username.as_ref().unwrap()).await);
    }

    #[tokio::test]
    async fn test_cannot_activate() {
        let mut context = TestContextBuilder::new()
            .with_activation_success(ActivationSuccess::DefaultHtml)
            .build()
            .await;

        let user = context.create_inactive_whoami_user(8991).await;

        let request = ActivateRequest { code: 123 };
        OneShotBuilder::new(context.app(), route(user.id, request))
            .send_empty()
            .await
            .expect_status(http::StatusCode::BAD_REQUEST)
            .expect_error("Invalid activation code")
            .await;

        assert!(!context.user_is_active(user.username.as_ref().unwrap()).await);
    }

    #[tokio::test]
    async fn test_bad_user_id() {
        let context = TestContextBuilder::new()
            .with_activation_success(ActivationSuccess::DefaultHtml)
            .build()
            .await;

        OneShotBuilder::new(
            context.into_app(),
            (http::Method::GET, "/api/test/users/not-valid/activate?code=1"),
        )
        .send_empty()
        .await
        .expect_status(http::StatusCode::BAD_REQUEST)
        .expect_error("Invalid user ID")
        .await;
    }

    test_payload_must_be_empty!(
        TestContextBuilder::new()
            .with_activation_success(ActivationSuccess::DefaultHtml)
            .build()
            .await
            .into_app(),
        route(Uuid::nil(), ActivateRequest { code: 0 })
    );
}
