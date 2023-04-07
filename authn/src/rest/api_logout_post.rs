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

//! API to terminate an existing session.

use crate::driver::AuthnDriver;
use crate::rest::get_bearer_auth;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use iii_iv_core::model::Username;
use iii_iv_core::rest::{EmptyBody, RestError};

/// POST handler for this API.
pub(crate) async fn handler(
    State(driver): State<AuthnDriver>,
    Path(user): Path<Username>,
    headers: HeaderMap,
    _: EmptyBody,
) -> Result<(), RestError> {
    let access_token = get_bearer_auth(&headers, driver.realm())?;
    driver.logout(access_token, user).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::model::AccessToken;
    use crate::rest::testutils::*;
    use axum::http;
    use iii_iv_core::rest::testutils::OneShotBuilder;
    use iii_iv_core::test_payload_must_be_empty;

    fn route(username: &str) -> (http::Method, String) {
        (http::Method::POST, format!("/api/test/users/{}/logout", username))
    }

    #[tokio::test]
    async fn test_ok() {
        let mut context = TestContextBuilder::new().build().await;

        let user = context.create_whoami_user().await;
        let token = context.access_token().await;

        assert!(context.session_exists(&token).await);

        OneShotBuilder::new(context.app(), route(user.username().as_str()))
            .with_bearer_auth(token.as_str())
            .send_empty()
            .await
            .expect_empty()
            .await;

        assert!(!context.session_exists(&token).await);
    }

    #[tokio::test]
    async fn test_not_found() {
        let mut context = TestContextBuilder::new().build().await;

        let user = context.create_whoami_user().await;
        let token = AccessToken::generate();

        OneShotBuilder::new(context.app(), route(user.username().as_str()))
            .with_bearer_auth(token.as_str())
            .send_empty()
            .await
            .expect_status(http::StatusCode::NOT_FOUND)
            .expect_error("Entity not found")
            .await;

        assert!(!context.session_exists(&token).await);
    }

    #[tokio::test]
    async fn test_bad_username() {
        let context = TestContextBuilder::new().build().await;

        OneShotBuilder::new(context.app(), route("not%20valid"))
            .send_empty()
            .await
            .expect_status(http::StatusCode::BAD_REQUEST)
            .expect_text("Unsupported character")
            .await;
    }

    test_payload_must_be_empty!(
        TestContextBuilder::new().build().await.into_app(),
        route("irrelevant")
    );
}
