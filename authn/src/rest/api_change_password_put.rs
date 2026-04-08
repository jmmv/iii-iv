// III-IV
// Copyright 2026 Julio Merino
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

//! API to change a user's password.

use crate::driver::AuthnDriver;
use crate::model::Password;
use crate::rest::get_bearer_auth;
use axum::Json;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use iii_iv_core::model::Username;
use iii_iv_core::rest::RestError;
use serde::{Deserialize, Serialize};

/// Request to change a user's password.
#[derive(Debug, Deserialize, Serialize)]
pub struct ChangePasswordRequest {
    /// The user's current password.
    pub old_password: Password,

    /// The new password to set.
    pub new_password: Password,
}

/// PUT /users/{user}/password handler.
pub(crate) async fn handler(
    State(driver): State<AuthnDriver>,
    Path(username): Path<Username>,
    headers: HeaderMap,
    Json(request): Json<ChangePasswordRequest>,
) -> Result<(), RestError> {
    let access_token = get_bearer_auth(&headers, driver.realm())?;

    driver
        .clone()
        .change_password(access_token, username, request.old_password, request.new_password)
        .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::AccessToken;
    use crate::model::password;
    use crate::rest::testutils::*;
    use axum::http;
    use iii_iv_core::rest::testutils::OneShotBuilder;

    fn route(username: &str) -> (http::Method, String) {
        (http::Method::PUT, format!("/api/test/users/{}/password", username))
    }

    #[tokio::test]
    async fn test_ok() {
        let mut context = TestContextBuilder::new().build().await;

        let user = context.create_whoami_user().await;
        let token = context.access_token().await;

        let old_password = context.whoami_password().clone();
        let new_password = password!("new1password");

        let request = ChangePasswordRequest { old_password: old_password.clone(), new_password };

        OneShotBuilder::new(context.app(), route(user.username().as_str()))
            .with_bearer_auth(token.as_str())
            .send_json(&request)
            .await
            .expect_empty()
            .await;

        do_test_login(context.app(), "/api/test", user.username(), &password!("new1password"))
            .await;
    }

    #[tokio::test]
    async fn test_wrong_old_password() {
        let mut context = TestContextBuilder::new().build().await;

        let user = context.create_whoami_user().await;
        let token = context.access_token().await;

        let new_password = password!("new1password");

        let request =
            ChangePasswordRequest { old_password: password!("wrong0password"), new_password };

        OneShotBuilder::new(context.app(), route(user.username().as_str()))
            .with_bearer_auth(token.as_str())
            .send_json(&request)
            .await
            .expect_status(http::StatusCode::BAD_REQUEST)
            .expect_error("Invalid password")
            .await;
    }

    #[tokio::test]
    async fn test_invalid_session() {
        let context = TestContextBuilder::new().build().await;

        let token = AccessToken::generate();

        let request = ChangePasswordRequest {
            old_password: password!("old0password"),
            new_password: password!("new1password"),
        };

        OneShotBuilder::new(context.app(), route("whoami"))
            .with_bearer_auth(token.as_str())
            .send_json(&request)
            .await
            .expect_status(http::StatusCode::NOT_FOUND)
            .expect_error("Entity not found")
            .await;
    }

    #[tokio::test]
    async fn test_username_mismatch() {
        let mut context = TestContextBuilder::new().build().await;

        context.create_whoami_user().await;
        let token = context.access_token().await;

        let request = ChangePasswordRequest {
            old_password: password!("test0password"),
            new_password: password!("new1password"),
        };

        OneShotBuilder::new(context.app(), route("other"))
            .with_bearer_auth(token.as_str())
            .send_json(&request)
            .await
            .expect_status(http::StatusCode::NOT_FOUND)
            .expect_error("Entity not found")
            .await;
    }
}
