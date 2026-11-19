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

//! API to permanently delete an account.

use crate::driver::{AuthnDriver, AuthnHooks};
use crate::model::Password;
use crate::rest::get_bearer_auth;
use axum::Json;
use axum::extract::State;
use axum::http::HeaderMap;
use iii_iv_core::rest::RestError;
use serde::{Deserialize, Serialize};

/// Request to permanently delete the authenticated account.
#[derive(Debug, Deserialize, Serialize)]
pub struct DeleteAccountRequest {
    /// The account's current password.
    pub password: Password,
}

/// DELETE /account handler.
pub(crate) async fn handler<H: AuthnHooks>(
    State(driver): State<AuthnDriver<H>>,
    headers: HeaderMap,
    Json(request): Json<DeleteAccountRequest>,
) -> Result<(), RestError> {
    let realm = driver.realm();
    let access_token = get_bearer_auth(&headers, realm)?;
    driver.delete_account(access_token, request.password).await.map_err(|error| {
        RestError::from_driver_error(error, || {
            RestError::unauthorized("Bearer", realm, "Invalid session")
        })
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::password;
    use crate::rest::testutils::TestContextBuilder;
    use http::{Method, StatusCode};
    use iii_iv_core::rest::testutils::OneShotBuilder;

    #[tokio::test]
    async fn test_delete_account() {
        let mut context = TestContextBuilder::new().build().await;
        context.create_whoami_user().await;
        let token = context.access_token().await;
        let wrong = DeleteAccountRequest { password: password!("wrong") };
        OneShotBuilder::new(context.app(), (Method::DELETE, "/api/test/account"))
            .with_bearer_auth(token.as_str())
            .send_json(wrong)
            .await
            .expect_status(StatusCode::BAD_REQUEST)
            .expect_error("Invalid password")
            .await;
        let request = DeleteAccountRequest { password: context.whoami_password().clone() };
        OneShotBuilder::new(context.app(), (Method::DELETE, "/api/test/account"))
            .with_bearer_auth(token.as_str())
            .send_json(&request)
            .await
            .expect_status(StatusCode::OK)
            .expect_empty()
            .await;
        OneShotBuilder::new(context.app(), (Method::DELETE, "/api/test/account"))
            .with_bearer_auth(token.as_str())
            .send_json(&request)
            .await
            .expect_status(StatusCode::UNAUTHORIZED)
            .expect_error("Invalid session")
            .await;
    }

    #[tokio::test]
    async fn test_delete_account_requires_bearer() {
        let context = TestContextBuilder::new().build().await;
        OneShotBuilder::new(context.app(), (Method::DELETE, "/api/test/account"))
            .send_json(DeleteAccountRequest { password: password!("test") })
            .await
            .expect_status(StatusCode::UNAUTHORIZED)
            .expect_error("Missing Authorization header")
            .await;
    }
}
