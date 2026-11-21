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

//! Public password recovery endpoints.

use crate::driver::{AuthnDriver, AuthnHooks};
use crate::model::{EmailToken, Password};
use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use iii_iv_core::model::EmailAddress;
use iii_iv_core::rest::RestError;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Request an emailed recovery link.
#[derive(Deserialize, Serialize)]
pub struct PasswordRecoveryRequest {
    /// Account email address.
    pub email: EmailAddress,
}

/// Complete a password reset using an emailed credential.
#[derive(Deserialize, Serialize)]
pub struct PasswordResetRequest {
    /// Account identified by the email link.
    pub user_id: Uuid,
    /// Single-use recovery credential.
    pub token: EmailToken,
    /// Desired password.
    pub new_password: Password,
}

/// POST /password/recovery handler.
pub(crate) async fn request<H: AuthnHooks>(
    State(driver): State<AuthnDriver<H>>,
    Json(request): Json<PasswordRecoveryRequest>,
) -> Result<StatusCode, RestError> {
    driver.request_password_recovery(request.email).await?;
    Ok(StatusCode::ACCEPTED)
}

/// POST /password/reset handler.
pub(crate) async fn reset<H: AuthnHooks>(
    State(driver): State<AuthnDriver<H>>,
    Json(request): Json<PasswordResetRequest>,
) -> Result<(), RestError> {
    driver.reset_password(request.user_id, request.token, request.new_password).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::password;
    use crate::rest::testutils::TestContextBuilder;
    use http::Method;
    use iii_iv_core::rest::testutils::OneShotBuilder;

    #[tokio::test]
    async fn test_recovery_flow() {
        let mut context = TestContextBuilder::new().build().await;
        let user = context.create_inactive_whoami_user(42).await;
        OneShotBuilder::new(context.app(), (Method::POST, "/api/test/password/recovery"))
            .send_json(PasswordRecoveryRequest { email: user.email.clone() })
            .await
            .expect_status(StatusCode::ACCEPTED)
            .expect_empty()
            .await;
        let token = context.get_latest_recovery_token(&user.email).await.unwrap();
        let request = PasswordResetRequest {
            user_id: user.id,
            token,
            new_password: password!("reset1password"),
        };
        OneShotBuilder::new(context.app(), (Method::POST, "/api/test/password/reset"))
            .send_json(&request)
            .await
            .expect_empty()
            .await;
        OneShotBuilder::new(context.app(), (Method::POST, "/api/test/password/reset"))
            .send_json(&request)
            .await
            .expect_status(StatusCode::BAD_REQUEST)
            .expect_error("Invalid recovery link")
            .await;
        OneShotBuilder::new(context.app(), (Method::POST, "/api/test/login"))
            .with_basic_auth(user.username.as_ref().unwrap().as_str(), "reset1password")
            .send_empty()
            .await
            .expect_json::<crate::rest::LoginResponse>()
            .await;
    }
}
