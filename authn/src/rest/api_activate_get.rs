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

use crate::db::AuthnTx;
use crate::driver::AuthnDriver;
use axum::extract::{Path, Query, State};
use axum::response::Html;
use iii_iv_core::clocks::Clock;
use iii_iv_core::db::Db;
use iii_iv_core::model::Username;
use iii_iv_core::rest::{EmptyBody, RestError};
use iii_iv_lettre::SmtpMailer;
use serde::Deserialize;
#[cfg(test)]
use serde::Serialize;
use std::fmt::Write;

/// Message sent to the server to activate a user account.
#[derive(Default, Deserialize)]
#[cfg_attr(test, derive(Serialize))]
pub struct ActivateRequest {
    /// Activation code.
    pub code: u32,
}

/// GET handler for this API.
pub(crate) async fn handler<C, D, M>(
    State(driver): State<AuthnDriver<C, D, M>>,
    Path(user): Path<String>,
    Query(request): Query<ActivateRequest>,
    _: EmptyBody,
) -> Result<Html<String>, RestError>
where
    C: Clock + Clone + Send + Sync + 'static,
    D: Db + Clone + Send + Sync + 'static,
    D::Tx: AuthnTx + From<D::SqlxTx> + Send + Sync + 'static,
    M: SmtpMailer + Clone + Send + Sync + 'static,
{
    let user = Username::new(user)?;

    driver.activate(user.clone(), request.code).await?;

    // TODO(jmmv): Parameterize this so that clients can supply their own reponse
    // to activation requests.
    let mut body = String::new();
    body += "<html><head><title>Account activated</title></head><body>";

    body += "<h1>Success!</h1>";

    write!(&mut body, "<p>{}, your account has been successfully activated.</p>", user.as_str())?;

    body += "</body></html>";

    Ok(Html(body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rest::testutils::*;
    use axum::http;
    use iii_iv_core::{rest::testutils::OneShotBuilder, test_payload_must_be_empty};

    fn route(username: &str, query: ActivateRequest) -> (http::Method, String) {
        (
            http::Method::GET,
            format!(
                "/api/test/users/{}/activate?{}",
                username,
                serde_urlencoded::to_string(query).unwrap()
            ),
        )
    }

    #[tokio::test]
    async fn test_ok() {
        let mut context = TestContextBuilder::new().build().await;

        let user = context.create_inactive_whoami_user(8991).await;

        let request = ActivateRequest { code: 8991 };
        let body = OneShotBuilder::new(context.app(), route(user.username().as_str(), request))
            .send_empty()
            .await
            .take_body_as_text()
            .await;

        assert!(body.contains("Success"));
        assert!(body.contains(&format!("{}, your", context.whoami().as_str())));

        assert!(context.user_is_active(user.username()).await);
    }

    #[tokio::test]
    async fn test_cannot_activate() {
        let mut context = TestContextBuilder::new().build().await;

        let user = context.create_inactive_whoami_user(8991).await;

        let request = ActivateRequest { code: 123 };
        OneShotBuilder::new(context.app(), route(user.username().as_str(), request))
            .send_empty()
            .await
            .expect_status(http::StatusCode::BAD_REQUEST)
            .expect_error("Invalid activation code")
            .await;

        assert!(!context.user_is_active(user.username()).await);
    }

    #[tokio::test]
    async fn test_bad_username() {
        let context = TestContextBuilder::new().build().await;

        let request = ActivateRequest { code: 1 };
        OneShotBuilder::new(context.into_app(), route("not%20valid", request))
            .send_empty()
            .await
            .expect_status(http::StatusCode::BAD_REQUEST)
            .expect_error("Unsupported character")
            .await;
    }

    test_payload_must_be_empty!(
        TestContextBuilder::new().build().await.into_app(),
        route("irrelevant", ActivateRequest { code: 0 })
    );
}
