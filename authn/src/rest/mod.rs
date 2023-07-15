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

//! REST interface for a generic authentication service.

use crate::db::AuthnTx;
use crate::driver::AuthnDriver;
use axum::Router;
use iii_iv_core::clocks::Clock;
use iii_iv_core::db::Db;
use iii_iv_lettre::SmtpMailer;

mod api_activate_get;
mod api_login_post;
mod api_logout_post;
mod api_signup_post;
mod httputils;
#[cfg(test)]
mod testutils;

pub use httputils::{get_basic_auth, get_bearer_auth, has_bearer_auth};

/// Creates the router for the authentication endpoints.
///
/// The `driver` is a configured instance of the `AuthnDriver` to handle accounts.
///
/// The `activated_template` HTML template is used when confirming the successful activation of
/// a new account.
pub fn app<C, D, M>(
    driver: AuthnDriver<C, D, M>,
    activated_template: Option<&'static str>,
) -> Router
where
    C: Clock + Clone + Send + Sync + 'static,
    D: Db + Clone + Send + Sync + 'static,
    D::Tx: AuthnTx + From<D::SqlxTx> + Send + Sync + 'static,
    M: SmtpMailer + Clone + Send + Sync + 'static,
{
    use axum::routing::{get, post};

    let activate_router = Router::new()
        .route("/users/:user/activate", get(api_activate_get::handler))
        .with_state((driver.clone(), activated_template));

    Router::new()
        .route("/login", post(api_login_post::handler))
        .route("/users/:user/logout", post(api_logout_post::handler))
        .route("/signup", post(api_signup_post::handler))
        .with_state(driver)
        .merge(activate_router)
}

#[cfg(test)]
mod tests {
    use super::api_activate_get::ActivateRequest;
    use super::api_login_post::LoginResponse;
    use super::api_signup_post::SignupRequest;
    use super::testutils::*;
    use http::{Method, StatusCode};
    use iii_iv_core::model::{EmailAddress, Username};
    use iii_iv_core::rest::testutils::*;

    #[tokio::test]
    async fn test_e2e_signup_flow() {
        let mut context = TestContextBuilder::new().with_whoami("the-user").build().await;

        let request = SignupRequest {
            username: "the-user".into(),
            password: "The1234Password".into(),
            email: "new@example.com".into(),
        };
        OneShotBuilder::new(context.app(), (Method::POST, "/api/test/signup"))
            .send_json(request)
            .await
            .expect_empty()
            .await;

        OneShotBuilder::new(context.app(), (Method::POST, "/api/test/login"))
            .with_basic_auth("the-user", "the password")
            .send_empty()
            .await
            .expect_status(StatusCode::FORBIDDEN)
            .expect_error("Invalid password")
            .await;

        OneShotBuilder::new(context.app(), (Method::POST, "/api/test/login"))
            .with_basic_auth("the-user", "The1234Password")
            .send_empty()
            .await
            .expect_status(StatusCode::CONFLICT)
            .expect_error("Account.*not.*activated")
            .await;

        let request = ActivateRequest {
            code: context
                .get_latest_activation_code(
                    &EmailAddress::from("new@example.com"),
                    &Username::from("the-user"),
                )
                .await
                .unwrap(),
        };
        OneShotBuilder::new(
            context.app(),
            (
                Method::GET,
                format!(
                    "/api/test/users/the-user/activate?{}",
                    serde_urlencoded::to_string(request).unwrap()
                ),
            ),
        )
        .send_empty()
        .await
        .expect_text("successfully activated")
        .await;

        let response = OneShotBuilder::new(context.app(), (Method::POST, "/api/test/login"))
            .with_basic_auth("the-user", "The1234Password")
            .send_empty()
            .await
            .expect_json::<LoginResponse>()
            .await;
        let access_token1 = response.access_token;
        assert!(context.session_exists(&access_token1).await);

        let response = OneShotBuilder::new(context.app(), (Method::POST, "/api/test/login"))
            .with_basic_auth("the-user", "The1234Password")
            .send_empty()
            .await
            .expect_json::<LoginResponse>()
            .await;
        let access_token2 = response.access_token;
        assert!(context.session_exists(&access_token1).await);
        assert!(context.session_exists(&access_token2).await);

        assert_ne!(access_token1, access_token2);

        OneShotBuilder::new(context.app(), (Method::POST, "/api/test/users/the-user/logout"))
            .with_bearer_auth(access_token1.as_str())
            .send_empty()
            .await
            .expect_empty()
            .await;
        assert!(!context.session_exists(&access_token1).await);
        assert!(context.session_exists(&access_token2).await);
    }
}
