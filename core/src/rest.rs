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

//! Generic code for REST handlers.
//!
//! All services should implement an `app` function in this module that returns the `Router` for the
//! application.
//!
//! Every API should be put in its own `.rs` file, using a name like `<entity>_<method>.rs`.  This
//! may seem overkill, but putting every API in its own file makes it easy to ensure all the
//! integration tests for the given API truly belong to that API.
//!
//! More specifically, the `tests` module within an API should define a `route` method that
//! returns the HTTP method and the API path under test.  All integration tests within the module
//! then rely on `route` to obtain this information, ensuring that they all test the desired API.
//!
//! It is also useful for the tests in this layer to define a `TestContext` in a `testutils` module
//! that allows interacting with the database layer directly, using simplified types.

use crate::driver::DriverError;
use crate::model::ModelError;
use async_trait::async_trait;
use axum::Json;
use axum::body::HttpBody;
use axum::extract::{FromRequest, Request};
use axum::http::header::AsHeaderName;
use axum::http::{HeaderMap, HeaderValue};
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};
use std::fmt;

mod base_urls;
pub use base_urls::BaseUrls;

/// Frontend errors.  These are the errors that are visible to the user on failed requests.
#[derive(Debug, PartialEq, thiserror::Error)]
pub enum RestError {
    /// Indicates an authorization problem.
    #[error("Access denied: {0}")]
    Forbidden(String),

    /// Catch-all error type for all unexpected errors.
    #[error("{0}")]
    InternalError(String),

    /// Indicates an error in the contents of the request.
    #[error("{0}")]
    InvalidRequest(String),

    /// Indicates insufficient disk quota to perform the requested write operation.
    #[error("{0}")]
    NoSpace(String),

    /// Indicates that login cannot succeed because the account is not yet activated.
    #[error("Account has not been activated yet")]
    NotActivated,

    /// Indicates that a requested entity does not exist.
    #[error("{0}")]
    NotFound(String),

    /// Indicates that a request that should have empty content did not.
    #[error("Content should be empty")]
    PayloadNotEmpty,

    /// Indicates an authentication problem.
    #[error("Unauthorized: {message}")]
    Unauthorized {
        /// Expected authorization scheme.
        scheme: &'static str,

        /// Expected authorization realm.
        realm: &'static str,

        /// Descriptive message explaining the nature of the problem.
        message: String,
    },
}

impl From<DriverError> for RestError {
    fn from(e: DriverError) -> Self {
        match e {
            DriverError::AlreadyExists(_) => RestError::InvalidRequest(e.to_string()),
            DriverError::BackendError(_) => RestError::InternalError(e.to_string()),
            DriverError::InvalidInput(_) => RestError::InvalidRequest(e.to_string()),
            DriverError::NoSpace(_) => RestError::NoSpace(e.to_string()),
            DriverError::NotActivated => RestError::NotActivated,
            DriverError::NotFound(_) => RestError::NotFound(e.to_string()),
            DriverError::Unauthorized(_) => RestError::Forbidden(e.to_string()),
        }
    }
}

impl From<fmt::Error> for RestError {
    fn from(e: fmt::Error) -> Self {
        RestError::InternalError(e.to_string())
    }
}

impl From<ModelError> for RestError {
    fn from(e: ModelError) -> Self {
        RestError::InvalidRequest(e.to_string())
    }
}

impl From<serde_json::Error> for RestError {
    fn from(e: serde_json::Error) -> Self {
        RestError::InvalidRequest(e.to_string())
    }
}

impl IntoResponse for RestError {
    fn into_response(self) -> axum::response::Response {
        let status;
        let mut headers = HeaderMap::new();
        match self {
            RestError::Forbidden(_) => {
                status = http::StatusCode::FORBIDDEN;
            }
            RestError::InternalError(_) => {
                status = http::StatusCode::INTERNAL_SERVER_ERROR;
            }
            RestError::InvalidRequest(_) => {
                status = http::StatusCode::BAD_REQUEST;
            }
            RestError::NoSpace(_) => {
                status = http::StatusCode::INSUFFICIENT_STORAGE;
            }
            RestError::NotActivated => {
                status = http::StatusCode::CONFLICT;
            }
            RestError::NotFound(_) => {
                status = http::StatusCode::NOT_FOUND;
            }
            RestError::PayloadNotEmpty => {
                status = http::StatusCode::PAYLOAD_TOO_LARGE;
            }
            RestError::Unauthorized { scheme, realm, message: _ } => {
                status = http::StatusCode::UNAUTHORIZED;
                headers.insert(
                    "WWW-Authenticate",
                    format!("{} realm=\"{}\"", scheme, realm).parse().unwrap(),
                );
            }
        };

        let response = ErrorResponse { message: self.to_string() };

        (status, headers, Json(response)).into_response()
    }
}

/// Result type for this module.
pub type RestResult<T> = Result<T, RestError>;

/// Representation of the details of an error response.
#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct ErrorResponse {
    /// Textual representation of the error message.
    pub(crate) message: String,
}

/// A request body extractor that forbids any content.
///
/// Any API that doesn't expect a body should use this to ensure we don't get garbage data that we
/// don't care about.  This future-proofs the service.
pub struct EmptyBody {}

#[async_trait]
impl<S> FromRequest<S> for EmptyBody
where
    S: Send + Sync,
{
    type Rejection = RestError;

    async fn from_request(req: Request, _state: &S) -> Result<Self, Self::Rejection> {
        if req.into_body().is_end_stream() {
            Ok(EmptyBody {})
        } else {
            Err(RestError::PayloadNotEmpty)
        }
    }
}

/// Extracts the header `name` from `headers` and ensures it has at most one value.
pub fn get_unique_header<K: AsHeaderName + Copy>(
    headers: &HeaderMap,
    name: K,
) -> RestResult<Option<&HeaderValue>> {
    let mut iter = headers.get_all(name).iter();
    let value = iter.next();
    if iter.next().is_some() {
        return Err(RestError::InvalidRequest(format!(
            "Header {} cannot have more than one value",
            name.as_str()
        )));
    }
    Ok(value)
}

/// Common test code for the REST server.
#[cfg(feature = "testutils")]
pub mod testutils {
    use super::*;
    use axum::Router;
    use axum::http::{self, HeaderName};
    use base64::Engine;
    use base64::engine::general_purpose;
    use bytes::Bytes;
    use serde::Serialize;
    use serde::de::DeserializeOwned;
    use tower::util::ServiceExt;

    /// Maximum body size for testing purposes.
    const MAX_BODY_SIZE: usize = 1024;

    /// Builder for a single request to the API server.
    #[must_use]
    pub struct OneShotBuilder {
        /// The router for the app being tested.
        app: Router,

        /// Builder for the request that will be sent to the app.
        builder: axum::http::request::Builder,
    }

    impl OneShotBuilder {
        /// Creates a new request against a given `method`/`uri` pair served by an `app` router.
        pub fn new<U: AsRef<str>>(app: Router, (method, uri): (http::Method, U)) -> Self {
            let builder = Request::builder().method(method).uri(uri.as_ref());
            Self { app, builder }
        }

        /// Extends the URI in the request with a `query`.
        pub fn with_query<Q: Serialize>(mut self, query: Q) -> Self {
            let uri = self.builder.uri_ref().unwrap().to_string();
            assert!(!uri.contains('?'), "URI already contains a query: {}", uri);
            assert!(!uri.contains('#'), "URI contains a fragment: {}", uri);
            self.builder = self.builder.uri(format!(
                "{}?{}",
                uri,
                serde_urlencoded::to_string(query).unwrap()
            ));
            self
        }

        /// Extends the URI in the request with a `fragment`.
        pub fn with_fragment<F: AsRef<str>>(mut self, fragment: F) -> Self {
            let uri = self.builder.uri_ref().unwrap().to_string();
            assert!(!uri.contains('#'), "URI already contains a fragment: {}", uri);
            self.builder = self.builder.uri(format!("{}#{}", uri, fragment.as_ref()));
            self
        }

        /// Adds basic authentication to the request.
        pub fn with_basic_auth<U, P>(mut self, username: U, password: P) -> Self
        where
            U: fmt::Display,
            P: fmt::Display,
        {
            let value = format!(
                "Basic {}",
                general_purpose::STANDARD.encode(format!("{}:{}", username, password))
            );
            self.builder = self.builder.header(http::header::AUTHORIZATION, value);
            self
        }

        /// Adds bearer authentication to the request.
        pub fn with_bearer_auth<T>(mut self, token: T) -> Self
        where
            T: fmt::Display,
        {
            let value = format!("Bearer {}", token);
            self.builder = self.builder.header(http::header::AUTHORIZATION, value);
            self
        }

        /// Sets the header `name` to `value` in the outgoing request.
        pub fn with_header<K, V>(mut self, name: K, value: V) -> Self
        where
            HeaderName: TryFrom<K>,
            <HeaderName as TryFrom<K>>::Error: Into<http::Error>,
            HeaderValue: TryFrom<V>,
            <HeaderValue as TryFrom<V>>::Error: Into<http::Error>,
        {
            self.builder = self.builder.header(name, value);
            self
        }

        /// Finishes building the request and sends it with an empty payload.
        pub async fn send_empty(self) -> ResponseChecker {
            let request = self.builder.body(axum::body::Body::empty()).unwrap();
            ResponseChecker::from(self.app.oneshot(request).await.unwrap())
        }

        /// Finishes building the request and sends it with a binary payload.
        pub async fn send_bytes(self, bytes: Bytes) -> ResponseChecker {
            let request = self
                .builder
                .header(http::header::CONTENT_TYPE, mime::APPLICATION_OCTET_STREAM.as_ref())
                .body(axum::body::Body::from(bytes))
                .unwrap();
            ResponseChecker::from(self.app.oneshot(request).await.unwrap())
        }

        /// Finishes building the request and sends it with a text payload.
        pub async fn send_text<T: Into<String>>(self, text: T) -> ResponseChecker {
            let request = self
                .builder
                .header(http::header::CONTENT_TYPE, mime::TEXT_PLAIN.as_ref())
                .body(axum::body::Body::from(text.into()))
                .unwrap();
            ResponseChecker::from(self.app.oneshot(request).await.unwrap())
        }

        /// Finishes building the request and sends it with a binary payload.
        pub async fn send_vec<B: Into<Vec<u8>>>(self, bytes: B) -> ResponseChecker {
            let request = self
                .builder
                .header(http::header::CONTENT_TYPE, mime::APPLICATION_OCTET_STREAM.as_ref())
                .body(axum::body::Body::from(bytes.into()))
                .unwrap();
            ResponseChecker::from(self.app.oneshot(request).await.unwrap())
        }

        /// Finishes building the request and sends it with a form encoded in the
        /// body as the payload.
        pub async fn send_form<T: Serialize>(self, request: T) -> ResponseChecker {
            let request = self
                .builder
                .header(http::header::CONTENT_TYPE, mime::APPLICATION_WWW_FORM_URLENCODED.as_ref())
                .body(axum::body::Body::from(serde_urlencoded::to_string(&request).unwrap()))
                .unwrap();
            ResponseChecker::from(self.app.oneshot(request).await.unwrap())
        }

        /// Finishes building the request and sends it with a JSON payload.
        pub async fn send_json<T: Serialize>(self, request: T) -> ResponseChecker {
            let request = self
                .builder
                .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                .body(axum::body::Body::from(serde_json::to_vec(&request).unwrap()))
                .unwrap();
            ResponseChecker::from(self.app.oneshot(request).await.unwrap())
        }
    }

    /// Type alias for the complex type returned by the `oneshot` function.
    type HttpResponse = hyper::Response<axum::body::Body>;

    /// Validator for the outcome of a request sent by a `OneShotBuilder`.
    #[must_use]
    pub struct ResponseChecker {
        /// Actual response that we received from the app.
        response: HttpResponse,

        /// Expected HTTP status code in the response above.
        exp_status: http::StatusCode,
    }

    impl From<HttpResponse> for ResponseChecker {
        fn from(response: HttpResponse) -> Self {
            Self { response, exp_status: http::StatusCode::OK }
        }
    }

    impl ResponseChecker {
        /// Sets the expected exit HTTP status to `status`.
        pub fn expect_status(mut self, status: http::StatusCode) -> Self {
            self.exp_status = status;
            self
        }

        /// Performs common validation operations on the response.
        pub fn verify(&self) {
            assert_eq!(self.exp_status, self.response.status());
        }

        /// Finishes checking the response and expects it to contain an empty body.
        pub async fn expect_empty(self) {
            self.verify();

            let body =
                axum::body::to_bytes(self.response.into_body(), MAX_BODY_SIZE).await.unwrap();
            let body = String::from_utf8(body.to_vec()).unwrap();
            assert!(body.is_empty(), "Body not empty; got {}", body);
        }

        /// Finishes checking the response and expects its body to be an `ErrorResponse` that
        /// matches `exp_re`.
        pub async fn expect_error(self, exp_re: &str) {
            self.verify();

            let body =
                axum::body::to_bytes(self.response.into_body(), MAX_BODY_SIZE).await.unwrap();
            let response: ErrorResponse = match serde_json::from_slice(&body) {
                Ok(response) => response,
                Err(e) => {
                    let body = String::from_utf8(body.to_vec()).unwrap();
                    panic!("Invalid error response due to {}; content was {}", e, body);
                }
            };
            if exp_re.is_empty() {
                assert!(
                    response.message.is_empty(),
                    "Response content '{:?}' is not empty",
                    response
                );
            } else {
                let re = regex::Regex::new(exp_re).unwrap();
                assert!(
                    re.is_match(&response.message),
                    "Response content '{:?}' does not match re '{}'",
                    response,
                    exp_re
                );
            }
        }

        /// Finishes checking the response and expects it to contain a valid JSON object of
        /// type `T`.
        pub async fn expect_json<T: DeserializeOwned>(self) -> T {
            self.verify();

            let body =
                axum::body::to_bytes(self.response.into_body(), MAX_BODY_SIZE).await.unwrap();
            serde_json::from_slice::<T>(&body).unwrap()
        }

        /// Finishes checking the response and expects its body to be valid UTF-8 and to match
        /// `exp_re`.
        pub async fn expect_text(self, exp_re: &str) {
            assert!(!exp_re.is_empty(), "Use expect_empty to validate empty responses");

            self.verify();

            let body =
                axum::body::to_bytes(self.response.into_body(), MAX_BODY_SIZE).await.unwrap();
            let body = String::from_utf8(body.to_vec()).unwrap();
            assert!(
                !body.contains("\"message\":"),
                "Use expect_error to validate errors wrapped in an ErrorResponse"
            );
            let re = regex::Regex::new(exp_re).unwrap();
            assert!(re.is_match(&body), "Body content '{}' does not match re '{}'", body, exp_re);
        }

        /// Finishes checking the response and returns the body of the response as UTF-8.
        pub async fn take_body_as_text(self) -> String {
            self.verify();

            let body =
                axum::body::to_bytes(self.response.into_body(), MAX_BODY_SIZE).await.unwrap();
            String::from_utf8(body.to_vec()).unwrap()
        }

        /// Finishes checking the response and returns the response itself for out of band
        /// validation of properties not supported by the `ResponseChecker`.
        pub async fn take_response(self) -> HttpResponse {
            self.verify();

            self.response
        }
    }

    /// Generates a test to verify that an API that expects JSON fails when it gets something else.
    #[macro_export]
    macro_rules! test_payload_must_be_json {
        ( $app:expr, $route:expr $(, $query:expr)? ) => {
            #[tokio::test]
            async fn test_payload_must_be_json() {
                // TODO(jmmv): These checks should be using expect_error instead of expect_text, but
                // JSON deserialization errors are not funneled through RestError.

                $crate::rest::testutils::OneShotBuilder::new($app, $route)
                    $( .with_query($query) )?
                    .send_text("this is not json")
                    .await
                    .expect_status(axum::http::StatusCode::UNSUPPORTED_MEDIA_TYPE)
                    .expect_text("Content-Type")
                    .await;

                $crate::rest::testutils::OneShotBuilder::new($app, $route)
                    $( .with_query($query) )?
                    .with_header(axum::http::header::CONTENT_TYPE, "application/json")
                    .send_text("this is not json")
                    .await
                    .expect_status(axum::http::StatusCode::BAD_REQUEST)
                    .expect_text("expected ident")
                    .await;
            }
        };
    }

    pub use test_payload_must_be_json;

    /// Generates a test to verify that an API that does not expect a payload fails as necessary.
    #[macro_export]
    macro_rules! test_payload_must_be_empty {
        ( $app:expr, $route:expr $(, $query:expr)? ) => {
            #[tokio::test]
            async fn test_payload_must_be_empty() {
                $crate::rest::testutils::OneShotBuilder::new($app, $route)
                    $( .with_query($query) )?
                    .send_text("should not be here")
                    .await
                    .expect_status(axum::http::StatusCode::PAYLOAD_TOO_LARGE)
                    .expect_error("should be empty")
                    .await;
            }
        };
    }

    pub use test_payload_must_be_empty;

    /// Generates a test to verify that an API that expects a form in its body fails when it gets
    /// something else.
    #[macro_export]
    macro_rules! test_payload_must_be_form {
        ( $app:expr, $route:expr $(, $query:expr)? ) => {
            #[tokio::test]
            async fn test_payload_must_be_form() {
                // TODO(jmmv): These checks should be using expect_error instead of expect_text, but
                // form deserialization errors are not funneled through RestError.

                $crate::rest::testutils::OneShotBuilder::new($app, $route)
                    $( .with_query($query) )?
                    .send_text("this is not a form")
                    .await
                    .expect_status(axum::http::StatusCode::UNSUPPORTED_MEDIA_TYPE)
                    .expect_text("Content-Type")
                    .await;

                $crate::rest::testutils::OneShotBuilder::new($app, $route)
                    $( .with_query($query) )?
                    .with_header(axum::http::header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .send_text("this is not a form")
                    .await
                    .expect_status(axum::http::StatusCode::UNPROCESSABLE_ENTITY)
                    .expect_text("missing field")
                    .await;
            }
        };
    }

    pub use test_payload_must_be_form;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_unique_header_missing() {
        let mut headers = HeaderMap::new();
        headers.append("ignore-me", "ignored".parse().unwrap());
        assert!(get_unique_header(&headers, "the-header").unwrap().is_none());
    }

    #[test]
    fn test_get_unique_header_one() {
        let mut headers = HeaderMap::new();
        headers.append("ignore-me", "ignored".parse().unwrap());
        headers.append("the-header", "foo".parse().unwrap());
        assert_eq!(b"foo", get_unique_header(&headers, "the-header").unwrap().unwrap().as_bytes());
    }

    #[test]
    fn test_get_unique_header_many() {
        let mut headers = HeaderMap::new();
        headers.append("the-header", "foo".parse().unwrap());
        headers.append("ignore-me", "ignored".parse().unwrap());
        headers.append("The-Header", "bar".parse().unwrap());
        assert_eq!(
            RestError::InvalidRequest(
                "Header the-header cannot have more than one value".to_owned()
            ),
            get_unique_header(&headers, "the-header").unwrap_err()
        );
    }
}
