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

//! Utilities to deal with HTTP authorization.

use crate::model::{AccessToken, Password};
use axum::Json;
use axum::body::Bytes;
use axum::extract::rejection::{JsonRejection, MissingJsonContentType};
use axum::extract::{FromRequest, Request};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose;
use http::header::{self, HeaderMap};
use http::{HeaderValue, StatusCode};
use iii_iv_core::model::Username;
use iii_iv_core::rest::{RestError, RestResult, get_unique_header};
use json_value_merge::Merge;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::str;

/// Returns true if the `headers` indicate a JSON content type.
///
/// This is the same logic implemented in the `axum::Json` handler.
fn is_json_content_type(headers: &HeaderMap) -> bool {
    let Ok(Some(content_type)) = get_unique_header(headers, header::CONTENT_TYPE.as_str()) else {
        return false;
    };

    let Ok(content_type) = content_type.to_str() else {
        return false;
    };

    let Ok(mime) = content_type.parse::<mime::Mime>() else {
        return false;
    };

    mime.type_() == "application"
        && (mime.subtype() == "json" || mime.suffix().is_some_and(|name| name == "json"))
}

/// Multipart JSON Extractor / Response.
///
/// When used as an extractor, this processes the response into two types.  The two types should
/// be structs and should have non-overlapping fields.
///
/// When used as a response, this combines the two types, which should be structs, into a single
/// JSON dictionary.  If the structs have overlapping keys, the behavior of the resulting JSON
/// is undefined.
#[derive(Debug, Clone, Copy, Default)]
#[must_use]
pub(crate) struct JsonMultipart<T1, T2>(pub T1, pub T2);

impl<T1, T2, S> FromRequest<S> for JsonMultipart<T1, T2>
where
    T1: DeserializeOwned,
    T2: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = JsonRejection;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        if !is_json_content_type(req.headers()) {
            return Err(JsonRejection::MissingJsonContentType(MissingJsonContentType::default()));
        }

        let bytes = Bytes::from_request(req, state).await?;
        let Json(part1) = Json::from_bytes(&bytes)?;
        let Json(part2) = Json::from_bytes(&bytes)?;
        Ok(Self(part1, part2))
    }
}

impl<T1, T2> IntoResponse for JsonMultipart<T1, T2>
where
    T1: Serialize,
    T2: Serialize,
{
    fn into_response(self) -> Response {
        let result = serde_json::to_value(&self.0).and_then(|mut v1| {
            serde_json::to_value(&self.1).map(|v2| {
                v1.merge(&v2);
                v1
            })
        });

        match result {
            Ok(merged) => Json(merged).into_response(),
            Err(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(header::CONTENT_TYPE, HeaderValue::from_static(mime::TEXT_PLAIN_UTF_8.as_ref()))],
                err.to_string(),
            )
                .into_response(),
        }
    }
}

/// Validates that the `Authorization` HTTP header contains a textual payload for the
/// `exp_scheme` scheme and returns it.
fn get_authorization_header<'a>(
    headers: &'a HeaderMap,
    exp_scheme: &'static str,
    exp_realm: &'static str,
) -> RestResult<&'a str> {
    let authz = match get_unique_header(headers, "Authorization") {
        Ok(Some(value)) => value,
        Ok(None) => {
            return Err(RestError::Unauthorized {
                scheme: exp_scheme,
                realm: exp_realm,
                message: "Missing Authorization header".to_owned(),
            });
        }
        Err(e) => {
            return Err(RestError::Unauthorized {
                scheme: exp_scheme,
                realm: exp_realm,
                message: e.to_string(),
            });
        }
    };

    let authz = match authz.to_str() {
        Ok(value) => value,
        Err(e) => {
            return Err(RestError::Unauthorized {
                scheme: exp_scheme,
                realm: exp_realm,
                message: format!("Bad encoding in Authorization header: {}", e),
            });
        }
    };

    let mut fields = authz.splitn(2, ' ');
    let scheme = match fields.next() {
        Some(s) if !s.is_empty() => s,
        _ => {
            return Err(RestError::Unauthorized {
                scheme: exp_scheme,
                realm: exp_realm,
                message: "Bad Authorization header: missing scheme".to_owned(),
            });
        }
    };
    let payload = match fields.next() {
        Some(s) => s,
        None => {
            return Err(RestError::Unauthorized {
                scheme: exp_scheme,
                realm: exp_realm,
                message: "Bad Authorization header: missing payload".to_owned(),
            });
        }
    };
    assert!(fields.next().is_none());

    if scheme != exp_scheme {
        return Err(RestError::Unauthorized {
            scheme: exp_scheme,
            realm: exp_realm,
            message: "Unsupported scheme".to_owned(),
        });
    }

    Ok(payload)
}

/// Assumes that the `headers` contain basic authentication credentials and extracts them.
pub fn get_basic_auth(
    headers: &HeaderMap,
    exp_realm: &'static str,
) -> RestResult<(Username, Password)> {
    let base64_payload = get_authorization_header(headers, "Basic", exp_realm)?;

    let payload = match general_purpose::STANDARD.decode(base64_payload) {
        Ok(bytes) => bytes,
        Err(e) => {
            return Err(RestError::Unauthorized {
                scheme: "Basic",
                realm: exp_realm,
                message: format!("Bad base64 encoding in payload: {}", e),
            });
        }
    };

    // Both the username and the password have to be strings, so it is easier to convert the
    // payload first in one go instead of doing two conversion after splitting the bytes.
    let payload = match String::from_utf8(payload) {
        Ok(s) => s,
        Err(e) => {
            return Err(RestError::Unauthorized {
                scheme: "Basic",
                realm: exp_realm,
                message: format!("Bad UTF-8 encoding in payload: {}", e),
            });
        }
    };

    let split = match payload.chars().position(|x| x == ':') {
        Some(index) => index,
        None => {
            return Err(RestError::Unauthorized {
                scheme: "Basic",
                realm: exp_realm,
                message: "Bad content".to_owned(),
            });
        }
    };

    let (username, password) = payload.split_at(split);
    let password = &password[1..];

    Ok((Username::new(username)?, Password::new(password)?))
}

/// Checks if the request has an authorization header.
pub fn has_bearer_auth(headers: &HeaderMap, exp_realm: &'static str) -> RestResult<bool> {
    match get_unique_header(headers, "Authorization") {
        Ok(Some(_)) => Ok(true),
        Ok(None) => Ok(false),
        Err(e) => Err(RestError::Unauthorized {
            scheme: "Bearer",
            realm: exp_realm,
            message: e.to_string(),
        }),
    }

    // TODO(jmmv): This isn't completely correct because we don't validate that the header contains
    // a bearer token if the header is present.
}

/// Assumes that the `headers` contain a bearer access token and extracts it.
pub fn get_bearer_auth(headers: &HeaderMap, exp_realm: &'static str) -> RestResult<AccessToken> {
    let payload = get_authorization_header(headers, "Bearer", exp_realm)?;
    match AccessToken::new(payload) {
        Ok(token) => Ok(token),
        Err(e) => Err(RestError::Unauthorized {
            scheme: "Bearer",
            realm: exp_realm,
            message: e.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::password;
    use axum::body::{self, Body};
    use http::{HeaderValue, Request};
    use serde::Deserialize;

    #[derive(Serialize)]
    struct EmptyDict {}

    #[derive(Debug, Deserialize, PartialEq, Serialize)]
    struct Dict1 {
        #[serde(default)]
        field1: u32,
        #[serde(default)]
        field2: u32,
    }

    #[derive(Debug, Deserialize, PartialEq, Serialize)]
    struct Dict2 {
        #[serde(default)]
        field3: u32,
        #[serde(default)]
        field4: u32,
    }

    #[tokio::test]
    async fn test_json_multipart_from_request_no_fields() {
        let request = Request::builder()
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .body(Body::from(r#"{}"#))
            .unwrap();
        let multipart: JsonMultipart<Dict1, Dict2> =
            JsonMultipart::from_request(request, &()).await.unwrap();
        assert_eq!(Dict1 { field1: 0, field2: 0 }, multipart.0);
        assert_eq!(Dict2 { field3: 0, field4: 0 }, multipart.1);
    }

    #[tokio::test]
    async fn test_json_multipart_from_request_some_fields() {
        let request = Request::builder()
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .body(Body::from(r#"{"field2":2,"field4":4}"#))
            .unwrap();
        let multipart: JsonMultipart<Dict1, Dict2> =
            JsonMultipart::from_request(request, &()).await.unwrap();
        assert_eq!(Dict1 { field1: 0, field2: 2 }, multipart.0);
        assert_eq!(Dict2 { field3: 0, field4: 4 }, multipart.1);
    }

    #[tokio::test]
    async fn test_json_multipart_from_request_missing_content_type() {
        let request = Request::builder().body(Body::from(r#"{}"#)).unwrap();
        let result: Result<JsonMultipart<Dict1, Dict2>, JsonRejection> =
            JsonMultipart::from_request(request, &()).await;
        assert!(matches!(result, Err(JsonRejection::MissingJsonContentType(_))));
    }

    #[tokio::test]
    async fn test_json_multipart_from_request_invalid_json() {
        let request = Request::builder()
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .body(Body::from(r#"not valid json"#))
            .unwrap();
        let result: Result<JsonMultipart<Dict1, Dict2>, JsonRejection> =
            JsonMultipart::from_request(request, &()).await;
        assert!(result.is_err());
    }

    async fn do_json_multipart_into_response_test(response: Response, exp_json: &str) {
        let content_type =
            get_unique_header(response.headers(), header::CONTENT_TYPE.as_str()).unwrap().unwrap();
        assert_eq!(mime::APPLICATION_JSON.as_ref(), content_type);

        let body = String::from_utf8(
            body::to_bytes(response.into_body(), usize::MAX).await.unwrap().to_vec(),
        )
        .unwrap();
        assert_eq!(exp_json, body);
    }

    #[tokio::test]
    async fn test_json_multipart_into_response_only_part1() {
        do_json_multipart_into_response_test(
            JsonMultipart(Dict1 { field1: 1, field2: 2 }, EmptyDict {}).into_response(),
            r#"{"field1":1,"field2":2}"#,
        )
        .await;
    }

    #[tokio::test]
    async fn test_json_multipart_into_response_only_part2() {
        do_json_multipart_into_response_test(
            JsonMultipart(EmptyDict {}, Dict1 { field1: 1, field2: 2 }).into_response(),
            r#"{"field1":1,"field2":2}"#,
        )
        .await;
    }

    #[tokio::test]
    async fn test_json_multipart_into_response_both_parts() {
        do_json_multipart_into_response_test(
            JsonMultipart(Dict1 { field1: 1, field2: 2 }, Dict2 { field3: 3, field4: 4 })
                .into_response(),
            r#"{"field1":1,"field2":2,"field3":3,"field4":4}"#,
        )
        .await;
    }

    #[test]
    fn test_get_basic_auth_ok() {
        let mut headers = HeaderMap::new();
        headers.append(
            "Authorization",
            format!("Basic {}", general_purpose::STANDARD.encode("hello:bye")).parse().unwrap(),
        );
        assert_eq!(
            (Username::from("hello"), password!("bye")),
            get_basic_auth(&headers, "the-realm").unwrap()
        );
    }

    /// Runs `get_basic_auth` with an invalid set of header `values` and ensures that the call
    /// falls with an `Unauthorized` error that contains `exp_error` in the failure message.
    fn do_get_basic_auth_error_test(exp_error: &str, values: &[&[u8]]) {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append("Authorization", HeaderValue::from_bytes(value).unwrap());
        }
        match get_basic_auth(&headers, "the-realm") {
            Err(ref e @ RestError::Unauthorized { scheme, realm, ref message }) => {
                assert_eq!("Basic", scheme);
                assert_eq!("the-realm", realm);
                assert!(
                    message.contains(exp_error),
                    "message '{}' does not contain '{}'",
                    message,
                    exp_error
                );

                // Make sure that the formatted error contains the most descriptive part of the
                // problem description.
                assert!(e.to_string().contains(exp_error));
            }
            e => panic!("{:?}", e),
        }
    }

    #[test]
    fn test_get_basic_auth_missing() {
        do_get_basic_auth_error_test("Missing Authorization", &[]);
    }

    #[test]
    fn test_get_basic_auth_duplicate() {
        do_get_basic_auth_error_test("cannot have more than one value", &[b"abc", b"def"]);
    }

    #[test]
    fn test_get_basic_auth_invalid_encoding() {
        do_get_basic_auth_error_test("Bad encoding in Authorization", &[b"bad \xc5 bytes"]);
    }

    #[test]
    fn test_get_basic_auth_missing_scheme() {
        do_get_basic_auth_error_test("missing scheme", &[b""]);
    }

    #[test]
    fn test_get_basic_auth_missing_payload() {
        do_get_basic_auth_error_test("missing payload", &[b"Basic"]);
    }

    #[test]
    fn test_get_basic_auth_unsupported_scheme() {
        do_get_basic_auth_error_test("Unsupported scheme", &[b"Bearer 123"]);
    }

    #[test]
    fn test_get_basic_auth_invalid_payload_base64() {
        do_get_basic_auth_error_test("Bad base64 encoding", &[b"Basic xxx"]);
    }

    #[test]
    fn test_get_basic_auth_invalid_payload_utf8() {
        let mut value = vec![];
        value.extend_from_slice(b"Basic ");
        value.extend_from_slice(general_purpose::STANDARD.encode(b"bad \xc5 bytes").as_bytes());
        do_get_basic_auth_error_test("Bad UTF-8 encoding in payload", &[&value]);
    }

    #[test]
    fn test_get_basic_auth_bad_content() {
        let mut value = vec![];
        value.extend_from_slice(b"Basic ");
        value.extend_from_slice(general_purpose::STANDARD.encode("username-password").as_bytes());
        do_get_basic_auth_error_test("Bad content", &[&value]);
    }

    #[test]
    fn test_has_bearer_auth_ok() {
        let token = AccessToken::generate();

        let mut headers = HeaderMap::new();
        headers.append("Authorization", format!("Bearer {}", token.as_str()).parse().unwrap());
        assert!(has_bearer_auth(&headers, "the-realm").unwrap());
    }

    #[test]
    fn test_has_bearer_auth_missing() {
        let mut headers = HeaderMap::new();
        headers.append("foo", "bar".parse().unwrap());
        assert!(!has_bearer_auth(&headers, "the-realm").unwrap());
    }

    #[test]
    fn test_get_bearer_auth_ok() {
        let token = AccessToken::generate();

        let mut headers = HeaderMap::new();
        headers.append("Authorization", format!("Bearer {}", token.as_str()).parse().unwrap());
        assert_eq!(token, get_bearer_auth(&headers, "the-realm").unwrap());
    }

    /// Runs `get_bearer_auth` with an invalid set of header `values` and ensures that the call
    /// falls with an `Unauthorized` error that contains `exp_error` in the failure message.
    fn do_get_bearer_auth_error_test(exp_error: &str, values: &[&[u8]]) {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append("Authorization", HeaderValue::from_bytes(value).unwrap());
        }
        match get_bearer_auth(&headers, "the-realm") {
            Err(ref e @ RestError::Unauthorized { scheme, realm, ref message }) => {
                assert_eq!("Bearer", scheme);
                assert_eq!("the-realm", realm);
                assert!(
                    message.contains(exp_error),
                    "message '{}' does not contain '{}'",
                    message,
                    exp_error
                );

                // Make sure that the formatted error contains the most descriptive part of the
                // problem description.
                assert!(e.to_string().contains(exp_error));
            }
            e => panic!("{:?}", e),
        }
    }

    #[test]
    fn test_get_bearer_auth_missing() {
        do_get_bearer_auth_error_test("Missing Authorization", &[]);
    }

    #[test]
    fn test_get_bearer_auth_duplicate() {
        do_get_bearer_auth_error_test("cannot have more than one value", &[b"abc", b"def"]);
    }

    #[test]
    fn test_get_bearer_auth_invalid_encoding() {
        do_get_bearer_auth_error_test("Bad encoding in Authorization", &[b"bad \xc5 bytes"]);
    }

    #[test]
    fn test_get_bearer_auth_missing_scheme() {
        do_get_bearer_auth_error_test("missing scheme", &[b""]);
    }

    #[test]
    fn test_get_bearer_auth_missing_payload() {
        do_get_bearer_auth_error_test("missing payload", &[b"Bearer"]);
    }

    #[test]
    fn test_get_bearer_auth_unsupported_scheme() {
        do_get_bearer_auth_error_test("Unsupported scheme", &[b"Basic 123"]);
    }

    #[test]
    fn test_get_bearer_auth_invalid_payload_base64() {
        do_get_bearer_auth_error_test("Invalid access token", &[b"Bearer xxx"]);
    }
}
