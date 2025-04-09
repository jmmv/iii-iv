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
use base64::Engine;
use base64::engine::general_purpose;
use http::header::HeaderMap;
use iii_iv_core::model::Username;
use iii_iv_core::rest::{RestError, RestResult, get_unique_header};
use std::str;

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
    use http::HeaderValue;

    #[test]
    fn test_get_basic_auth_ok() {
        let mut headers = HeaderMap::new();
        headers.append(
            "Authorization",
            format!("Basic {}", general_purpose::STANDARD.encode("hello:bye")).parse().unwrap(),
        );
        assert_eq!(
            (Username::from("hello"), Password::from("bye")),
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
