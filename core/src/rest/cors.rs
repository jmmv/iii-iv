// III-IV
// Copyright 2025 Julio Merino
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

//! Utilities to configure CORS for the REST service.

use crate::env::{Result, get_optional_var};
use crate::rest::BaseUrls;
use http::{HeaderName, HeaderValue, Method, header};
use tower_http::cors::{AllowOrigin, CorsLayer};

/// Builder for a `CorsLayer` to merge settings form various sources.
//
// The various `Vec`s in here would be better represented as `HashSet`s.  Unfortunately, that
// makes testing difficult because we can't place restrictions on ordering and some of the values
// we store do not derive `Ord`.  Using `Vec`s keeps order stable, albeit at the expense of an
// inconsequential inefficiency during construction.
struct CorsLayerBuilder {
    /// List of allowed origins.
    allow_origin: Vec<HeaderValue>,

    /// Whether credentials are allowed or not.
    allow_credentials: bool,

    /// List of allowed methods.
    allow_methods: Vec<Method>,

    /// List of allowed headers.
    allow_headers: Vec<HeaderName>,
}

impl CorsLayerBuilder {
    /// Instantiates a CORS layer builder from environment variables.
    ///
    /// The user configuration will be read from the environment via variables such as
    /// `<prefix>_CORS_ALLOW_ORIGIN`, `<prefix>_CORS_ALLOW_CREDENTIALS`,
    /// `<prefix>_CORS_ALLOW_METHODS`, and `<prefix>_CORS_ALLOW_HEADERS`.
    fn from_env(prefix: &str) -> Result<Self> {
        let mut allow_origin = vec![];
        if let Some(env_str) = get_optional_var::<String>(prefix, "CORS_ALLOW_ORIGIN")? {
            for s in env_str.split(',') {
                let origin = match s.parse() {
                    Ok(origin) => origin,
                    Err(e) => {
                        return Err(format!(
                            "Invalid value in {}_CORS_ALLOW_ORIGIN: {}",
                            prefix, e
                        ));
                    }
                };
                allow_origin.push(origin);
            }
        }

        let allow_credentials =
            get_optional_var::<bool>(prefix, "CORS_ALLOW_CREDENTIALS")?.unwrap_or(false);

        let mut allow_methods = vec![];
        if let Some(env_str) = get_optional_var::<String>(prefix, "CORS_ALLOW_METHODS")? {
            for s in env_str.split(',') {
                let method = match s.parse() {
                    Ok(method) => method,
                    Err(e) => {
                        return Err(format!(
                            "Invalid value in {}_CORS_ALLOW_METHODS: {}",
                            prefix, e
                        ));
                    }
                };
                allow_methods.push(method);
            }
        }

        let mut allow_headers = vec![];
        if let Some(env_str) = get_optional_var::<String>(prefix, "CORS_ALLOW_HEADERS")? {
            for s in env_str.split(',') {
                let header = match s.parse() {
                    Ok(header) => header,
                    Err(e) => {
                        return Err(format!(
                            "Invalid value in {}_CORS_ALLOW_HEADERS: {}",
                            prefix, e
                        ));
                    }
                };
                allow_headers.push(header);
            }
        }

        Ok(Self { allow_origin, allow_credentials, allow_methods, allow_headers })
    }

    /// Modifies the CORS layer builder to allow connections from the `base_urls` frontend, if
    /// necessary because it lives in a separate URL than the backend.
    fn allow_base_urls(mut self, base_urls: &BaseUrls) -> Result<Self> {
        let backend_root = base_urls.make_backend_url("");
        let frontend_root = base_urls.make_frontend_url("");
        if backend_root == frontend_root {
            return Ok(self);
        }

        let s = frontend_root.as_str().trim_end_matches('/');
        let origin = match s.parse() {
            Ok(origin) => origin,
            Err(e) => return Err(format!("Invalid value in base URLs: {}", e)),
        };
        if !self.allow_origin.contains(&origin) {
            self.allow_origin.push(origin);
        }

        self.allow_credentials = true;

        for method in [Method::DELETE, Method::GET, Method::PATCH, Method::POST] {
            if !self.allow_methods.contains(&method) {
                self.allow_methods.push(method);
            }
        }

        if !self.allow_headers.contains(&header::CONTENT_TYPE) {
            self.allow_headers.push(header::CONTENT_TYPE);
        }

        Ok(self)
    }

    /// Creates the CORS layer.
    fn build(self) -> CorsLayer {
        let mut layer = CorsLayer::new();
        if !self.allow_origin.is_empty() {
            if self.allow_origin == ["*"] {
                layer = layer.allow_origin(AllowOrigin::any());
            } else {
                layer = layer.allow_origin(self.allow_origin);
            }
        }
        if self.allow_credentials {
            layer = layer.allow_credentials(true);
        }
        if !self.allow_methods.is_empty() {
            layer = layer.allow_methods(self.allow_methods);
        }
        if !self.allow_headers.is_empty() {
            layer = layer.allow_headers(self.allow_headers);
        }
        layer
    }
}

/// Instantiates a CORS layer to support connections from the frontend at `BaseUrls` and any
/// user-specified settings provided in the environment via variables such as
/// `<prefix>_CORS_ALLOW_ORIGIN`, `<prefix>_CORS_ALLOW_CREDENTIALS`,
/// `<prefix>_CORS_ALLOW_METHODS`, and `<prefix>_CORS_ALLOW_HEADERS`.
pub fn new_cors_layer(prefix: &str, base_urls: &BaseUrls) -> Result<CorsLayer> {
    Ok(CorsLayerBuilder::from_env(prefix)?.allow_base_urls(base_urls)?.build())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    /// Introspects `layer` to verify that it contains the `expected` origins.
    fn assert_origin(expected: &[&str], layer: &CorsLayer) {
        // This is terrible but `CorsLayer` does not allow peeking into its contents, so...
        let dbg = format!("{:?}", layer);
        let exp_dbg = if expected == ["*"] {
            "allow_origin: Const(\"*\")".to_owned()
        } else {
            format!("allow_origin: List({:?})", expected)
        };
        assert!(dbg.contains(&exp_dbg), "Substring '{}' not found in '{}'", exp_dbg, dbg);
    }

    /// Introspects `layer` to verify that it contains the `expected` credentials.
    fn assert_credentials(expected: bool, layer: &CorsLayer) {
        // This is terrible but `CorsLayer` does not allow peeking into its contents, so...
        let dbg = format!("{:?}", layer);
        let exp_dbg = if expected { "allow_credentials: Yes" } else { "allow_credentials: No" };
        assert!(dbg.contains(exp_dbg), "Substring '{}' not found in '{}'", exp_dbg, dbg);
    }

    /// Introspects `layer` to verify that it contains the `expected` methods.
    fn assert_methods(expected: Option<&str>, layer: &CorsLayer) {
        // This is terrible but `CorsLayer` does not allow peeking into its contents, so...
        let dbg = format!("{:?}", layer);
        let exp_dbg = format!("allow_methods: Const({:?})", expected);
        assert!(dbg.contains(&exp_dbg), "Substring '{}' not found in '{}'", exp_dbg, dbg);
    }

    /// Introspects `layer` to verify that it contains the `expected` headers.
    fn assert_headers(expected: Option<&str>, layer: &CorsLayer) {
        // This is terrible but `CorsLayer` does not allow peeking into its contents, so...
        let dbg = format!("{:?}", layer);
        let exp_dbg = format!("allow_headers: Const({:?})", expected);
        assert!(dbg.contains(&exp_dbg), "Substring '{}' not found in '{}'", exp_dbg, dbg);
    }

    #[test]
    #[serial(PREFIX_CORS)]
    fn test_new_cors_layer_nothing() {
        let overrides: [(&str, Option<&str>); 4] = [
            ("PREFIX_CORS_ALLOW_ORIGIN", None),
            ("PREFIX_CORS_ALLOW_CREDENTIALS", None),
            ("PREFIX_CORS_ALLOW_METHODS", None),
            ("PREFIX_CORS_ALLOW_HEADERS", None),
        ];
        temp_env::with_vars(overrides, || {
            let base_urls = BaseUrls::from_strs("https://backend.example.com", None);
            let layer = new_cors_layer("PREFIX", &base_urls).unwrap();
            assert_origin(&[], &layer);
            assert_credentials(false, &layer);
            assert_methods(None, &layer);
            assert_headers(None, &layer);
        });
    }

    #[test]
    #[serial(PREFIX_CORS)]
    fn test_new_cors_layer_only_env() {
        let overrides = [
            ("PREFIX_CORS_ALLOW_ORIGIN", Some("https://a.example.com,http://b.example.com")),
            ("PREFIX_CORS_ALLOW_CREDENTIALS", Some("true")),
            ("PREFIX_CORS_ALLOW_METHODS", Some("PUT,PATCH")),
            ("PREFIX_CORS_ALLOW_HEADERS", Some("X-Custom")),
        ];
        temp_env::with_vars(overrides, || {
            let base_urls = BaseUrls::from_strs("https://backend.example.com", None);
            let layer = new_cors_layer("PREFIX", &base_urls).unwrap();
            assert_origin(&["https://a.example.com", "http://b.example.com"], &layer);
            assert_credentials(true, &layer);
            assert_methods(Some("PUT,PATCH"), &layer);
            assert_headers(Some("x-custom"), &layer);
        });
    }

    #[test]
    #[serial(PREFIX_CORS)]
    fn test_new_cors_layer_only_frontend() {
        let overrides: [(&str, Option<&str>); 4] = [
            ("PREFIX_CORS_ALLOW_ORIGIN", None),
            ("PREFIX_CORS_ALLOW_CREDENTIALS", None),
            ("PREFIX_CORS_ALLOW_METHODS", None),
            ("PREFIX_CORS_ALLOW_HEADERS", None),
        ];
        temp_env::with_vars(overrides, || {
            let base_urls = BaseUrls::from_strs(
                "https://backend.example.com",
                Some("https://frontend.example.com:1234/foo/"),
            );
            let layer = new_cors_layer("PREFIX", &base_urls).unwrap();
            assert_origin(&["https://frontend.example.com:1234/foo"], &layer);
            assert_credentials(true, &layer);
            assert_methods(Some("DELETE,GET,PATCH,POST"), &layer);
            assert_headers(Some("content-type"), &layer);
        });
    }

    #[test]
    #[serial(PREFIX_CORS)]
    fn test_new_cors_layer_env_and_frontend() {
        let overrides = [
            ("PREFIX_CORS_ALLOW_ORIGIN", Some("https://var.example.com")),
            ("PREFIX_CORS_ALLOW_CREDENTIALS", Some("false")),
            ("PREFIX_CORS_ALLOW_METHODS", Some("PUT")),
            ("PREFIX_CORS_ALLOW_HEADERS", Some("X-Custom")),
        ];
        temp_env::with_vars(overrides, || {
            let base_urls = BaseUrls::from_strs(
                "https://backend.example.com",
                Some("https://frontend.example.com:1234/foo/"),
            );
            let layer = new_cors_layer("PREFIX", &base_urls).unwrap();
            assert_origin(
                &["https://var.example.com", "https://frontend.example.com:1234/foo"],
                &layer,
            );
            assert_credentials(true, &layer);
            assert_methods(Some("PUT,DELETE,GET,PATCH,POST"), &layer);
            assert_headers(Some("x-custom,content-type"), &layer);
        });
    }

    #[test]
    #[serial(PREFIX_CORS)]
    fn test_new_cors_layer_all_origins() {
        let overrides = [
            ("PREFIX_CORS_ALLOW_ORIGIN", Some("*")),
            ("PREFIX_CORS_ALLOW_CREDENTIALS", None),
            ("PREFIX_CORS_ALLOW_METHODS", None),
            ("PREFIX_CORS_ALLOW_HEADERS", None),
        ];
        temp_env::with_vars(overrides, || {
            let base_urls = BaseUrls::from_strs("https://backend.example.com", None);
            let layer = new_cors_layer("PREFIX", &base_urls).unwrap();
            assert_origin(&["*"], &layer);
            assert_credentials(false, &layer);
            assert_methods(None, &layer);
            assert_headers(None, &layer);
        });
    }
}
