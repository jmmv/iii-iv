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

//! The `BaseUrls` type.

use crate::env::get_optional_var;
use crate::env::get_required_var;
use url::Url;

/// Common error message for URLs built via hardcoded values.
const URL_MUST_BE_VALID: &str = "URLs built in-process must be valid";

/// Checks if `base` has the right format to be a base URL and returns an error if it is not.
fn ensure_valid_base(base: &Url) -> Result<(), String> {
    if !base.join("x").unwrap().as_str().starts_with(base.as_str()) {
        return Err(format!("URL '{}' cannot be a base: missing trailing slash", base));
    }
    Ok(())
}

/// Contains the backend and frontend base URLs of a service and allows building absolute URLs
/// within either.
///
/// In the general "production" case, a service will run with the backend address pointing at
/// itself and with the frontend address being unset, assuming that the backend is responsible
/// for serving the files of the frontend.
///
/// The separation of backend and frontend comes in handy when both are served from different
/// servers though, which is a common workflow during development.  For example, the backend
/// may be started and left running while the developer iterates on the frontend code using
/// the dev server of whichever framework is in use.
#[cfg_attr(test, derive(Debug, Eq, PartialEq))]
pub struct BaseUrls {
    /// The base URL to the backend service (ourselves).
    backend: Url,

    /// The base URL to the frontend service.  Should be `None` if the frontend is served by us.
    frontend: Option<Url>,
}

impl BaseUrls {
    /// Creates a set of base URLs from already-parsed URLs.
    pub fn new(backend: Url, frontend: Option<Url>) -> Result<Self, String> {
        ensure_valid_base(&backend)?;
        if let Some(frontend) = frontend.as_ref() {
            ensure_valid_base(frontend)?;
        }
        Ok(Self { backend, frontend })
    }

    /// Creates a set of base URLs from environment variables whose name is prefixed with the
    /// given `prefix`.
    ///
    /// This will use variables such as `<prefix>_BACKEND_BASE_URL`, `<prefix>_FRONTEND_BASE_URL`.
    pub fn from_env(prefix: &str) -> Result<Self, String> {
        let backend = get_required_var::<Url>(prefix, "BACKEND_BASE_URL")?;
        let frontend = get_optional_var::<Url>(prefix, "FRONTEND_BASE_URL")?;
        Self::new(backend, frontend)
    }

    /// Creates a set of base URLs from fixed strings, which must represent valid URLs.
    #[cfg(any(test, feature = "testutils"))]
    pub fn from_strs(backend: &'static str, frontend: Option<&'static str>) -> Self {
        let backend = Url::parse(backend).unwrap();
        let frontend = frontend.map(|s| Url::parse(s).unwrap());
        Self::new(backend, frontend).unwrap()
    }

    /// Generates a URL to the backend given a `path`, which must be relative.  The `path` can be
    /// empty to obtain a reference to the root.
    pub fn make_backend_url(&self, path: &str) -> Url {
        assert!(!path.starts_with('/'));
        self.backend.join(path).expect(URL_MUST_BE_VALID)
    }

    /// Generates a URL to the frontend given a `path`, which must be relative.  The `path` can be
    /// empty to obtain a reference to the root.
    pub fn make_frontend_url(&self, path: &str) -> Url {
        assert!(!path.starts_with('/'));
        match self.frontend.as_ref() {
            Some(base) => base.join(path).expect(URL_MUST_BE_VALID),
            None => self.backend.join(path).expect(URL_MUST_BE_VALID),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Constructs a URL from a valid raw string for testing purposes.
    fn url(s: &'static str) -> Url {
        Url::parse(s).unwrap()
    }

    #[test]
    pub fn test_ensure_valid_base() {
        ensure_valid_base(&url("http://example.com")).unwrap();
        ensure_valid_base(&url("http://example.com/")).unwrap();
        ensure_valid_base(&url("http://example.com:1234")).unwrap();
        ensure_valid_base(&url("http://example.com:1234/")).unwrap();

        ensure_valid_base(&url("http://example.com/foo/")).unwrap();
        ensure_valid_base(&url("http://example.com:1234/foo/")).unwrap();

        ensure_valid_base(&url("http://example.com:1234/foo")).unwrap_err();
    }

    #[test]
    pub fn test_new_validates_backend() {
        assert!(
            BaseUrls::new(url("http://example.com/bad"), None)
                .unwrap_err()
                .contains("/bad' cannot be a base")
        );
    }

    #[test]
    pub fn test_new_validates_frontend() {
        assert!(
            BaseUrls::new(url("http://example.com/ok/"), Some(url("http://example.com/bad")))
                .unwrap_err()
                .contains("/bad' cannot be a base")
        );
    }

    #[test]
    pub fn test_from_env_required_present() {
        let overrides = [
            ("TEST_BACKEND_BASE_URL", Some("https://backend.example.com/api/")),
            ("TEST_FRONTEND_BASE_URL", None::<&str>),
        ];
        temp_env::with_vars(overrides, || {
            let opts = BaseUrls::from_env("TEST").unwrap();
            assert_eq!(
                BaseUrls { backend: url("https://backend.example.com/api/"), frontend: None },
                opts
            );
        });
    }

    #[test]
    pub fn test_from_env_all_present() {
        let overrides = [
            ("TEST_BACKEND_BASE_URL", Some("https://backend.example.com/api/")),
            ("TEST_FRONTEND_BASE_URL", Some("https://frontend.example.com/")),
        ];
        temp_env::with_vars(overrides, || {
            let opts = BaseUrls::from_env("TEST").unwrap();
            assert_eq!(
                BaseUrls {
                    backend: url("https://backend.example.com/api/"),
                    frontend: Some(url("https://frontend.example.com/")),
                },
                opts
            );
        });
    }

    #[test]
    pub fn test_from_env_missing() {
        temp_env::with_var_unset("TEST_BACKEND_BASE_URL", || {
            let err = BaseUrls::from_env("TEST").unwrap_err();
            assert!(err.contains("TEST_BACKEND_BASE_URL not present"));
        });
    }

    #[test]
    pub fn test_from_env_calls_new_for_validation() {
        let overrides = [("TEST_BACKEND_BASE_URL", Some("https://example.com/api"))];
        temp_env::with_vars(overrides, || {
            assert!(BaseUrls::from_env("TEST").unwrap_err().contains("missing trailing slash"));
        });
    }

    #[test]
    pub fn test_make_backend_url() {
        let base_urls = BaseUrls::from_strs("http://backend.example.com/api/", None);

        assert_eq!(url("http://backend.example.com/api/"), base_urls.make_backend_url(""));
        assert_eq!(url("http://backend.example.com/api/foo"), base_urls.make_backend_url("foo"));
    }

    #[test]
    pub fn test_make_frontend_url_same_as_backend() {
        let base_urls = BaseUrls::from_strs("http://backend.example.com/api/", None);

        assert_eq!(url("http://backend.example.com/api/"), base_urls.make_frontend_url(""));
        assert_eq!(url("http://backend.example.com/api/foo"), base_urls.make_frontend_url("foo"));
    }

    #[test]
    pub fn test_make_frontend_url_different_from_backend() {
        let base_urls = BaseUrls::from_strs(
            "http://backend.example.com/api/",
            Some("http://frontend.example.com"),
        );

        assert_eq!(url("http://frontend.example.com/"), base_urls.make_frontend_url(""));
        assert_eq!(url("http://frontend.example.com/foo"), base_urls.make_frontend_url("foo"));
    }
}
