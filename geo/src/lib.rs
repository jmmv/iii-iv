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

//! APIs to access geo-location information.

// Keep these in sync with other top-level files.
#![warn(anonymous_parameters, bad_style, clippy::missing_docs_in_private_items, missing_docs)]
#![warn(unused, unused_extern_crates, unused_import_braces, unused_qualifications)]
#![warn(unsafe_code)]

use async_trait::async_trait;
use serde::de::Visitor;
use serde::{Deserialize, Serialize};
use std::io;
use std::net::IpAddr;

mod azure;
pub use azure::{AzureGeoLocator, AzureGeoLocatorOptions};
#[cfg(any(test, feature = "testutils"))]
mod mock;
#[cfg(any(test, feature = "testutils"))]
pub use mock::MockGeoLocator;

/// Result type for this module.
type GeoResult<T> = io::Result<T>;

/// Representation of a two-letter country ISO code.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct CountryIsoCode(String);

impl CountryIsoCode {
    /// Creates a new country ISO code after validating that it is OK.
    pub fn new<S: Into<String>>(code: S) -> GeoResult<Self> {
        let code = code.into();
        if code.len() != 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Country code {} does not have length 2", code),
            ));
        }
        Ok(Self(code.to_uppercase()))
    }

    /// Returns the country ISO code as a uppercase string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Visitor to deserialize a `CountryIsoCode` from a string.
struct CountryIsoCodeVisitor;

impl<'de> Visitor<'de> for CountryIsoCodeVisitor {
    type Value = CountryIsoCode;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str(r#"a two-letter country ISO code"#)
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        match CountryIsoCode::new(v) {
            Ok(code) => Ok(code),
            Err(e) => Err(E::custom(format!("{}", e))),
        }
    }

    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        match CountryIsoCode::new(v) {
            Ok(code) => Ok(code),
            Err(e) => Err(E::custom(format!("{}", e))),
        }
    }
}

impl<'de> Deserialize<'de> for CountryIsoCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_string(CountryIsoCodeVisitor)
    }
}

/// Interface to obtain geolocation information.
#[async_trait]
pub trait GeoLocator {
    /// Figures out which country `ip` is in, if possible.
    async fn locate(&self, ip: &IpAddr) -> GeoResult<Option<CountryIsoCode>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_test::{assert_de_tokens_error, assert_tokens, Token};

    #[test]
    fn test_country_iso_code_ser_de_ok() {
        let code = CountryIsoCode::new("ES").unwrap();
        assert_tokens(&code, &[Token::String("ES")]);
    }

    #[test]
    fn test_country_iso_code_de_error() {
        assert_de_tokens_error::<CountryIsoCode>(
            &[Token::String("ESP")],
            "Country code ESP does not have length 2",
        );
    }
}
