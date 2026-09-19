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

//! Coupon data types.

use iii_iv_core::model::{ModelError, ModelResult};
use serde::{Deserialize, Deserializer, Serialize, de};
use std::borrow::Cow;
use time::OffsetDateTime;

/// Maximum length of a coupon name as specified in the schema.
const COUPONS_MAX_NAME_LENGTH: usize = 16;

/// A validated and normalized coupon name.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct CouponName(Cow<'static, str>);

impl CouponName {
    /// Checks whether a coupon name is valid.
    const fn validate(name: &str) -> Option<&'static str> {
        if name.is_empty() {
            return Some("Coupon name cannot be empty");
        }
        if name.len() > COUPONS_MAX_NAME_LENGTH {
            return Some("Coupon name is too long");
        }
        let bytes = name.as_bytes();
        let mut index = 0;
        while index < bytes.len() {
            let byte = bytes[index];
            if !byte.is_ascii_uppercase() && !byte.is_ascii_digit() && byte != b'-' && byte != b'_'
            {
                return Some("Unsupported character in coupon name");
            }
            index += 1;
        }
        None
    }

    /// Creates a coupon name from untrusted input and normalizes it to uppercase.
    pub fn new<S: Into<String>>(name: S) -> ModelResult<Self> {
        let name = name.into().to_ascii_uppercase();
        if let Some(error) = Self::validate(&name) {
            return Err(ModelError(error.to_owned()));
        }
        Ok(Self(Cow::Owned(name)))
    }

    /// Creates a coupon name from a hardcoded string.
    #[cfg(any(test, feature = "testutils"))]
    pub const fn from_static(name: &'static str) -> Self {
        if Self::validate(name).is_some() {
            panic!("Hardcoded coupon names must be valid and uppercase");
        }
        Self(Cow::Borrowed(name))
    }

    /// Returns a string view of the coupon name.
    pub fn as_str(&self) -> &str {
        self.0.as_ref()
    }
}

impl<'de> Deserialize<'de> for CouponName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let name = String::deserialize(deserializer)?;
        Self::new(name).map_err(de::Error::custom)
    }
}

/// Instantiates a coupon name from a static string.
#[cfg(any(test, feature = "testutils"))]
#[macro_export]
macro_rules! __coupon_name__ {
    ( $string:expr ) => {
        $crate::model::CouponName::from_static($string)
    };
}

#[cfg(any(test, feature = "testutils"))]
pub use __coupon_name__ as coupon_name;

/// A coupon that can authorize a bounded number of signups during a time window.
#[derive(Clone, Debug, PartialEq)]
pub struct Coupon {
    /// Canonical coupon name.
    pub name: CouponName,

    /// First instant at which the coupon can be used.
    pub valid_from: OffsetDateTime,

    /// First instant at which the coupon can no longer be used.
    pub valid_until: OffsetDateTime,

    /// Maximum number of successful signups authorized by the coupon.
    pub max_usages: u32,

    /// Number of successful signups already authorized by the coupon.
    pub usages: u32,
}

impl Coupon {
    /// Creates a new, unused coupon.
    pub fn new(
        name: CouponName,
        valid_from: OffsetDateTime,
        valid_until: OffsetDateTime,
        max_usages: u32,
    ) -> ModelResult<Self> {
        if valid_from >= valid_until {
            return Err(ModelError("Coupon validity window is empty".to_owned()));
        }
        Ok(Self { name, valid_from, valid_until, max_usages, usages: 0 })
    }

    /// Checks whether the given instant is within this coupon's validity window.
    pub fn is_valid(&self, now: OffsetDateTime) -> bool {
        self.valid_from <= now && now < self.valid_until
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn test_coupon_name_ok() {
        assert_eq!(coupon_name!("BETA100"), CouponName::new("beta100").unwrap());
        assert_eq!(coupon_name!("A-B_C"), CouponName::new("a-b_c").unwrap());
    }

    #[test]
    fn test_coupon_name_error() {
        assert!(CouponName::new("").is_err());
        assert!(CouponName::new("HAS SPACES").is_err());
        assert!(CouponName::new("12345678901234567").is_err());
        assert!(CouponName::new("NONASCII-É").is_err());
    }

    #[test]
    fn test_coupon_new() {
        let valid_from = datetime!(2026-01-01 0:00 UTC);
        let valid_until = datetime!(2026-02-01 0:00 UTC);
        let coupon = Coupon::new(coupon_name!("BETA100"), valid_from, valid_until, 100).unwrap();
        assert_eq!(coupon_name!("BETA100"), coupon.name);
        assert_eq!(valid_from, coupon.valid_from);
        assert_eq!(valid_until, coupon.valid_until);
        assert_eq!(100, coupon.max_usages);
        assert_eq!(0, coupon.usages);
        assert!(Coupon::new(coupon_name!("EMPTY"), valid_until, valid_from, 1).is_err());
    }

    #[test]
    fn test_coupon_is_valid() {
        let valid_from = datetime!(2026-01-01 0:00 UTC);
        let valid_until = datetime!(2026-02-01 0:00 UTC);
        let coupon = Coupon::new(coupon_name!("BETA100"), valid_from, valid_until, 100).unwrap();

        assert!(!coupon.is_valid(datetime!(2025-12-31 23:59:59 UTC)));
        assert!(coupon.is_valid(valid_from));
        assert!(coupon.is_valid(datetime!(2026-01-31 23:59:59 UTC)));
        assert!(!coupon.is_valid(valid_until));
    }
}
