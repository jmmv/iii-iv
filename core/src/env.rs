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

//! Utilities to deal with environment variables.

use crate::model::SecretString;
use std::{env, fmt::Debug, time::Duration};
use url::Url;

/// Result type for environment errors.
pub(crate) type Result<T> = std::result::Result<T, String>;

/// Constructs the name of an environment variable from a service prefix and a suffix.
pub fn var_name(prefix: &str, suffix: &str) -> String {
    if prefix.is_empty() { suffix.to_owned() } else { format!("{}_{}", prefix, suffix) }
}

/// Formats a parsed environment value for effective-configuration logging.
pub fn format_value<T: FormatValue>(value: &T) -> String {
    value.format_value()
}

/// Formats a parsed environment value for effective-configuration logging.
pub trait FormatValue {
    /// Formats this value without exposing secrets.
    fn format_value(&self) -> String;
}

/// Implements [`FormatValue`] for types that use their debug representation.
macro_rules! format_value_for_debug {
    ( $( $t:ty ),+ $(,)? ) => {
        $(
            impl FormatValue for $t {
                fn format_value(&self) -> String {
                    format!("{:?}", self)
                }
            }
        )+
    };
}

/// Implements [`FormatValue`] for types that use their display representation.
macro_rules! format_value_for_display {
    ( $( $t:ty ),+ $(,)? ) => {
        $(
            impl FormatValue for $t {
                fn format_value(&self) -> String {
                    self.to_string()
                }
            }
        )+
    };
}

format_value_for_debug!(Duration, SecretString);
format_value_for_display!(
    bool, i8, i16, i32, i64, i128, u8, u16, u32, u64, u128, usize, String, Url,
);

impl<T: Debug> FormatValue for Option<T> {
    fn format_value(&self) -> String {
        format!("{:?}", self)
    }
}

impl<T: Debug> FormatValue for Vec<T> {
    fn format_value(&self) -> String {
        format!("{:?}", self)
    }
}

/// Parses an environment value into a configuration type.
pub trait FromEnvValue: Sized {
    /// Parses `value` into this type.
    fn from_env_value(value: &str) -> Result<Self>;
}

impl FromEnvValue for String {
    fn from_env_value(value: &str) -> Result<Self> {
        Ok(value.to_owned())
    }
}

impl FromEnvValue for SecretString {
    fn from_env_value(value: &str) -> Result<Self> {
        Ok(SecretString::new(value.to_owned()))
    }
}

/// Implements [`FromEnvValue`] for types that can be parsed by `FromStr`.
macro_rules! from_env_value_for_fromstr [
    ( $t:ty ) => {
        impl FromEnvValue for $t {
            fn from_env_value(value: &str) -> Result<Self> {
                value.parse::<$t>().map_err(|e| format!("Invalid {}: {}", stringify!($t), e))
            }
        }
    }
];

from_env_value_for_fromstr!(bool);
from_env_value_for_fromstr!(i8);
from_env_value_for_fromstr!(i16);
from_env_value_for_fromstr!(i32);
from_env_value_for_fromstr!(i64);
from_env_value_for_fromstr!(i128);
from_env_value_for_fromstr!(u8);
from_env_value_for_fromstr!(u16);
from_env_value_for_fromstr!(u32);
from_env_value_for_fromstr!(u64);
from_env_value_for_fromstr!(u128);
from_env_value_for_fromstr!(usize);

impl FromEnvValue for Duration {
    fn from_env_value(value: &str) -> Result<Self> {
        let mut split_point = 0;
        for (i, ch) in value.chars().enumerate() {
            if !ch.is_ascii_digit() {
                split_point = i;
                break;
            }
        }
        let (quantity, unit) = value.split_at(split_point);

        let quantity = quantity
            .parse::<u64>()
            .map_err(|e| format!("Invalid time quantity '{}': {}", quantity, e))?;

        match unit {
            "ms" => Ok(Duration::from_millis(quantity)),
            "s" => Ok(Duration::from_secs(quantity)),
            "m" => Ok(Duration::from_secs(quantity.saturating_mul(60))),
            "h" => Ok(Duration::from_secs(quantity.saturating_mul(60 * 60))),
            "d" => Ok(Duration::from_secs(quantity.saturating_mul(24 * 60 * 60))),
            unit => Err(format!("Invalid time unit '{}'", unit)),
        }
    }
}

impl FromEnvValue for Url {
    fn from_env_value(value: &str) -> Result<Self> {
        match Url::parse(value) {
            Ok(url) => Ok(url),
            Err(e) => Err(format!("Invalid URL '{}': '{}'", value, e)),
        }
    }
}

impl<T: FromEnvValue> FromEnvValue for Vec<T> {
    fn from_env_value(value: &str) -> Result<Self> {
        value.split(',').map(T::from_env_value).collect()
    }
}

/// Gets an optional environment variable whose name is `<prefix>_<suffix>` with a conversion to
/// a target type `T`.
pub fn get_optional_var<T: FromEnvValue>(prefix: &str, suffix: &str) -> Result<Option<T>> {
    let name = var_name(prefix, suffix);
    match env::var(&name) {
        Ok(value) => match T::from_env_value(&value) {
            Ok(value) => Ok(Some(value)),
            Err(e) => Err(format!("Invalid type in environment variable {}: {}", name, e)),
        },
        Err(env::VarError::NotPresent) => Ok(None),
        Err(env::VarError::NotUnicode(_)) => {
            Err(format!("Invalid value in environment variable {}", name))
        }
    }
}

/// Gets a required environment variable whose name is `<prefix>_<suffix>` with a conversion to
/// a target type `T`.
pub fn get_required_var<T: FromEnvValue>(prefix: &str, suffix: &str) -> Result<T> {
    let name = var_name(prefix, suffix);
    match env::var(&name) {
        Ok(value) => match T::from_env_value(&value) {
            Ok(value) => Ok(value),
            Err(e) => Err(format!("Invalid type in environment variable {}: {}", name, e)),
        },
        Err(env::VarError::NotPresent) => {
            Err(format!("Required environment variable {} not present", name))
        }
        Err(env::VarError::NotUnicode(_)) => {
            Err(format!("Invalid value in environment variable {}", name))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    /// Value parsed by an application-defined environment parser.
    struct UppercaseString(String);

    impl FromEnvValue for UppercaseString {
        fn from_env_value(value: &str) -> Result<Self> {
            Ok(Self(value.to_ascii_uppercase()))
        }
    }

    #[test]
    fn test_from_env_value_custom() {
        assert_eq!("VALUE", UppercaseString::from_env_value("value").unwrap().0);
    }

    #[test]
    fn test_from_env_value_vec() {
        assert_eq!(vec![1, 2, 3], Vec::<u16>::from_env_value("1,2,3").unwrap());
        assert!(Vec::<u16>::from_env_value("1,nope,3").is_err());
    }

    #[test]
    fn test_var_name_empty_prefix() {
        assert_eq!("SETTING", var_name("", "SETTING"));
    }

    #[test]
    fn test_from_env_value_string() {
        assert_eq!("foo bar", String::from_env_value("foo bar").unwrap());
    }

    #[test]
    fn test_from_env_value_secret_string() {
        let secret = SecretString::from_env_value("foo bar").unwrap();
        assert_eq!("foo bar", secret.as_str());
        assert_eq!("scrubbed secret", format!("{:?}", secret));
        assert_eq!("foo bar", secret.into_string());
    }

    #[test]
    fn test_from_env_value_fromstr_bool() {
        assert!(!bool::from_env_value("false").unwrap());
        assert!(bool::from_env_value("true").unwrap());

        let err = bool::from_env_value("-1").unwrap_err();
        assert!(err.starts_with("Invalid bool:"));
    }

    #[test]
    fn test_from_env_value_fromstr_integer() {
        assert_eq!(1234u16, u16::from_env_value("1234").unwrap());

        let err = u16::from_env_value("-1").unwrap_err();
        assert!(err.starts_with("Invalid u16:"));
    }

    #[test]
    fn test_from_env_value_duration() {
        for (exp_duration, raw) in [
            (Duration::from_millis(3), "3ms"),
            (Duration::from_millis(123456789), "123456789ms"),
            (Duration::from_secs(5), "5s"),
            (Duration::from_secs(60), "1m"),
            (Duration::from_secs(2 * 60 * 60), "2h"),
            (Duration::from_secs(20 * 24 * 60 * 60), "20d"),
            (Duration::from_millis(u64::MAX), &format!("{}ms", u64::MAX)),
            (Duration::from_secs(u64::MAX), &format!("{}s", u64::MAX)),
            (Duration::from_secs(u64::MAX), &format!("{}m", u64::MAX)),
            (Duration::from_secs(u64::MAX), &format!("{}h", u64::MAX)),
            (Duration::from_secs(u64::MAX), &format!("{}d", u64::MAX)),
        ] {
            assert_eq!(exp_duration, Duration::from_env_value(raw).unwrap());
        }

        for (exp_err, raw) in [
            ("Invalid time quantity '':", ""),
            ("Invalid time quantity '':", "-"),
            ("Invalid time unit 'H'", "4H"),
            ("Invalid time unit 'a3d'", "2a3d"),
            ("Invalid time quantity '':", "-1d"),
            ("Invalid time quantity '':", " 1 s"),
            ("Invalid time quantity '':", " 1s"),
            ("Invalid time unit 's '", "1s "),
        ] {
            let err = Duration::from_env_value(raw).unwrap_err();
            assert!(err.starts_with(exp_err), "Error '{}' does not start with '{}'", err, exp_err);
        }
    }

    #[test]
    fn test_from_env_value_url() {
        assert_eq!(
            &Url::parse("https://somewhere.example.com/").unwrap(),
            &Url::from_env_value("https://somewhere.example.com/").unwrap()
        );
    }

    #[test]
    #[serial(ENV)]
    fn test_get_optional_var_ok() {
        temp_env::with_var("ENV_PRESENT", Some("1234"), || {
            assert_eq!(
                Some("1234"),
                get_optional_var::<String>("ENV", "PRESENT").unwrap().as_deref()
            );
        });
    }

    #[test]
    #[serial(ENV)]
    fn test_get_optional_var_missing() {
        temp_env::with_var_unset("ENV_MISSING", || {
            assert_eq!(None, get_optional_var::<String>("ENV", "MISSING").unwrap());
        });
    }

    #[test]
    #[serial(ENV)]
    fn test_get_optional_var_not_utf8() {
        temp_env::with_var("ENV_INVALID", Some(OsStr::from_bytes(b"\xc3\x28")), || {
            assert_eq!(
                "Invalid value in environment variable ENV_INVALID",
                &get_optional_var::<String>("ENV", "INVALID").unwrap_err()
            );
        });
    }

    #[test]
    #[serial(ENV)]
    fn test_get_optional_var_bad_type() {
        temp_env::with_var("ENV_BAD", Some("b4d"), || {
            let err = get_optional_var::<u16>("ENV", "BAD").unwrap_err();
            assert!(err.starts_with("Invalid type in environment variable ENV_BAD: Invalid u16"));
        });
    }

    #[test]
    #[serial(ENV)]
    fn test_get_required_var_ok() {
        temp_env::with_var("ENV_PRESENT", Some("1234"), || {
            assert_eq!("1234", &get_required_var::<String>("ENV", "PRESENT").unwrap());
        });
    }

    #[test]
    #[serial(ENV)]
    fn test_get_required_var_missing() {
        temp_env::with_var_unset("ENV_MISSING", || {
            assert_eq!(
                "Required environment variable ENV_MISSING not present",
                &get_required_var::<String>("ENV", "MISSING").unwrap_err()
            );
        });
    }

    #[test]
    #[serial(ENV)]
    fn test_get_required_var_not_utf8() {
        temp_env::with_var("ENV_INVALID", Some(OsStr::from_bytes(b"\xc3\x28")), || {
            assert_eq!(
                "Invalid value in environment variable ENV_INVALID",
                &get_required_var::<String>("ENV", "INVALID").unwrap_err()
            );
        });
    }

    #[test]
    #[serial(ENV)]
    fn test_get_required_var_bad_type() {
        temp_env::with_var("ENV_BAD", Some("b4d"), || {
            let err = get_required_var::<u16>("ENV", "BAD").unwrap_err();
            assert!(err.starts_with("Invalid type in environment variable ENV_BAD: Invalid u16"));
        });
    }
}
