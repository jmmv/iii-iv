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

use std::{env, time::Duration};

use url::Url;

/// Result type for environment errors.
type Result<T> = std::result::Result<T, String>;

/// Wrapper around an environment variable's value to support conversions to other types.
pub struct Value(String);

impl TryFrom<Value> for String {
    type Error = String;

    fn try_from(value: Value) -> std::result::Result<Self, Self::Error> {
        Ok(value.0)
    }
}

/// Generates a `TryFrom<Value>` for a type that can be parsed by `FromStr`.
macro_rules! tryfrom_value_for_fromstr [
    ( $t:ty ) => {
        impl TryFrom<Value> for $t {
            type Error = String;

            fn try_from(value: Value) -> std::result::Result<Self, Self::Error> {
                value.0.parse::<$t>().map_err(|e| format!("Invalid {}: {}", stringify!($t), e))
            }
        }
    }
];

tryfrom_value_for_fromstr!(i8);
tryfrom_value_for_fromstr!(i16);
tryfrom_value_for_fromstr!(i32);
tryfrom_value_for_fromstr!(i64);
tryfrom_value_for_fromstr!(i128);
tryfrom_value_for_fromstr!(u8);
tryfrom_value_for_fromstr!(u16);
tryfrom_value_for_fromstr!(u32);
tryfrom_value_for_fromstr!(u64);
tryfrom_value_for_fromstr!(u128);
tryfrom_value_for_fromstr!(usize);

impl TryFrom<Value> for Duration {
    type Error = String;

    fn try_from(value: Value) -> std::result::Result<Self, Self::Error> {
        let mut split_point = 0;
        for (i, ch) in value.0.chars().enumerate() {
            if !ch.is_ascii_digit() {
                split_point = i;
                break;
            }
        }
        let (quantity, unit) = value.0.split_at(split_point);

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

impl TryFrom<Value> for Url {
    type Error = String;

    fn try_from(value: Value) -> std::result::Result<Self, Self::Error> {
        match Url::parse(&value.0) {
            Ok(url) => Ok(url),
            Err(e) => Err(format!("Invalid URL '{}': '{}'", value.0, e)),
        }
    }
}

/// Gets an optional environment variable whose name is `<prefix>_<suffix>` with a conversion to
/// a target type `T`.
pub fn get_optional_var<T: TryFrom<Value, Error = String>>(
    prefix: &str,
    suffix: &str,
) -> Result<Option<T>> {
    let name = format!("{}_{}", prefix, suffix);
    match env::var(&name) {
        Ok(value) => match Value(value).try_into() {
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
pub fn get_required_var<T: TryFrom<Value, Error = String>>(
    prefix: &str,
    suffix: &str,
) -> Result<T> {
    let name = format!("{}_{}", prefix, suffix);
    match env::var(&name) {
        Ok(value) => match Value(value).try_into() {
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
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    #[test]
    fn test_value_to_string() {
        assert_eq!("foo bar", &TryInto::<String>::try_into(Value("foo bar".to_owned())).unwrap());
    }

    #[test]
    fn test_value_to_fromstr() {
        assert_eq!(1234u16, TryInto::<u16>::try_into(Value("1234".to_owned())).unwrap());

        let err = TryInto::<u16>::try_into(Value("-1".to_owned())).unwrap_err();
        assert!(err.starts_with("Invalid u16:"));
    }

    #[test]
    fn test_value_to_duration() {
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
            assert_eq!(exp_duration, TryInto::<Duration>::try_into(Value(raw.to_owned())).unwrap());
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
            let err = TryInto::<Duration>::try_into(Value(raw.to_owned())).unwrap_err();
            assert!(err.starts_with(exp_err), "Error '{}' does not start with '{}'", err, exp_err);
        }
    }

    #[test]
    fn test_value_to_url() {
        assert_eq!(
            &Url::parse("https://somewhere.example.com/").unwrap(),
            &TryInto::<Url>::try_into(Value("https://somewhere.example.com/".to_owned())).unwrap()
        );
    }

    #[test]
    fn test_get_optional_var_ok() {
        temp_env::with_var("PREFIX_PRESENT", Some("1234"), || {
            assert_eq!(
                Some("1234"),
                get_optional_var::<String>("PREFIX", "PRESENT").unwrap().as_deref()
            );
        });
    }

    #[test]
    fn test_get_optional_var_missing() {
        temp_env::with_var_unset("PREFIX_MISSING", || {
            assert_eq!(None, get_optional_var::<String>("PREFIX", "MISSING").unwrap());
        });
    }

    #[test]
    fn test_get_optional_var_not_utf8() {
        temp_env::with_var("PREFIX_INVALID", Some(OsStr::from_bytes(b"\xc3\x28")), || {
            assert_eq!(
                "Invalid value in environment variable PREFIX_INVALID",
                &get_optional_var::<String>("PREFIX", "INVALID").unwrap_err()
            );
        });
    }

    #[test]
    fn test_get_optional_var_bad_type() {
        temp_env::with_var("PREFIX_BAD", Some("b4d"), || {
            let err = get_optional_var::<u16>("PREFIX", "BAD").unwrap_err();
            assert!(err.starts_with("Invalid type in environment variable PREFIX_BAD: Invalid u16"));
        });
    }

    #[test]
    fn test_get_required_var_ok() {
        temp_env::with_var("PREFIX_PRESENT", Some("1234"), || {
            assert_eq!("1234", &get_required_var::<String>("PREFIX", "PRESENT").unwrap());
        });
    }

    #[test]
    fn test_get_required_var_missing() {
        temp_env::with_var_unset("PREFIX_MISSING", || {
            assert_eq!(
                "Required environment variable PREFIX_MISSING not present",
                &get_required_var::<String>("PREFIX", "MISSING").unwrap_err()
            );
        });
    }

    #[test]
    fn test_get_required_var_not_utf8() {
        temp_env::with_var("PREFIX_INVALID", Some(OsStr::from_bytes(b"\xc3\x28")), || {
            assert_eq!(
                "Invalid value in environment variable PREFIX_INVALID",
                &get_required_var::<String>("PREFIX", "INVALID").unwrap_err()
            );
        });
    }

    #[test]
    fn test_get_required_var_bad_type() {
        temp_env::with_var("PREFIX_BAD", Some("b4d"), || {
            let err = get_required_var::<u16>("PREFIX", "BAD").unwrap_err();
            assert!(err.starts_with("Invalid type in environment variable PREFIX_BAD: Invalid u16"));
        });
    }
}
