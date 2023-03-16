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

use std::env;

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
