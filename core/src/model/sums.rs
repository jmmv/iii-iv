// gitc
// Copyright 2026 Snowflake Inc.  All rights reserved.

//! Fixed-size message digests and their hexadecimal representations.
//!
//! ```
//! use iii_iv_core::model::{Sha1Sum, Sha256Sum};
//! use iii_iv_core::{sha1sum, sha256sum};
//!
//! const SHA1: Sha1Sum = sha1sum!("a9993e364706816aba3e25717850c26c9cd0d89d");
//! const SUM: Sha256Sum =
//!     sha256sum!("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
//! assert_eq!(20, SHA1.as_bytes().len());
//! assert_eq!(32, SUM.as_bytes().len());
//! ```
//!
//! ```compile_fail
//! use iii_iv_core::model::Sha1Sum;
//! use iii_iv_core::sha1sum;
//!
//! const BAD: Sha1Sum = sha1sum!("not-a-sha1");
//! ```
//!
//! ```compile_fail
//! use iii_iv_core::model::Sha256Sum;
//! use iii_iv_core::sha256sum;
//!
//! const BAD: Sha256Sum = sha256sum!("not-a-sha256");
//! ```

use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::fmt;

/// Defines a fixed-size hash type and its literal macro for a digest algorithm.
macro_rules! gensum {
    (
        $name:ident,
        $hasher:ident,
        $bytes_len_const:ident,
        $bytes_len:expr,
        $hex_len_const:ident,
        $macro_name:ident
    ) => {
        /// Length of a the hash value in bytes.
        #[allow(unused)]
        pub(crate) const $bytes_len_const: usize = $bytes_len;

        /// Length of the hex representation of the hash value.
        #[allow(unused)]
        pub(crate) const $hex_len_const: usize = $bytes_len * 2;

        /// Contains a hash value.
        #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
        pub struct $name([u8; $bytes_len_const]);

        impl $name {
            /// Creates a hash from its raw bytes.
            pub const fn from_bytes(bytes: [u8; $bytes_len]) -> Self {
                Self(bytes)
            }

            /// Parses a hash from its hexadecimal representation.
            pub const fn from_hex(value: &str) -> Option<Self> {
                if value.len() != $hex_len_const {
                    return None;
                }

                let value = value.as_bytes();
                let mut bytes = [0; $bytes_len_const];
                let mut index = 0;
                while index < $bytes_len_const {
                    let Some(high) = Self::hex_digit(value[index * 2]) else {
                        return None;
                    };
                    let Some(low) = Self::hex_digit(value[index * 2 + 1]) else {
                        return None;
                    };
                    bytes[index] = high << 4 | low;
                    index += 1;
                }
                Some(Self::from_bytes(bytes))
            }

            /// Returns the hash length in bytes.
            #[allow(unused)]
            pub(crate) fn bytes_len(&self) -> usize {
                $bytes_len_const
            }

            /// Returns the hash as bytes.
            #[allow(unused)]
            pub fn as_bytes(&self) -> &[u8] {
                &self.0
            }

            /// Returns the length of the hex representation of the hash.
            #[allow(unused)]
            pub(crate) fn hex_len(&self) -> usize {
                $hex_len_const
            }

            /// Returns the hash as a hex string.
            #[allow(unused)]
            pub(crate) fn as_hex(&self) -> String {
                hex::encode(self.0)
            }

            /// Decodes one hexadecimal digit.
            const fn hex_digit(value: u8) -> Option<u8> {
                match value {
                    b'0'..=b'9' => Some(value - b'0'),
                    b'a'..=b'f' => Some(value - b'a' + 10),
                    b'A'..=b'F' => Some(value - b'A' + 10),
                    _ => None,
                }
            }
        }

        impl From<$hasher> for $name {
            fn from(hasher: $hasher) -> Self {
                let hash = hasher.finalize();
                assert_eq!($bytes_len, hash.len());
                Self(hash.into())
            }
        }

        impl TryFrom<&str> for $name {
            type Error = String;

            fn try_from(value: &str) -> Result<Self, Self::Error> {
                match hex::decode(value) {
                    Ok(bytes) => Ok(bytes.try_into()?),
                    Err(_) => Err(format!("Invalid {} length", stringify!($name))),
                }
            }
        }

        impl TryFrom<String> for $name {
            type Error = String;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                match hex::decode(value) {
                    Ok(bytes) => Ok(bytes.try_into()?),
                    Err(_) => Err(format!("Invalid {} length", stringify!($name))),
                }
            }
        }

        impl TryFrom<Vec<u8>> for $name {
            type Error = String;

            fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
                match value.try_into() {
                    Ok(bytes) => Ok(Self(bytes)),
                    Err(_) => Err(format!("Invalid {} length", stringify!($name))),
                }
            }
        }

        impl TryFrom<&[u8]> for $name {
            type Error = String;

            fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
                match value.try_into() {
                    Ok(bytes) => Ok(Self(bytes)),
                    Err(_) => Err(format!("Invalid {} length", stringify!($name))),
                }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.as_hex())
            }
        }

        /// Creates a hash from a hardcoded hexadecimal literal.
        #[macro_export]
        macro_rules! $macro_name {
            ($value:literal) => {
                match $crate::model::$name::from_hex($value) {
                    Some(value) => value,
                    None => panic!(concat!(stringify!($macro_name), " requires a valid hash")),
                }
            };
        }
    };
}

gensum!(Sha1Sum, Sha1, SHA1SUM_BYTES_LEN, 20, SHA1SUM_HEX_LEN, sha1sum);
gensum!(Sha256Sum, Sha256, SHA256SUM_BYTES_LEN, 32, SHA256SUM_HEX_LEN, sha256sum);

#[cfg(test)]
mod tests {
    use super::*;

    const SHA: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    #[test]
    fn test_sha1sum_constants_describe_sha1() {
        assert_eq!(20, SHA1SUM_BYTES_LEN);
        assert_eq!(40, SHA1SUM_HEX_LEN);
    }

    #[test]
    fn test_sha1sum_from_hasher_calculates_digest() {
        let mut hasher = Sha1::new();
        hasher.update(b"abc");
        assert_eq!("a9993e364706816aba3e25717850c26c9cd0d89d", Sha1Sum::from(hasher).as_hex());
    }

    #[test]
    fn test_sha1sum_parses_hex() {
        let text = "a9993e364706816aba3e25717850c26c9cd0d89d";
        let sum = Sha1Sum::try_from(text).unwrap();
        assert_eq!(text, sum.to_string());
        assert_eq!(hex::decode(text).unwrap(), sum.as_bytes());
        assert_eq!(20, sum.bytes_len());
        assert_eq!(40, sum.hex_len());
        assert_eq!(sum, Sha1Sum::try_from(text.to_owned()).unwrap());
        assert_eq!(sum, Sha1Sum::try_from(text.to_uppercase()).unwrap());
    }

    #[test]
    fn test_sha1sum_parses_bytes() {
        let text = "a9993e364706816aba3e25717850c26c9cd0d89d";
        let bytes = hex::decode(text).unwrap();
        let sum = Sha1Sum::try_from(text).unwrap();
        assert_eq!(sum, Sha1Sum::from_bytes(bytes.clone().try_into().unwrap()));
        assert_eq!(sum, Sha1Sum::try_from(bytes.clone()).unwrap());
        assert_eq!(sum, Sha1Sum::try_from(bytes.as_slice()).unwrap());
    }

    #[test]
    fn test_sha1sum_macro_creates_sum() {
        const SUM: Sha1Sum = sha1sum!("a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!("a9993e364706816aba3e25717850c26c9cd0d89d", SUM.to_string());
        assert_eq!(SUM, Sha1Sum::from_hex("A9993E364706816ABA3E25717850C26C9CD0D89D").unwrap());
    }

    #[test]
    fn test_sha1sum_rejects_invalid_input() {
        for text in ["not-a-sha".to_owned(), "00".repeat(19), "00".repeat(21), "zz".repeat(20)] {
            assert!(Sha1Sum::try_from(text.as_str()).is_err());
            assert!(Sha1Sum::try_from(text.clone()).is_err());
            assert_eq!(None, Sha1Sum::from_hex(&text));
        }
        for bytes in [vec![0; 19], vec![0; 21]] {
            assert!(Sha1Sum::try_from(bytes.as_slice()).is_err());
            assert!(Sha1Sum::try_from(bytes).is_err());
        }
    }

    #[test]
    fn test_sha256sum_constants_describe_sha256() {
        assert_eq!(32, SHA256SUM_BYTES_LEN);
        assert_eq!(64, SHA256SUM_HEX_LEN);
    }

    #[test]
    fn test_sha256sum_parses_hex() {
        let sha = Sha256Sum::try_from(SHA).unwrap();
        assert_eq!(SHA, sha.to_string());
        assert_eq!(hex::decode(SHA).unwrap(), sha.as_bytes());
        assert_eq!(32, sha.bytes_len());
        assert_eq!(64, sha.hex_len());
        assert_eq!(sha, Sha256Sum::try_from(SHA.to_owned()).unwrap());
        assert_eq!(sha, Sha256Sum::try_from(SHA.to_uppercase()).unwrap());
    }

    #[test]
    fn test_sha256sum_from_hasher_calculates_digest() {
        let mut hasher = Sha256::new();
        hasher.update(b"abc");
        assert_eq!(SHA, Sha256Sum::from(hasher).as_hex());
    }

    #[test]
    fn test_sha256sum_parses_bytes() {
        let bytes = hex::decode(SHA).unwrap();
        let sum = Sha256Sum::try_from(SHA).unwrap();
        assert_eq!(sum, Sha256Sum::from_bytes(bytes.clone().try_into().unwrap()));
        assert_eq!(sum, Sha256Sum::try_from(bytes.clone()).unwrap());
        assert_eq!(sum, Sha256Sum::try_from(bytes.as_slice()).unwrap());
    }

    #[test]
    fn test_sha256sum_macro_creates_sum() {
        const SUM: Sha256Sum =
            sha256sum!("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(SHA, SUM.to_string());
        assert_eq!(SUM, Sha256Sum::from_hex(&SHA.to_uppercase()).unwrap());
    }

    #[test]
    fn test_sha256sum_rejects_invalid_input() {
        for text in ["not-a-sha".to_owned(), "00".repeat(31), "00".repeat(33), "zz".repeat(32)] {
            assert!(Sha256Sum::try_from(text.as_str()).is_err());
            assert!(Sha256Sum::try_from(text.clone()).is_err());
            assert_eq!(None, Sha256Sum::from_hex(&text));
        }
        for bytes in [vec![0; 31], vec![0; 33]] {
            assert!(Sha256Sum::try_from(bytes.as_slice()).is_err());
            assert!(Sha256Sum::try_from(bytes).is_err());
        }
    }
}
