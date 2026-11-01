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

//! High-level data types.

use derive_more::{AsRef, Constructor};
use iii_iv_core::model::{ModelError, ModelResult};
use serde::{Deserialize, Serialize};

/// Newtype pattern for the keys of our key/value store.
#[derive(AsRef, Constructor, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[cfg_attr(test, derive(Debug))]
pub(crate) struct Key(String);

/// A key's current version number.  We store this as an u32 but guarantee that it is
/// usable in an i32 context because the PostgreSQL database backend needs it.
#[derive(PartialEq, Serialize)]
#[cfg_attr(test, derive(Debug, Deserialize))]
pub(crate) struct Version(u32);

impl Version {
    /// Returns the initial version assigned to new keys.
    pub(crate) fn initial() -> Version {
        Version(1)
    }

    /// Returns the next version to assign to an existing key.
    pub(crate) fn next(self) -> ModelResult<Version> {
        let next = self.as_i32().checked_add(1).ok_or_else(|| {
            ModelError("Version cannot be represented: exceeds i32::MAX".to_owned())
        })?;
        Self::from_i32(next)
    }

    /// Creates a version from an `i32` with range validation.
    pub(crate) fn from_i32(version: i32) -> ModelResult<Version> {
        match u32::try_from(version) {
            Ok(version) => Ok(Version(version)),
            Err(e) => Err(ModelError(format!("Version cannot be represented: {}", e))),
        }
    }

    /// Returns the version as an `i32`.
    pub(crate) fn as_i32(&self) -> i32 {
        i32::try_from(self.0).expect("i32 compatibility validated at construction time")
    }
}

#[cfg(test)]
mod tests {
    use super::Version;

    #[test]
    fn test_version_bounds() {
        assert!(Version::from_i32(-1).is_err());
        assert_eq!(0, Version::from_i32(0).unwrap().as_i32());
        assert_eq!(i32::MAX, Version::from_i32(i32::MAX).unwrap().as_i32());
        assert_eq!(i32::MAX, Version::from_i32(i32::MAX - 1).unwrap().next().unwrap().as_i32());
        assert!(Version::from_i32(i32::MAX).unwrap().next().is_err());
    }
}

/// Content of the keys stored in our key/value store.
#[derive(Serialize)]
#[cfg_attr(test, derive(Debug, Deserialize, PartialEq))]
pub(crate) struct Entry {
    /// The key's raw value.
    pub(crate) value: String,

    /// The key's current version number.
    pub(crate) version: Version,
}

impl Entry {
    /// Creates an entry with the given value and version.
    pub(crate) const fn new(value: String, version: Version) -> Self {
        Self { value, version }
    }
}
