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

use derive_getters::Getters;
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
    pub(crate) fn next(self) -> Version {
        Version(self.0 + 1)
    }

    /// Creates a version from an `i32` with range validation.
    pub(crate) fn from_i32(version: i32) -> ModelResult<Version> {
        match u32::try_from(version) {
            Ok(version) => Ok(Version(version)),
            Err(e) => Err(ModelError(format!("Version cannot be represented: {}", e))),
        }
    }

    /// Creates a version from a `u32` with range validation.
    #[cfg(test)]
    pub(crate) fn from_u32(version: u32) -> ModelResult<Version> {
        match i32::try_from(version) {
            Ok(_) => Ok(Version(version)),
            Err(e) => Err(ModelError(format!("Version cannot be represented: {}", e))),
        }
    }

    /// Returns the version as an `i32`.
    pub(crate) fn as_i32(&self) -> i32 {
        i32::try_from(self.0).expect("i32 compatibility validated at construction time")
    }

    /// Returns the version as a `u32`.
    #[cfg(test)]
    pub(crate) fn as_u32(&self) -> u32 {
        self.0
    }
}

/// Content of the keys stored in our key/value store.
#[derive(Constructor, Getters, Serialize)]
#[cfg_attr(test, derive(Debug, Deserialize, PartialEq))]
pub(crate) struct Entry {
    /// The key's raw value.
    value: String,

    /// The key's current version number.
    version: Version,
}
