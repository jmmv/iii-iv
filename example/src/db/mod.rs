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

//! Database abstraction in terms of the operations needed by the server.

use crate::model::*;
use iii_iv_core::db::{BareTx, DbResult};
use std::collections::BTreeSet;
pub(crate) mod postgres;
#[cfg(test)]
pub(crate) mod sqlite;
#[cfg(test)]
pub(crate) mod tests;

/// A transaction with high-level operations that deal with our types.
#[async_trait::async_trait]
pub(crate) trait KVStoreTx: BareTx {
    /// Gets a list of all existing keys.
    async fn get_keys(&mut self) -> DbResult<BTreeSet<Key>>;

    /// Gets the current value of the given `key`.
    async fn get_key(&mut self, key: &Key) -> DbResult<Entry>;

    /// Gets the current version of the given `key`, or `None` if it does not exist.
    async fn get_key_version(&mut self, key: &Key) -> DbResult<Option<Version>>;

    /// Sets `key` to `entry`, which includes its value and version.
    async fn set_key(&mut self, key: &Key, entry: &Entry) -> DbResult<()>;

    /// Deletes `key`.
    async fn delete_key(&mut self, key: &Key) -> DbResult<()>;
}
