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

//! Business logic for the service.

use crate::db::Tx;
use iii_iv_core::db::Db;

mod key;
mod keys;
#[cfg(test)]
mod testutils;

/// Business logic.
///
/// The public operations exposed by the driver are all "one shot": they start and commit a
/// transaction, so it's incorrect for the caller to use two separate calls.  For this reason,
/// these operations consume the driver in an attempt to minimize the possibility of executing
/// two operations.
#[derive(Clone)]
pub(crate) struct Driver<D>
where
    D: Db + Clone + Send + Sync + 'static,
    D::Tx: Tx + Send + Sync + 'static,
{
    /// The database that the driver uses for persistence.
    db: D,
}

impl<D> Driver<D>
where
    D: Db + Clone + Send + Sync + 'static,
    D::Tx: Tx + Send + Sync + 'static,
{
    /// Creates a new driver backed by the given injected components.
    pub(crate) fn new(db: D) -> Self {
        Self { db }
    }
}
