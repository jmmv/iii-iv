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

//! Generic business logic for any service.
//!
//! Every service should implement its own `Driver` type.  In most cases, this type will be
//! parameterized on a database implementation, and as such the definition will look like this:
//!
//! ```rust
//! use iii_iv_core::db::{BareTx, Db};
//! trait Tx: BareTx {}
//!
//! #[derive(Clone)]
//! pub(crate) struct Driver<D>
//! where
//!     D: Db + Clone + Send + Sync + 'static,
//!     D::Tx: Tx + From<D::SqlxTx> + Send + Sync + 'static,
//! {
//!     /// The database that the driver uses for persistence.
//!     db: D,
//!
//!     // ... other fields here ...
//! }
//! ```
//!
//! Every operation implemented in the `Driver` should take consume `self` because this is the
//! layer that coordinates multiple operations against the database inside a single transaction.
//! Consuming `self` prevents the caller from easily issuing multiple operations against the driver,
//! as this would require a clone and highlight an undesirable pattern.

use crate::db::DbError;
use crate::model::ModelError;

/// Business logic errors.  These errors encompass backend and logical errors.
#[derive(Debug, PartialEq, thiserror::Error)]
pub enum DriverError {
    /// Indicates that a request to create an entry failed because it already exists.
    #[error("{0}")]
    AlreadyExists(String),

    /// Catch-all error type for unexpected database errors.
    #[error("{0}")]
    BackendError(String),

    /// Indicates an error in the input data.
    #[error("{0}")]
    InvalidInput(String),

    /// Indicates insufficient disk quota to perform the requested write operation.
    #[error("{0}")]
    NoSpace(String),

    /// Indicates that login cannot succeed because the account is not yet activated.
    #[error("Account has not been activated yet")]
    NotActivated,

    /// Indicates that a requested entry does not exist.
    #[error("{0}")]
    NotFound(String),

    /// Indicates that the calling user is not allowed to perform a read or write operation.
    #[error("{0}")]
    Unauthorized(String),
}

impl From<DbError> for DriverError {
    fn from(e: DbError) -> Self {
        match e {
            DbError::AlreadyExists => DriverError::AlreadyExists(e.to_string()),
            DbError::BackendError(_) => DriverError::BackendError(e.to_string()),
            DbError::DataIntegrityError(_) => DriverError::BackendError(e.to_string()),
            DbError::NotFound => DriverError::NotFound(e.to_string()),
            DbError::Unavailable => DriverError::BackendError(e.to_string()),
        }
    }
}

impl From<ModelError> for DriverError {
    fn from(e: ModelError) -> Self {
        DriverError::InvalidInput(e.to_string())
    }
}

/// Result type for this module.
pub type DriverResult<T> = Result<T, DriverError>;
