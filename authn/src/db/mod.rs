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

//! Database abstraction to manipulate users and authentication.

use crate::model::{AccessToken, HashedPassword, Session, User};
use iii_iv_core::db::{BareTx, DbResult};
use iii_iv_core::model::{EmailAddress, Username};
use time::OffsetDateTime;

#[cfg(feature = "postgres")]
mod postgres;
#[cfg(feature = "postgres")]
pub use postgres::PostgresAuthnTx;

#[cfg(any(feature = "sqlite", test))]
mod sqlite;
#[cfg(any(feature = "sqlite", test))]
pub use sqlite::SqliteAuthnTx;

#[cfg(test)]
pub(crate) mod tests;

/// A transaction with high-level operations that deal with our types.
#[async_trait::async_trait]
pub trait AuthnTx: BareTx {
    /// Creates a new user named `username`, with a `password` in hashed form, an `email` address.
    /// The user is created as activated (no activation code) and as not having logged in.
    async fn create_user(
        &mut self,
        username: Username,
        password: Option<HashedPassword>,
        email: EmailAddress,
    ) -> DbResult<User>;

    /// Updates an existing user `username` to have new `last_login` details.
    async fn update_user(&mut self, username: Username, last_login: OffsetDateTime)
        -> DbResult<()>;

    /// Updates the activation code of an existing user, either to a new code or to nothing to
    /// indicate that the user is active.
    async fn set_user_activation_code(&mut self, user: User, code: Option<u64>) -> DbResult<User>;

    /// Gets information about an existing user named `username`.
    async fn get_user_by_username(&mut self, username: Username) -> DbResult<User>;

    /// Gets a session from its access token.  Sessions marked as deleted (logged out) are
    /// ignored.
    async fn get_session(&mut self, access_token: &AccessToken) -> DbResult<Session>;

    /// Saves a session.
    async fn put_session(&mut self, session: &Session) -> DbResult<()>;

    /// Marks a session as deleted.
    async fn delete_session(&mut self, session: Session, now: OffsetDateTime) -> DbResult<()>;
}
