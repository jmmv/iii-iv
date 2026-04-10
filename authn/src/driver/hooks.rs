// III-IV
// Copyright 2026 Julio Merino
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

//! Extension points for the authn driver.

use crate::model::User;
use async_trait::async_trait;
use iii_iv_core::db::TxExecutor;
use iii_iv_core::driver::DriverResult;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// Collection of hooks to extend the behavior of the authn APIs.
#[async_trait]
pub trait AuthnHooks: Clone + Send + Sync + 'static {
    /// Additional fields returned from a login API call.
    type LoginOutput: Send + Serialize;

    /// Hook executed after a successful login, but before state is committed.
    /// Returning a failure from this hook results in an aborted login.
    async fn login_hook(
        &self,
        tx: &mut TxExecutor,
        now: OffsetDateTime,
        user: &User,
    ) -> DriverResult<Self::LoginOutput>;

    /// Additional fields processed during a signup API call.
    type SignupInput: Default + DeserializeOwned + Send;

    /// Hook executed after a successful signup, but before state is committed.
    /// Returning a failure from this hook results in an aborted signup.
    async fn signup_hook(
        &self,
        tx: &mut TxExecutor,
        now: OffsetDateTime,
        user: &User,
        input: Self::SignupInput,
    ) -> DriverResult<()>;
}

/// An empty JSON map used to represent no extensions to API inputs/outputs.
#[derive(Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct NoExtensions {}

/// A constant of `NoExtensions`.
pub const NO_EXTENSIONS: NoExtensions = NoExtensions {};

/// Default authn hooks that do nothing.
#[derive(Clone)]
pub struct AuthnNoHooks;

#[async_trait]
impl AuthnHooks for AuthnNoHooks {
    type LoginOutput = NoExtensions;

    async fn login_hook(
        &self,
        _tx: &mut TxExecutor,
        _now: OffsetDateTime,
        _user: &User,
    ) -> DriverResult<Self::LoginOutput> {
        Ok(NO_EXTENSIONS)
    }

    type SignupInput = NoExtensions;

    async fn signup_hook(
        &self,
        _tx: &mut TxExecutor,
        _now: OffsetDateTime,
        _user: &User,
        _input: Self::SignupInput,
    ) -> DriverResult<()> {
        Ok(())
    }
}
