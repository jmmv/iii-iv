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

//! Entry point to the REST server.

use crate::db::Tx;
use crate::driver::Driver;
use axum::Router;
use iii_iv_core::db::Db;

mod key_delete;
mod key_get;
mod key_put;
mod keys_get;
#[cfg(test)]
mod testutils;

/// Creates the router for the application.
pub(crate) fn app<D>(driver: Driver<D>) -> Router
where
    D: Db + Clone + Send + Sync + 'static,
    D::Tx: Tx + Send + Sync + 'static,
{
    use axum::routing::get;
    Router::new()
        .route(
            "/api/v1/keys/:key",
            get(key_get::handler).put(key_put::handler).delete(key_delete::handler),
        )
        .route("/api/v1/keys", get(keys_get::handler))
        .with_state(driver)
}
