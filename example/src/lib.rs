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

//! Sample REST service that implements a key/value store.

// Keep these in sync with other top-level files.
#![warn(anonymous_parameters, bad_style, clippy::missing_docs_in_private_items, missing_docs)]
#![warn(unused, unused_extern_crates, unused_import_braces, unused_qualifications)]
#![warn(unsafe_code)]

use iii_iv_core::db::Db;
use std::error::Error;
use std::net::SocketAddr;
use std::sync::Arc;

pub mod db;
pub mod driver;
use driver::Driver;
pub(crate) mod model;
mod rest;
use rest::app;

/// Instantiates all resources to serve the application on `bind_addr`.
///
/// While it'd be nice to push this responsibility to `main`, doing so would force us to expose many
/// crate-internal types to the public, which in turn would make dead code detection harder.
pub async fn serve(
    bind_addr: impl Into<SocketAddr>,
    db: Arc<dyn Db + Send + Sync>,
) -> Result<(), Box<dyn Error>> {
    let driver = Driver::new(db);
    let app = app(driver);

    axum_server::bind(bind_addr.into()).serve(app.into_make_service()).await?;
    Ok(())
}
