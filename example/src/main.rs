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

//! Entry point to the sample service.

// Keep these in sync with other top-level files.
#![warn(anonymous_parameters, bad_style, clippy::missing_docs_in_private_items, missing_docs)]
#![warn(unused, unused_extern_crates, unused_import_braces, unused_qualifications)]
#![warn(unsafe_code)]

use iii_iv_core::db::postgres::{PostgresDb, PostgresOptions};
use iii_iv_core::db::Db;
use iii_iv_example::db::init_schema;
use iii_iv_example::serve;
use std::env;
use std::net::Ipv4Addr;

#[tokio::main]
async fn main() {
    env_logger::init();

    let port: u16 = match env::var("FUNCTIONS_CUSTOMHANDLER_PORT") {
        Ok(val) => val.parse().expect("Custom handler port has to be a number"),
        Err(_) => 3000,
    };
    let addr = (Ipv4Addr::LOCALHOST, port);

    let db_opts = PostgresOptions::from_env("PGSQL_PROD").unwrap();
    let db = Box::from(PostgresDb::connect(db_opts).unwrap());
    init_schema(&mut db.ex()).await.unwrap();

    serve(addr, db).await.unwrap()
}
