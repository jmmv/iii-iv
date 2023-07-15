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

//! Rudimentary framework to build web services.
//!
//! Services built using this framework adhere to the following layered architecture, and they
//! should structure their code to have these modules as well:
//!
//! 1.  `model`: This is the base layer, providing high-level data types that represent concepts in
//!     the domain of the application.  There should be no logic in here.  Extensive use of the
//!     newtype and builder patterns is strongly encouraged.
//!
//! 1.  `db`: This is the persistence layer.  Services extend the `BareTx` trait with a `Tx` type
//!     that provides domain-specific operations.
//!
//! 1.  `driver`: This is the business logic layer.  Services provide their own `Driver` type to
//!     encapsulates all of the in-memory state required by the app and to coordinate access to the
//!     database.
//!
//! 1.  `rest`: This is the HTTP layer, offering the REST APIs.  Services should provide their own
//!     `axum::Router` implementation and back every API with a data object of type `Driver`.
//!
//! 1.  `main`: This is the app launcher.  It sole purpose is to gather configuration data from
//!     environment variables and call the `crate::serve` function to start the application.
//!
//! There are result and error types in every layer, such as `DbResult` and `DbError`.  Errors can
//! transparently float to the top of the app using the `?` operator, being translated to HTTP
//! status codes once returned from the REST layer.
//!
//! This crate provides the basic structure and is modeled after the layers presented above.  Every
//! service implementation should define the same modules.  For more details on how to implement
//! each module, refer to the module-level docstring of the modules in this crate.
//!
//! This crate does not have any heavy dependencies except those that are required for all services.
//! Heavy dependencies are introduced by depending on sibling crates.

// Keep these in sync with other top-level files.
#![warn(anonymous_parameters, bad_style, clippy::missing_docs_in_private_items, missing_docs)]
#![warn(unused, unused_extern_crates, unused_import_braces, unused_qualifications)]
#![warn(unsafe_code)]

pub mod clocks;
pub mod db;
pub mod driver;
pub mod env;
pub mod model;
pub mod rest;
pub mod template;
