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

//! A persistent task queue.
//!
//! This crate provides facilities to implement a persistent task queue backed
//! by a database.
//!
//! The client offered by `driver::Client` enqueues new tasks and fetches details
//! about their status by directly querying the database.  There can be as many
//! different clients as necessary accessing the tasks in this way.
//!
//! The worker offered by `driver::Worker` polls for tasks whenever it is poked
//! by an external actor and executes those tasks.  This is designed to work in
//! the context of a serverless process, but could also be un in a long-lived
//! process.  There can also be multiple workers.

pub mod db;
pub mod driver;
pub mod model;
pub mod rest;
