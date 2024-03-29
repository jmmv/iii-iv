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

//! Test utilities for the business layer.

use crate::db;
use crate::driver::Driver;
use iii_iv_core::db::{Db, Executor};
use std::sync::Arc;

pub(crate) struct TestContext {
    db: Arc<dyn Db + Send + Sync>,
    driver: Driver,
}

impl TestContext {
    pub(crate) async fn setup() -> Self {
        let db = Arc::from(iii_iv_core::db::sqlite::connect(":memory:").await.unwrap());
        db::init_schema(&mut db.ex().await.unwrap()).await.unwrap();
        let driver = Driver::new(db.clone());
        Self { db, driver }
    }

    pub(crate) async fn ex(&self) -> Executor {
        self.db.ex().await.unwrap()
    }

    pub(crate) fn driver(&self) -> Driver {
        self.driver.clone()
    }
}
