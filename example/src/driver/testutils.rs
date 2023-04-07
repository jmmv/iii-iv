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

use crate::db::sqlite::SqliteTx;
use crate::driver::Driver;
use iii_iv_sqlite::{self, SqliteDb};

pub(crate) struct TestContext {
    db: SqliteDb<SqliteTx>,
    driver: Driver<SqliteDb<SqliteTx>>,
}

impl TestContext {
    pub(crate) async fn setup() -> Self {
        let pool = iii_iv_sqlite::connect(":memory:").await.unwrap();
        let db = SqliteDb::<SqliteTx>::attach(pool).await.unwrap();
        let driver = Driver::new(db.clone());
        Self { db, driver }
    }

    pub(crate) fn db(&self) -> &SqliteDb<SqliteTx> {
        &self.db
    }

    pub(crate) fn driver(&self) -> Driver<SqliteDb<SqliteTx>> {
        self.driver.clone()
    }
}
