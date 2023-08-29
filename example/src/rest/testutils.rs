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

//! Test utilities for the REST API.

use crate::db;
use crate::driver::Driver;
use crate::model::*;
use crate::rest::app;
use axum::Router;
use iii_iv_core::db::Db;
use std::sync::Arc;

pub(crate) struct TestContext {
    db: Arc<dyn Db + Send + Sync>,
    app: Router,
}

impl TestContext {
    pub(crate) async fn setup() -> Self {
        let db = Arc::from(iii_iv_core::db::sqlite::connect(":memory:").await.unwrap());
        db::init_schema(&mut db.ex().await.unwrap()).await.unwrap();
        let driver = Driver::new(db.clone());
        let app = app(driver);
        Self { db, app }
    }

    pub(crate) fn app(&self) -> Router {
        self.app.clone()
    }

    pub(crate) fn into_app(self) -> Router {
        self.app
    }

    pub(crate) async fn set_key<K: Into<String>, V: Into<String>>(
        &mut self,
        key: K,
        value: V,
        version: u32,
    ) {
        db::set_key(
            &mut self.db.ex().await.unwrap(),
            &Key::new(key.into()),
            &Entry::new(value.into(), Version::from_u32(version).unwrap()),
        )
        .await
        .unwrap();
    }

    pub(crate) async fn has_key<K: Into<String>>(&self, key: K) -> bool {
        db::get_key_version(&mut self.db.ex().await.unwrap(), &Key::new(key.into()))
            .await
            .unwrap()
            .is_some()
    }

    pub(crate) async fn get_key<K: Into<String>>(&self, key: K) -> Entry {
        db::get_key(&mut self.db.ex().await.unwrap(), &Key::new(key.into())).await.unwrap()
    }
}
