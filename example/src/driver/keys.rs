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

//! Operations on a collection of keys.

use crate::db::Tx;
use crate::driver::Driver;
use crate::model::*;
use iii_iv_core::db::{BareTx, Db};
use iii_iv_core::driver::DriverResult;
use std::collections::BTreeSet;

impl<D> Driver<D>
where
    D: Db + Clone + Send + Sync + 'static,
    D::Tx: Tx + From<D::SqlxTx> + Send + Sync + 'static,
{
    /// Gets a list of all existing keys.
    pub(crate) async fn get_keys(self) -> DriverResult<BTreeSet<Key>> {
        let mut tx = self.db.begin().await?;
        let keys = tx.get_keys().await?;
        tx.commit().await?;
        Ok(keys)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::testutils::*;

    #[tokio::test]
    async fn test_get_keys_none() {
        let context = TestContext::setup().await;

        let keys = context.driver().get_keys().await.unwrap();
        assert!(keys.is_empty());
    }

    #[tokio::test]
    async fn test_get_keys_some() {
        let context = TestContext::setup().await;

        let key1 = Key::new("1".to_owned());
        let key2 = Key::new("2".to_owned());
        let key3 = Key::new("3".to_owned());
        let entry = Entry::new("the value".to_owned(), Version::initial());

        let mut tx = context.db().begin().await.unwrap();
        tx.set_key(&key1, &entry).await.unwrap();
        tx.set_key(&key3, &entry).await.unwrap();
        tx.set_key(&key2, &entry).await.unwrap();
        tx.commit().await.unwrap();

        let keys = context.driver().get_keys().await.unwrap();
        assert_eq!(vec![key1, key2, key3], keys.into_iter().collect::<Vec<Key>>());
    }
}
