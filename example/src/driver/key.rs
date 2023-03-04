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

//! Operations on one key.

use crate::db::Tx;
use crate::driver::Driver;
use crate::model::*;
use iii_iv_core::db::{BareTx, Db};
use iii_iv_core::driver::DriverResult;

impl<D> Driver<D>
where
    D: Db + Clone + Send + Sync + 'static,
    D::Tx: Tx + From<D::SqlxTx> + Send + Sync + 'static,
{
    /// Deletes an existing `key`.
    pub(crate) async fn delete_key(self, key: &Key) -> DriverResult<()> {
        let mut tx = self.db.begin().await?;
        tx.delete_key(key).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Gets the current value of the given `key`.
    pub(crate) async fn get_key(self, key: &Key) -> DriverResult<Entry> {
        let mut tx = self.db.begin().await?;
        let value = tx.get_key(key).await?;
        tx.commit().await?;
        Ok(value)
    }

    /// Sets `key` to `value`, incrementing its version.
    pub(crate) async fn set_key(self, key: &Key, value: String) -> DriverResult<Entry> {
        let mut tx = self.db.begin().await?;
        let version =
            tx.get_key_version(key).await?.map(Version::next).unwrap_or_else(Version::initial);
        let entry = Entry::new(value, version);
        tx.set_key(key, &entry).await?;
        tx.commit().await?;
        Ok(entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::testutils::*;
    use iii_iv_core::db::DbError;
    use iii_iv_core::driver::DriverError;

    #[tokio::test]
    async fn test_delete_key_ok() {
        let context = TestContext::setup().await;

        let key = Key::new("test".to_owned());
        let entry = Entry::new("the value".to_owned(), Version::initial());

        let mut tx = context.db().begin().await.unwrap();
        tx.set_key(&key, &entry).await.unwrap();
        tx.commit().await.unwrap();

        context.driver().delete_key(&key).await.unwrap();

        let mut tx = context.db().begin().await.unwrap();
        assert_eq!(DbError::NotFound, tx.get_key(&key).await.unwrap_err());
        tx.commit().await.unwrap();
    }

    #[tokio::test]
    async fn test_delete_key_not_found() {
        let context = TestContext::setup().await;

        let key = Key::new("test".to_owned());

        assert_eq!(
            DriverError::NotFound("Entity not found".to_owned()),
            context.driver().delete_key(&key).await.unwrap_err()
        );
    }

    #[tokio::test]
    async fn test_get_key_ok() {
        let context = TestContext::setup().await;

        let key = Key::new("test".to_owned());
        let exp_entry = Entry::new("the value".to_owned(), Version::initial());

        let mut tx = context.db().begin().await.unwrap();
        tx.set_key(&key, &exp_entry).await.unwrap();
        tx.commit().await.unwrap();

        let entry = context.driver().get_key(&key).await.unwrap();
        assert_eq!(exp_entry, entry);
    }

    #[tokio::test]
    async fn test_get_key_not_found() {
        let context = TestContext::setup().await;

        let key = Key::new("test".to_owned());

        assert_eq!(
            DriverError::NotFound("Entity not found".to_owned()),
            context.driver().get_key(&key).await.unwrap_err()
        );
    }

    #[tokio::test]
    async fn test_set_key_new() {
        let context = TestContext::setup().await;

        let key = Key::new("test".to_owned());

        context.driver().set_key(&key, "first value".to_owned()).await.unwrap();

        let mut tx = context.db().begin().await.unwrap();
        let entry = tx.get_key(&key).await.unwrap();
        assert_eq!(Entry::new("first value".to_owned(), Version::initial()), entry);
        tx.commit().await.unwrap();
    }

    #[tokio::test]
    async fn test_set_key_update_existing() {
        let context = TestContext::setup().await;

        let key = Key::new("test".to_owned());

        context.driver().set_key(&key, "first value".to_owned()).await.unwrap();
        context.driver().set_key(&key, "second value".to_owned()).await.unwrap();

        let mut tx = context.db().begin().await.unwrap();
        let entry = tx.get_key(&key).await.unwrap();
        assert_eq!(Entry::new("second value".to_owned(), Version::initial().next()), entry);
        tx.commit().await.unwrap();
    }
}
