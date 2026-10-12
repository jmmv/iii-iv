// III-IV
// Copyright 2026 Julio Merino
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

//! Bounded execution of password-hashing operations.

use crate::driver::{AuthnDriver, AuthnHooks};
use crate::model::{HashedPassword, Password};
use iii_iv_core::driver::{DriverError, DriverResult};
use iii_iv_core::model::ModelResult;
use tokio::sync::OwnedSemaphorePermit;

#[cfg(test)]
use std::sync::Arc;

/// Pluggable implementation of password hashing for deterministic tests.
pub(super) trait PasswordHasher: Send + Sync {
    /// Hashes `password` after applying `validator`.
    fn hash(
        &self,
        password: Password,
        validator: fn(&str) -> Option<&'static str>,
    ) -> ModelResult<HashedPassword>;

    /// Checks whether `password` matches `hash`.
    fn verify(&self, password: Password, hash: HashedPassword) -> ModelResult<bool>;
}

/// Production bcrypt password hasher.
pub(super) struct BcryptPasswordHasher;

impl PasswordHasher for BcryptPasswordHasher {
    fn hash(
        &self,
        password: Password,
        validator: fn(&str) -> Option<&'static str>,
    ) -> ModelResult<HashedPassword> {
        password.validate_and_hash(validator)
    }

    fn verify(&self, password: Password, hash: HashedPassword) -> ModelResult<bool> {
        password.verify(&hash)
    }
}

impl<H: AuthnHooks> AuthnDriver<H> {
    /// Acquires password-hashing capacity without waiting.
    pub(super) fn acquire_password_hash_capacity(&self) -> DriverResult<OwnedSemaphorePermit> {
        self.password_hash_semaphore
            .clone()
            .try_acquire_owned()
            .map_err(|_| DriverError::Unavailable)
    }

    /// Hashes a password on the blocking worker pool.
    pub(super) async fn hash_password(
        &self,
        password: Password,
        validator: fn(&str) -> Option<&'static str>,
        permit: OwnedSemaphorePermit,
    ) -> DriverResult<(HashedPassword, OwnedSemaphorePermit)> {
        let hasher = self.password_hasher.clone();
        let (result, permit) = tokio::task::spawn_blocking(move || {
            let result = hasher.hash(password, validator);
            (result, permit)
        })
        .await
        .map_err(|error| {
            DriverError::BackendError(format!("Password hashing worker failed: {}", error))
        })?;
        Ok((result?, permit))
    }

    /// Verifies a password on the blocking worker pool.
    pub(super) async fn verify_password(
        &self,
        password: Password,
        hash: &HashedPassword,
        permit: OwnedSemaphorePermit,
    ) -> DriverResult<(bool, OwnedSemaphorePermit)> {
        let hash = HashedPassword::new(hash.as_str().to_owned());
        let hasher = self.password_hasher.clone();
        let (result, permit) = tokio::task::spawn_blocking(move || {
            let result = hasher.verify(password, hash);
            (result, permit)
        })
        .await
        .map_err(|error| {
            DriverError::BackendError(format!("Password hashing worker failed: {}", error))
        })?;
        Ok((result?, permit))
    }

    /// Replaces the production hasher in unit tests.
    #[cfg(test)]
    pub(super) fn with_password_hasher(mut self, hasher: Arc<dyn PasswordHasher>) -> Self {
        self.password_hasher = hasher;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::AuthnOptions;
    use crate::driver::testutils::TestContext;
    use crate::model::{hashed_password, password};
    use iii_iv_core::model::ModelError;
    use std::sync::{Condvar, Mutex, mpsc};

    /// Hasher that does not finish until explicitly released by a test.
    struct BlockingHasher {
        entered: mpsc::Sender<()>,
        finished: mpsc::Sender<()>,
        released: Arc<(Mutex<bool>, Condvar)>,
    }

    impl BlockingHasher {
        /// Blocks until the test releases this hasher.
        fn block(&self) {
            self.entered.send(()).unwrap();
            let (lock, condvar) = self.released.as_ref();
            let mut released = lock.lock().unwrap();
            while !*released {
                released = condvar.wait(released).unwrap();
            }
            self.finished.send(()).unwrap();
        }
    }

    impl PasswordHasher for BlockingHasher {
        fn hash(
            &self,
            _password: Password,
            _validator: fn(&str) -> Option<&'static str>,
        ) -> ModelResult<HashedPassword> {
            self.block();
            Ok(hashed_password!("hash"))
        }

        fn verify(&self, _password: Password, _hash: HashedPassword) -> ModelResult<bool> {
            self.block();
            Ok(true)
        }
    }

    /// Hasher that always fails.
    struct FailingHasher;

    impl PasswordHasher for FailingHasher {
        fn hash(
            &self,
            _password: Password,
            _validator: fn(&str) -> Option<&'static str>,
        ) -> ModelResult<HashedPassword> {
            Err(ModelError("Hasher failure".to_owned()))
        }

        fn verify(&self, _password: Password, _hash: HashedPassword) -> ModelResult<bool> {
            Err(ModelError("Hasher failure".to_owned()))
        }
    }

    /// Hasher that always panics.
    struct PanickingHasher;

    impl PasswordHasher for PanickingHasher {
        fn hash(
            &self,
            _password: Password,
            _validator: fn(&str) -> Option<&'static str>,
        ) -> ModelResult<HashedPassword> {
            panic!("Hasher panic")
        }

        fn verify(&self, _password: Password, _hash: HashedPassword) -> ModelResult<bool> {
            panic!("Hasher panic")
        }
    }

    /// Creates a driver and synchronization controls for a blocking hasher.
    async fn setup_blocking_driver(
        concurrency: usize,
    ) -> (
        AuthnDriver<crate::driver::AuthnNoHooks>,
        mpsc::Receiver<()>,
        mpsc::Receiver<()>,
        Arc<(Mutex<bool>, Condvar)>,
    ) {
        let (entered_tx, entered_rx) = mpsc::channel();
        let (finished_tx, finished_rx) = mpsc::channel();
        let released = Arc::new((Mutex::new(false), Condvar::new()));
        let hasher = Arc::new(BlockingHasher {
            entered: entered_tx,
            finished: finished_tx,
            released: released.clone(),
        });
        let opts = AuthnOptions { password_hash_concurrency: concurrency, ..Default::default() };
        let context = TestContext::setup(opts).await;
        let driver = context.driver().with_password_hasher(hasher);
        (driver, entered_rx, finished_rx, released)
    }

    /// Releases all calls in a blocking hasher.
    fn release_hasher(released: &Arc<(Mutex<bool>, Condvar)>) {
        let (lock, condvar) = released.as_ref();
        *lock.lock().unwrap() = true;
        condvar.notify_all();
    }

    /// Waits until a permit released by a blocking task becomes observable.
    async fn wait_for_capacity(
        driver: &AuthnDriver<crate::driver::AuthnNoHooks>,
    ) -> OwnedSemaphorePermit {
        loop {
            if let Ok(permit) = driver.acquire_password_hash_capacity() {
                return permit;
            }
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_concurrency_is_bounded_across_clones() {
        let (driver, entered, finished, released) = setup_blocking_driver(2).await;
        let mut jobs = Vec::new();
        for _ in 0..2 {
            let permit = driver.acquire_password_hash_capacity().unwrap();
            let driver = driver.clone();
            jobs.push(tokio::spawn(async move {
                driver.hash_password(password!("password"), |_| None, permit).await
            }));
        }
        entered.recv().unwrap();
        entered.recv().unwrap();

        assert!(matches!(driver.acquire_password_hash_capacity(), Err(DriverError::Unavailable)));

        release_hasher(&released);
        finished.recv().unwrap();
        finished.recv().unwrap();
        for job in jobs {
            let (_, permit) = job.await.unwrap().unwrap();
            drop(permit);
        }
        drop(wait_for_capacity(&driver).await);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_cancellation_keeps_capacity_until_worker_finishes() {
        let (driver, entered, finished, released) = setup_blocking_driver(1).await;
        let permit = driver.acquire_password_hash_capacity().unwrap();
        let worker_driver = driver.clone();
        let job = tokio::spawn(async move {
            worker_driver.hash_password(password!("password"), |_| None, permit).await
        });
        entered.recv().unwrap();

        job.abort();
        assert!(matches!(driver.acquire_password_hash_capacity(), Err(DriverError::Unavailable)));

        release_hasher(&released);
        finished.recv().unwrap();
        drop(wait_for_capacity(&driver).await);
    }

    #[tokio::test]
    async fn test_hasher_error_releases_capacity() {
        let opts = AuthnOptions { password_hash_concurrency: 1, ..Default::default() };
        let context = TestContext::setup(opts).await;
        let driver = context.driver().with_password_hasher(Arc::new(FailingHasher));
        let permit = driver.acquire_password_hash_capacity().unwrap();

        assert!(driver.hash_password(password!("password"), |_| None, permit).await.is_err());
        drop(driver.acquire_password_hash_capacity().unwrap());
    }

    #[tokio::test]
    async fn test_worker_panic_releases_capacity() {
        let opts = AuthnOptions { password_hash_concurrency: 1, ..Default::default() };
        let context = TestContext::setup(opts).await;
        let driver = context.driver().with_password_hasher(Arc::new(PanickingHasher));
        let permit = driver.acquire_password_hash_capacity().unwrap();

        let error = driver
            .verify_password(password!("password"), &hashed_password!("hash"), permit)
            .await
            .unwrap_err();
        assert!(matches!(error, DriverError::BackendError(_)));
        drop(driver.acquire_password_hash_capacity().unwrap());
    }

    #[tokio::test]
    async fn test_zero_concurrency_rejects_all_work() {
        let opts = AuthnOptions { password_hash_concurrency: 0, ..Default::default() };
        let context = TestContext::setup(opts).await;

        assert!(matches!(
            context.driver().acquire_password_hash_capacity(),
            Err(DriverError::Unavailable)
        ));
    }
}
