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

//! Wrapper over a geolocation provider to offer caching of query results.

use crate::{CountryIsoCode, GeoLocator, GeoResult};
use async_trait::async_trait;
use derivative::Derivative;
use futures::lock::Mutex;
use iii_iv_core::env::get_optional_var;
use log::warn;
use lru_time_cache::LruCache;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

/// Default maximum amount of time to keep cached entries in memory.
const DEFAULT_TTL_SECONDS: u64 = 60 * 60;

/// Default maximum number of responses to keep cached in memory.
const DEFAULT_CAPACITY: usize = 10 * 1024;

/// Options to configure an `CachingGeoLocator`.
#[derive(Derivative)]
#[derivative(Debug)]
#[cfg_attr(test, derivative(PartialEq))]
pub struct CachingGeoLocatorOptions {
    /// The TTL for the entries in the cache.
    pub ttl: Duration,

    /// The cache capacity in number of entries.
    pub capacity: usize,
}

impl Default for CachingGeoLocatorOptions {
    fn default() -> Self {
        Self { ttl: Duration::from_secs(DEFAULT_TTL_SECONDS), capacity: DEFAULT_CAPACITY }
    }
}

impl CachingGeoLocatorOptions {
    /// Creates a set of options from environment variables whose name is prefixed with the
    /// given `prefix`.
    ///
    /// This will use variables such as `<prefix>_TTL` and `<prefix>_CAPACITY`.
    pub fn from_env(prefix: &str) -> Result<Self, String> {
        Ok(Self {
            ttl: get_optional_var::<Duration>(prefix, "TTL")?
                .unwrap_or_else(|| Duration::from_secs(DEFAULT_TTL_SECONDS)),
            capacity: get_optional_var::<usize>(prefix, "CAPACITY")?.unwrap_or(DEFAULT_CAPACITY),
        })
    }
}

/// Geolocator that uses an Caching account.
#[derive(Clone)]
pub struct CachingGeoLocator<G> {
    /// The wrapped geolocator.
    delegee: G,

    /// Cache of successful responses.
    cache: Arc<Mutex<LruCache<IpAddr, Option<CountryIsoCode>>>>,
}

impl<G> CachingGeoLocator<G> {
    /// Creates a new caching geolocator that wraps `delegee` using `opts` for configuration.
    pub fn new(opts: CachingGeoLocatorOptions, delegee: G) -> Self {
        let cache = LruCache::with_expiry_duration_and_capacity(opts.ttl, opts.capacity);
        Self { delegee, cache: Arc::from(Mutex::from(cache)) }
    }
}

#[async_trait]
impl<G> GeoLocator for CachingGeoLocator<G>
where
    G: GeoLocator + Send + Sync,
{
    async fn locate(&self, ip: &IpAddr) -> GeoResult<Option<CountryIsoCode>> {
        {
            let mut cache = self.cache.lock().await;
            if let Some(code) = cache.get(ip) {
                return Ok(code.clone());
            };
        }

        let code = self.delegee.locate(ip).await?;

        let mut cache = self.cache.lock().await;
        if let Some(old_code) = cache.insert(*ip, code.clone()) {
            if old_code != code {
                warn!(
                    "Cache insertion race detected with inconsistent values: {:?} != {:?}",
                    old_code, code
                );
            }
        }
        Ok(code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MockGeoLocator;

    #[test]
    pub fn test_options_from_env_all_present() {
        let overrides = [("CACHING_TTL", Some("3d")), ("CACHING_CAPACITY", Some("1024"))];
        temp_env::with_vars(overrides, || {
            let opts = CachingGeoLocatorOptions::from_env("CACHING").unwrap();
            assert_eq!(
                CachingGeoLocatorOptions {
                    ttl: Duration::from_secs(3 * 24 * 60 * 60),
                    capacity: 1024,
                },
                opts
            );
        });
    }

    #[test]
    pub fn test_options_from_env_use_defaults() {
        let overrides = ["CACHING_TTL", "CACHING_CAPACITY"];
        temp_env::with_vars_unset(overrides, || {
            let opts = CachingGeoLocatorOptions::from_env("CACHING").unwrap();
            assert_eq!(
                CachingGeoLocatorOptions {
                    ttl: Duration::from_secs(DEFAULT_TTL_SECONDS),
                    capacity: DEFAULT_CAPACITY,
                },
                opts
            );
        });
    }

    struct TestContext {
        geolocator: CachingGeoLocator<MockGeoLocator>,
        delegee: MockGeoLocator,
    }

    impl TestContext {
        fn setup() -> Self {
            let delegee = MockGeoLocator::new(&[
                ("1.1.1.1", "ES"),
                ("2.2.2.2", "KR"),
                ("3.3.3.3", "US"),
                ("9.9.9.9", MockGeoLocator::RETURN_ERROR),
            ]);

            let geolocator = CachingGeoLocator::new(
                CachingGeoLocatorOptions { ttl: Duration::from_secs(1000000), capacity: 2 },
                delegee.clone(),
            );

            Self { geolocator, delegee }
        }

        /// Performs a lookup and extracts the country code as a string for easy comparisons.
        async fn locate(&self, ip: &str) -> Option<String> {
            self.geolocator
                .locate(&(*ip).parse::<IpAddr>().unwrap())
                .await
                .unwrap()
                .map(|code| code.as_str().to_owned())
        }

        /// Returns the number of times `ip` has been queried in the delegee geolocator.
        async fn query_count(&self, ip: &str) -> usize {
            self.delegee.query_count(&(*ip).parse::<IpAddr>().unwrap()).await
        }
    }

    #[tokio::test]
    async fn test_forward_to_delegee() {
        let context = TestContext::setup();
        assert_eq!(Some("ES"), context.locate("1.1.1.1").await.as_deref());
        assert_eq!(Some("KR"), context.locate("2.2.2.2").await.as_deref());
        assert_eq!(None, context.locate("0.0.0.0").await.as_deref());
    }

    #[tokio::test]
    async fn test_cache_behavior() {
        let context = TestContext::setup();

        // Fill the cache and check query counts.
        assert_eq!(Some("ES"), context.locate("1.1.1.1").await.as_deref());
        assert_eq!(Some("KR"), context.locate("2.2.2.2").await.as_deref());
        assert_eq!(1, context.query_count("1.1.1.1").await);
        assert_eq!(1, context.query_count("2.2.2.2").await);
        assert_eq!(0, context.query_count("3.3.3.3").await);

        // Redo the same queries in different order and check query counts.
        assert_eq!(Some("KR"), context.locate("2.2.2.2").await.as_deref());
        assert_eq!(Some("ES"), context.locate("1.1.1.1").await.as_deref());
        assert_eq!(1, context.query_count("1.1.1.1").await);
        assert_eq!(1, context.query_count("2.2.2.2").await);
        assert_eq!(0, context.query_count("3.3.3.3").await);

        // Do a novel query which should push an entry out of the cache.
        assert_eq!(Some("US"), context.locate("3.3.3.3").await.as_deref());
        assert_eq!(1, context.query_count("1.1.1.1").await);
        assert_eq!(1, context.query_count("2.2.2.2").await);
        assert_eq!(1, context.query_count("3.3.3.3").await);

        // Redo the original queries, one of which should be refetched again.
        assert_eq!(Some("ES"), context.locate("1.1.1.1").await.as_deref());
        assert_eq!(Some("KR"), context.locate("2.2.2.2").await.as_deref());
        assert_eq!(1, context.query_count("1.1.1.1").await);
        assert_eq!(2, context.query_count("2.2.2.2").await);
        assert_eq!(1, context.query_count("3.3.3.3").await);
    }

    #[tokio::test]
    async fn test_unknown_results_are_cached() {
        let context = TestContext::setup();

        // Fill the cache.
        assert_eq!(Some("ES"), context.locate("1.1.1.1").await.as_deref());
        assert_eq!(Some("KR"), context.locate("2.2.2.2").await.as_deref());

        // Query an unknown address.
        assert_eq!(None, context.locate("5.5.5.5").await.as_deref());

        // Redo the original queries.
        assert_eq!(Some("ES"), context.locate("1.1.1.1").await.as_deref());
        assert_eq!(Some("KR"), context.locate("2.2.2.2").await.as_deref());
        assert_eq!(2, context.query_count("1.1.1.1").await);
        assert_eq!(2, context.query_count("2.2.2.2").await);
        assert_eq!(1, context.query_count("5.5.5.5").await);
    }

    #[tokio::test]
    async fn test_errors_are_not_cached() {
        let context = TestContext::setup();

        // Fill the cache.
        assert_eq!(Some("ES"), context.locate("1.1.1.1").await.as_deref());
        assert_eq!(Some("KR"), context.locate("2.2.2.2").await.as_deref());

        // Query an address that returns an error.
        context.geolocator.locate(&"9.9.9.9".parse().unwrap()).await.unwrap_err();
        context.geolocator.locate(&"9.9.9.9".parse().unwrap()).await.unwrap_err();
        context.geolocator.locate(&"9.9.9.9".parse().unwrap()).await.unwrap_err();

        // Redo the original queries and ensure they are still cached.
        assert_eq!(Some("ES"), context.locate("1.1.1.1").await.as_deref());
        assert_eq!(Some("KR"), context.locate("2.2.2.2").await.as_deref());
        assert_eq!(1, context.query_count("1.1.1.1").await);
        assert_eq!(1, context.query_count("2.2.2.2").await);
        assert_eq!(3, context.query_count("9.9.9.9").await);
    }
}
