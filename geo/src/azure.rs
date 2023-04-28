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

//! Geolocation API implementation backed by Azure Maps.

use crate::{CountryIsoCode, GeoLocator, GeoResult};
use async_trait::async_trait;
use bytes::Buf;
use derivative::Derivative;
use futures::lock::Mutex;
use iii_iv_core::env::get_optional_var;
use iii_iv_core::env::get_required_var;
use log::warn;
use lru_time_cache::LruCache;
use reqwest::{Client, Response, StatusCode};
use serde::{Deserialize, Serialize};
use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

/// Default maximum amount of time to keep cached entries in memory.
const DEFAULT_CACHE_TTL_SECONDS: u64 = 60 * 60;

/// Default maximum number of responses to keep cached in memory.
const DEFAULT_CACHE_CAPACITY: usize = 10 * 1024;

/// Converts a `reqwest::Error` to an `io::Error`.
fn reqwest_error_to_io_error(e: reqwest::Error) -> io::Error {
    io::Error::new(io::ErrorKind::Other, format!("{}", e))
}

/// Converts a `reqwest::Response` to an `io::Error`.  The response should have a non-OK status.
async fn http_response_to_io_error(response: Response) -> io::Error {
    let status = response.status();

    let kind = match status {
        StatusCode::OK => panic!("Should not have been called on a successful request"),

        // Match against the codes we know the server explicitly hands us.
        StatusCode::BAD_REQUEST => io::ErrorKind::InvalidInput,
        StatusCode::UNAUTHORIZED => io::ErrorKind::PermissionDenied,
        StatusCode::FORBIDDEN => io::ErrorKind::PermissionDenied,
        StatusCode::NOT_FOUND => io::ErrorKind::NotFound,
        StatusCode::INTERNAL_SERVER_ERROR => io::ErrorKind::Other,

        _ => io::ErrorKind::Other,
    };

    match response.text().await {
        Ok(text) => io::Error::new(
            kind,
            format!("HTTP request returned status {} with text '{}'", status, text),
        ),
        Err(e) => io::Error::new(
            kind,
            format!("HTTP request returned status {} and failed to get text due to {}", status, e),
        ),
    }
}

/// Request to the Azure Maps service to geolocate an IP address.
#[derive(Serialize)]
struct LocateRequest<'a, 'b> {
    /// Desired format of the response.
    format: &'static str,

    /// Version number of the API in use.
    #[serde(rename = "api-version")]
    api_version: &'static str,

    /// The IP to geolocate.
    ip: &'a str,

    /// The Azure Maps key to use.
    #[serde(rename = "subscription-key")]
    subscription_key: &'b str,
}

/// Country region information as encoded within `LocateResponse`.
#[derive(Deserialize)]
struct CountryRegionResponse {
    /// The ISO country code as returned from the server.  Must be validated and converted into a
    /// `CountryIsoCode` object before use.
    #[serde(rename = "isoCode")]
    iso_code: Option<String>,
}

/// Response from the Azure Maps service on a successful `LocateRequest`.
#[derive(Deserialize)]
struct LocateResponse {
    /// Object containing the country region information.
    #[serde(rename = "countryRegion")]
    country_region: Option<CountryRegionResponse>,

    /// The IP passed in the request.
    #[serde(rename = "ipAddress")]
    ip: String,
}

/// Options to configure an `AzureGeoLocator`.
#[derive(Derivative)]
#[derivative(Debug)]
#[cfg_attr(test, derivative(PartialEq))]
pub struct AzureGeoLocatorOptions {
    /// The API key to use to contact Azure Maps.
    #[derivative(Debug = "ignore")]
    pub key: String,

    /// The TTL for the entries in the cache.
    pub cache_ttl: Duration,

    /// The cache capacity in number of entries.
    pub cache_capacity: usize,
}

impl AzureGeoLocatorOptions {
    /// Creates a set of options from from environment variables whose name is prefixed with the
    /// given `prefix`.
    ///
    /// This will use variables such as `<prefix>_KEY`, `<prefix>_CACHE_TTL` and
    /// `<prefix>_CACHE_CAPACITY`.
    pub fn from_env(prefix: &str) -> Result<Self, String> {
        Ok(Self {
            key: get_required_var::<String>(prefix, "KEY")?,
            cache_ttl: get_optional_var::<Duration>(prefix, "CACHE_TTL")?
                .unwrap_or_else(|| Duration::from_secs(DEFAULT_CACHE_TTL_SECONDS)),
            cache_capacity: get_optional_var::<usize>(prefix, "CACHE_CAPACITY")?
                .unwrap_or(DEFAULT_CACHE_CAPACITY),
        })
    }
}

/// Geolocator that uses an Azure Maps account.
#[derive(Clone)]
pub struct AzureGeoLocator {
    /// Azure Maps service key.
    key: String,

    /// Asynchronous HTTP client with which to issue the service requests.
    client: Client,

    /// Cache of successful responses.
    cache: Arc<Mutex<LruCache<IpAddr, Option<CountryIsoCode>>>>,
}

impl AzureGeoLocator {
    /// Creates a new Azure Maps-backed geolocator using `opts` for configuration.
    pub fn new(opts: AzureGeoLocatorOptions) -> Self {
        let cache =
            LruCache::with_expiry_duration_and_capacity(opts.cache_ttl, opts.cache_capacity);
        Self { key: opts.key, client: Client::default(), cache: Arc::from(Mutex::from(cache)) }
    }

    /// Same as `locate` but takes an IP as a string.  Useful for testing purposes only as this
    /// allows feeding invalid IPs to the server and bypasses the cache.
    async fn locate_raw(&self, ip: &str) -> GeoResult<Option<CountryIsoCode>> {
        let request =
            LocateRequest { format: "json", api_version: "1.0", ip, subscription_key: &self.key };
        let response = self
            .client
            .get("https://atlas.microsoft.com/geolocation/ip/json")
            .query(&request)
            .send()
            .await
            .map_err(reqwest_error_to_io_error)?;
        match response.status() {
            StatusCode::OK => {
                let bytes = response.bytes().await.map_err(reqwest_error_to_io_error)?;
                let response: LocateResponse = serde_json::from_reader(bytes.reader())?;

                match response.ip.parse::<IpAddr>() {
                    Ok(response_ip) => {
                        if ip != response_ip.to_string() {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!(
                                    "Mismatched IP in response: got {} but want {}",
                                    response_ip, ip
                                ),
                            ));
                        }
                    }
                    Err(e) => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("Invalid {} IP in the response: {}", response.ip, e),
                        ))
                    }
                }

                match response.country_region {
                    Some(country_region) => match country_region.iso_code {
                        Some(iso_code) => Ok(Some(CountryIsoCode::new(iso_code)?)),
                        None => Ok(None),
                    },
                    None => Ok(None),
                }
            }
            _ => Err(http_response_to_io_error(response).await),
        }
    }
}

#[async_trait]
impl GeoLocator for AzureGeoLocator {
    async fn locate(&self, ip: &IpAddr) -> GeoResult<Option<CountryIsoCode>> {
        {
            let mut cache = self.cache.lock().await;
            if let Some(code) = cache.get(ip) {
                return Ok(code.clone());
            };
        }

        let code = self.locate_raw(&ip.to_string()).await?;

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
    use std::env;
    use std::net::Ipv4Addr;

    #[test]
    pub fn test_azuregeolocatoroptions_from_env_all_present() {
        let overrides = [
            ("AZURE_MAPS_KEY", Some("the-key")),
            ("AZURE_MAPS_CACHE_TTL", Some("3d")),
            ("AZURE_MAPS_CACHE_CAPACITY", Some("1024")),
        ];
        temp_env::with_vars(overrides, || {
            let opts = AzureGeoLocatorOptions::from_env("AZURE_MAPS").unwrap();
            assert_eq!(
                AzureGeoLocatorOptions {
                    key: "the-key".to_owned(),
                    cache_ttl: Duration::from_secs(3 * 24 * 60 * 60),
                    cache_capacity: 1024,
                },
                opts
            );
        });
    }

    #[test]
    pub fn test_azuregeolocatoroptions_from_env_use_defaults() {
        let overrides = [
            ("AZURE_MAPS_KEY", Some("the-key")),
            ("AZURE_MAPS_CACHE_TTL", None),
            ("AZURE_MAPS_CACHE_CAPACITY", None),
        ];
        temp_env::with_vars(overrides, || {
            let opts = AzureGeoLocatorOptions::from_env("AZURE_MAPS").unwrap();
            assert_eq!(
                AzureGeoLocatorOptions {
                    key: "the-key".to_owned(),
                    cache_ttl: Duration::from_secs(DEFAULT_CACHE_TTL_SECONDS),
                    cache_capacity: DEFAULT_CACHE_CAPACITY,
                },
                opts
            );
        });
    }

    #[test]
    pub fn test_azuregeolocatoroptions_from_env_missing() {
        temp_env::with_var_unset("AZURE_MAPS_KEY", || {
            let err = AzureGeoLocatorOptions::from_env("AZURE_MAPS").unwrap_err();
            assert!(err.contains("AZURE_MAPS_KEY not present"));
        });
    }

    fn setup() -> AzureGeoLocator {
        AzureGeoLocator::new(AzureGeoLocatorOptions::from_env("AZURE_MAPS").unwrap())
    }

    #[tokio::test]
    #[ignore = "Requires environment configuration and is expensive"]
    async fn test_ok() {
        let geolocator = setup();
        assert_eq!(
            "ES",
            geolocator.locate(&"212.170.36.79".parse().unwrap()).await.unwrap().unwrap().as_str()
        );
        assert_eq!(
            "IE",
            geolocator.locate(&"185.2.66.42".parse().unwrap()).await.unwrap().unwrap().as_str()
        );
        assert_eq!(
            "US",
            geolocator
                .locate(&"2001:4898:80e8:3c::".parse().unwrap())
                .await
                .unwrap()
                .unwrap()
                .as_str()
        );
    }

    #[tokio::test]
    #[ignore = "Requires environment configuration and is expensive"]
    async fn test_cache() {
        let key = env::var("AZURE_MAPS_KEY").unwrap();
        let mut geolocator = AzureGeoLocator::new(AzureGeoLocatorOptions {
            key,
            cache_ttl: Duration::from_secs(1000000),
            cache_capacity: 10,
        });

        for i in 0..5 {
            let ip = IpAddr::V4(Ipv4Addr::new(212, 170, 36, 79 + i));
            assert_eq!("ES", geolocator.locate(&ip).await.unwrap().unwrap().as_str());

            let ip = IpAddr::V4(Ipv4Addr::new(185, 2, 66, 42 + i));
            assert_eq!("IE", geolocator.locate(&ip).await.unwrap().unwrap().as_str());
        }

        geolocator.key = "invalid key".to_string();

        // Query an IP we have already seen, which should be served from the cache and not hit
        // errors due to the invalid key.
        let ip = IpAddr::V4(Ipv4Addr::new(212, 170, 36, 79));
        assert_eq!("ES", geolocator.locate(&ip).await.unwrap().unwrap().as_str());

        // Force the cache to evict an entry by querying a new IP, which we expect to result in an
        // error when contacting the backend.
        let ip = IpAddr::V4(Ipv4Addr::new(212, 170, 36, 90));
        geolocator.locate(&ip).await.unwrap_err();

        geolocator.key = env::var("AZURE_MAPS_KEY").unwrap();

        // And now ensure that the faulty query would have been valid if it hadn't been by the
        // bad key, and that we do not cache errors.
        let ip = IpAddr::V4(Ipv4Addr::new(212, 170, 36, 90));
        assert_eq!("ES", geolocator.locate(&ip).await.unwrap().unwrap().as_str());
    }

    #[tokio::test]
    #[ignore = "Requires environment configuration and is expensive"]
    async fn test_invalid_ip() {
        let geolocator = setup();
        match geolocator.locate_raw("1.2.3.256").await {
            Err(e) => {
                assert_eq!(io::ErrorKind::InvalidInput, e.kind());
                assert!(e.to_string().contains("IP address is not valid"));
            }
            e => panic!("{:?}", e),
        }
    }

    #[tokio::test]
    #[ignore = "Requires environment configuration and is expensive"]
    async fn test_missing() {
        let geolocator = setup();
        assert_eq!(None, geolocator.locate(&"198.18.0.1".parse().unwrap()).await.unwrap());
    }
}
